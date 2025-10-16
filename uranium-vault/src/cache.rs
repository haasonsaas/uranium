use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

use uranium_core::models::DecryptedModel;

pub struct ModelCache {
    cache: Arc<RwLock<HashMap<Uuid, CacheEntry>>>,
    lru_queue: Arc<RwLock<VecDeque<Uuid>>>,
    max_size_bytes: usize,
    current_size_bytes: Arc<RwLock<usize>>,
    eviction_tx: broadcast::Sender<Uuid>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

struct CacheEntry {
    model: Arc<DecryptedModel>,
    size_bytes: usize,
    access_count: u64,
    last_accessed: std::time::Instant,
}

impl ModelCache {
    pub fn new(max_size_mb: usize) -> Self {
        let (eviction_tx, _) = broadcast::channel(100);

        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            lru_queue: Arc::new(RwLock::new(VecDeque::new())),
            max_size_bytes: max_size_mb * 1024 * 1024,
            current_size_bytes: Arc::new(RwLock::new(0)),
            eviction_tx,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    pub async fn get(&self, model_id: Uuid) -> Option<Arc<DecryptedModel>> {
        let mut cache = self.cache.write();

        if let Some(entry) = cache.get_mut(&model_id) {
            entry.access_count += 1;
            entry.last_accessed = std::time::Instant::now();

            // Move to end of LRU queue
            let mut queue = self.lru_queue.write();
            queue.retain(|&id| id != model_id);
            queue.push_back(model_id);

            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.model.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub async fn insert(&self, model_id: Uuid, model: Arc<DecryptedModel>) {
        let size_bytes = model.weights.len();

        // Check if we need to evict entries
        self.ensure_capacity(size_bytes).await;

        let entry = CacheEntry {
            model,
            size_bytes,
            access_count: 1,
            last_accessed: std::time::Instant::now(),
        };

        // Insert into cache
        {
            let mut cache = self.cache.write();
            cache.insert(model_id, entry);
        }

        // Update LRU queue
        {
            let mut queue = self.lru_queue.write();
            queue.push_back(model_id);
        }

        // Update size
        {
            let mut current_size = self.current_size_bytes.write();
            *current_size += size_bytes;
        }
    }

    pub async fn remove(&self, model_id: Uuid) -> Option<Arc<DecryptedModel>> {
        let entry = {
            let mut cache = self.cache.write();
            cache.remove(&model_id)
        };

        if let Some(entry) = entry {
            // Update LRU queue
            {
                let mut queue = self.lru_queue.write();
                queue.retain(|&id| id != model_id);
            }

            // Update size
            {
                let mut current_size = self.current_size_bytes.write();
                *current_size = current_size.saturating_sub(entry.size_bytes);
            }

            // Notify eviction
            let _ = self.eviction_tx.send(model_id);

            Some(entry.model)
        } else {
            None
        }
    }

    pub async fn clear(&self) {
        let model_ids: Vec<Uuid> = {
            let cache = self.cache.read();
            cache.keys().cloned().collect()
        };

        for model_id in model_ids {
            self.remove(model_id).await;
        }
    }

    async fn ensure_capacity(&self, required_bytes: usize) {
        let mut evicted_count = 0;

        while *self.current_size_bytes.read() + required_bytes > self.max_size_bytes {
            // Get least recently used model
            let lru_model_id = {
                let queue = self.lru_queue.read();
                queue.front().cloned()
            };

            if let Some(model_id) = lru_model_id {
                if self.remove(model_id).await.is_some() {
                    evicted_count += 1;
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                break;
            }
        }

        if evicted_count > 0 {
            tracing::info!("Evicted {} models from cache to make room", evicted_count);
        }
    }

    pub fn get_stats(&self) -> CacheStats {
        let cache = self.cache.read();
        let current_size = *self.current_size_bytes.read();

        let total_access_count: u64 = cache.values().map(|entry| entry.access_count).sum();
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let requests = hits + misses;
        let hit_rate = if requests > 0 {
            hits as f64 / requests as f64
        } else {
            0.0
        };
        let evictions = self.evictions.load(Ordering::Relaxed);

        CacheStats {
            entries: cache.len(),
            size_bytes: current_size,
            max_size_bytes: self.max_size_bytes,
            total_access_count,
            hit_rate,
            requests,
            hits,
            misses,
            evictions,
        }
    }

    pub fn subscribe_evictions(&self) -> broadcast::Receiver<Uuid> {
        self.eviction_tx.subscribe()
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub size_bytes: usize,
    pub max_size_bytes: usize,
    pub total_access_count: u64,
    pub hit_rate: f64,
    pub requests: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uranium_core::models::{ModelFormat, ModelMetadata};

    fn create_test_model(size_bytes: usize) -> Arc<DecryptedModel> {
        let metadata = ModelMetadata {
            id: Uuid::new_v4(),
            name: "test_model".to_string(),
            version: "1.0".to_string(),
            format: ModelFormat::SafeTensors,
            size_bytes: size_bytes as u64,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            description: None,
            tags: vec![],
            framework: None,
            architecture: None,
            parameters_count: None,
            watermark: None,
            license_constraints: None,
        };

        Arc::new(DecryptedModel::new(metadata, vec![0u8; size_bytes]))
    }

    #[tokio::test]
    async fn test_cache_basic_operations() {
        let cache = ModelCache::new(10); // 10MB cache

        let model_id = Uuid::new_v4();
        let model = create_test_model(1024 * 1024); // 1MB model

        // Insert
        cache.insert(model_id, model.clone()).await;

        // Get
        let retrieved = cache.get(model_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().metadata.id, model.metadata.id);
        assert_eq!(cache.get_stats().hits, 1);
        assert_eq!(cache.get_stats().misses, 0);
        assert_eq!(cache.get_stats().requests, 1);

        // Remove
        let removed = cache.remove(model_id).await;
        assert!(removed.is_some());

        // Get after remove
        let retrieved = cache.get(model_id).await;
        assert!(retrieved.is_none());
        let stats = cache.get_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.requests, 2);
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let cache = ModelCache::new(5); // 5MB cache

        // Insert 3 models of 2MB each
        let model1_id = Uuid::new_v4();
        let model2_id = Uuid::new_v4();
        let model3_id = Uuid::new_v4();

        cache
            .insert(model1_id, create_test_model(2 * 1024 * 1024))
            .await;
        cache
            .insert(model2_id, create_test_model(2 * 1024 * 1024))
            .await;

        // This should evict model1
        cache
            .insert(model3_id, create_test_model(2 * 1024 * 1024))
            .await;

        // Model1 should be evicted
        assert!(cache.get(model1_id).await.is_none());
        assert!(cache.get(model2_id).await.is_some());
        assert!(cache.get(model3_id).await.is_some());

        let stats = cache.get_stats();
        assert!(stats.evictions >= 1);
    }
}
