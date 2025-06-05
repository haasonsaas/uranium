use chrono::Utc;
use std::io::{self, Read, Write};
use std::path::Path;
use tempfile::TempDir;
use uranium_core::{
    crypto::{EncryptionAlgorithm, EncryptionKey, VaultCrypto},
    integrity::{HashAlgorithm, IntegrityVerifier},
    models::{ModelFormat, ModelFramework, ModelMetadata},
    storage::ModelStorage,
};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Uranium Core - Streaming Encryption Demo");
    println!("========================================\n");

    // Create temporary directory for storage
    let temp_dir = TempDir::new()?;
    println!("Created temporary storage at: {:?}", temp_dir.path());

    // Initialize storage with streaming support
    let storage = ModelStorage::new(
        temp_dir.path(),
        VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305),
        IntegrityVerifier::new(HashAlgorithm::Blake3),
    )?;

    // Generate encryption key
    let key = EncryptionKey::generate();
    println!("Generated encryption key");

    // Create model metadata
    let model_id = Uuid::new_v4();
    let model_size = 100 * 1024 * 1024; // 100MB
    let metadata = ModelMetadata {
        id: model_id,
        name: "large_language_model.bin".to_string(),
        version: "1.0.0".to_string(),
        format: ModelFormat::PyTorch,
        size_bytes: model_size as u64,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        description: Some("A large model for streaming encryption demo".to_string()),
        tags: vec!["demo".to_string(), "streaming".to_string()],
        framework: Some(ModelFramework::PyTorch),
        architecture: Some("transformer".to_string()),
        parameters_count: Some(1_000_000_000),
        watermark: None,
        license_constraints: None,
    };

    println!("\nModel Details:");
    println!("  ID: {}", model_id);
    println!("  Name: {}", metadata.name);
    println!("  Size: {} MB", model_size / (1024 * 1024));

    // Simulate large model data generation and streaming encryption
    println!("\n1. Streaming Encryption Demo");
    println!("   -------------------------");

    {
        let mut writer = storage.create_streaming_writer(model_id, metadata.clone(), &key)?;

        println!(
            "   Writing and encrypting {} MB of data in 1MB chunks...",
            model_size / (1024 * 1024)
        );

        let chunk_size = 1024 * 1024; // 1MB chunks
        let mut total_written = 0;

        // Generate and write data in chunks
        for i in 0..(model_size / chunk_size) {
            // Generate chunk data (simulating model weights)
            let chunk: Vec<u8> = (0..chunk_size)
                .map(|j| ((i * chunk_size + j) % 256) as u8)
                .collect();

            writer.write_all(&chunk)?;
            total_written += chunk.len();

            if i % 10 == 0 {
                println!("   Progress: {} MB written", total_written / (1024 * 1024));
            }
        }

        writer.finalize()?;
        println!(
            "   ✓ Successfully encrypted and stored {} MB",
            total_written / (1024 * 1024)
        );
    }

    // Demonstrate streaming decryption
    println!("\n2. Streaming Decryption Demo");
    println!("   -------------------------");

    {
        let mut reader = storage.create_streaming_reader(model_id, &key)?;

        println!(
            "   Reading and decrypting model: {}",
            reader.metadata().name
        );
        println!(
            "   Model size: {} MB",
            reader.metadata().size_bytes / (1024 * 1024)
        );

        let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer
        let mut total_read = 0;
        let mut checksum: u64 = 0;

        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }

            // Process the decrypted chunk (e.g., compute checksum)
            for &byte in &buffer[..n] {
                checksum = checksum.wrapping_add(byte as u64);
            }

            total_read += n;
            if total_read % (10 * 1024 * 1024) == 0 {
                println!("   Progress: {} MB read", total_read / (1024 * 1024));
            }
        }

        println!(
            "   ✓ Successfully decrypted {} MB",
            total_read / (1024 * 1024)
        );
        println!("   Checksum: {}", checksum);
    }

    // Demonstrate chunk processing
    println!("\n3. Chunk Processing Demo");
    println!("   ---------------------");

    let mut chunk_count = 0;
    let mut total_processed = 0;

    storage.stream_model(model_id, &key, |chunk| {
        chunk_count += 1;
        total_processed += chunk.len();

        if chunk_count % 100 == 0 {
            println!(
                "   Processed {} chunks ({} MB)",
                chunk_count,
                total_processed / (1024 * 1024)
            );
        }

        Ok(())
    })?;

    println!("   ✓ Processed {} total chunks", chunk_count);
    println!("   ✓ Total data: {} MB", total_processed / (1024 * 1024));

    // Demonstrate streaming from external source
    println!("\n4. External Source Streaming Demo");
    println!("   ------------------------------");

    // Simulate reading from an external source (e.g., network, S3, etc.)
    struct ExternalDataSource {
        size: usize,
        position: usize,
    }

    impl Read for ExternalDataSource {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = self.size - self.position;
            let to_read = std::cmp::min(buf.len(), remaining);

            // Simulate data generation
            for i in 0..to_read {
                buf[i] = ((self.position + i) % 256) as u8;
            }

            self.position += to_read;
            Ok(to_read)
        }
    }

    let external_model_id = Uuid::new_v4();
    let external_size = 50 * 1024 * 1024; // 50MB
    let mut external_metadata = metadata.clone();
    external_metadata.id = external_model_id;
    external_metadata.size_bytes = external_size as u64;
    external_metadata.name = "external_model.bin".to_string();

    println!("   Streaming from external source...");
    let external_source = ExternalDataSource {
        size: external_size,
        position: 0,
    };

    storage.store_model_streaming(external_model_id, external_metadata, external_source, &key)?;

    println!(
        "   ✓ Successfully encrypted {} MB from external source",
        external_size / (1024 * 1024)
    );

    // Verify the external model
    let mut verify_buffer = Vec::new();
    storage.load_model_streaming(external_model_id, &key, &mut verify_buffer)?;
    println!(
        "   ✓ Verified: read back {} MB",
        verify_buffer.len() / (1024 * 1024)
    );

    println!("\n✅ All streaming encryption demos completed successfully!");

    Ok(())
}
