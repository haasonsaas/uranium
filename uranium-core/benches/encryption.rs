use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use uranium_core::crypto::{EncryptionAlgorithm, EncryptionKey, VaultCrypto};

fn benchmark_encryption(c: &mut Criterion) {
    let key = EncryptionKey::generate();

    // Test different data sizes
    let sizes = vec![
        ("1KB", 1024),
        ("1MB", 1024 * 1024),
        ("10MB", 10 * 1024 * 1024),
        ("100MB", 100 * 1024 * 1024),
    ];

    // Benchmark ChaCha20-Poly1305
    let chacha_crypto = VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);

    for (name, size) in &sizes {
        let data = vec![0u8; *size];

        let mut group = c.benchmark_group(format!("ChaCha20-{}", name));
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function("encrypt", |b| {
            b.iter(|| {
                let _ = chacha_crypto.encrypt(&key, black_box(&data));
            });
        });

        let encrypted = chacha_crypto.encrypt(&key, &data).unwrap();

        group.bench_function("decrypt", |b| {
            b.iter(|| {
                let _ = chacha_crypto.decrypt(&key, black_box(&encrypted));
            });
        });

        group.finish();
    }

    // Benchmark AES-GCM
    let aes_crypto = VaultCrypto::new(EncryptionAlgorithm::AesGcm256);

    for (name, size) in &sizes {
        let data = vec![0u8; *size];

        let mut group = c.benchmark_group(format!("AES-GCM-{}", name));
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function("encrypt", |b| {
            b.iter(|| {
                let _ = aes_crypto.encrypt(&key, black_box(&data));
            });
        });

        let encrypted = aes_crypto.encrypt(&key, &data).unwrap();

        group.bench_function("decrypt", |b| {
            b.iter(|| {
                let _ = aes_crypto.decrypt(&key, black_box(&encrypted));
            });
        });

        group.finish();
    }
}

fn benchmark_key_derivation(c: &mut Criterion) {
    let password = "secure_password_123!@#";
    let salt = VaultCrypto::generate_salt();

    c.bench_function("key_derivation_pbkdf2", |b| {
        b.iter(|| {
            let _ = EncryptionKey::derive_from_password(black_box(password), black_box(&salt));
        });
    });
}

fn benchmark_hashing(c: &mut Criterion) {
    use uranium_core::integrity::{HashAlgorithm, IntegrityVerifier};

    let sizes = vec![
        ("1MB", 1024 * 1024),
        ("10MB", 10 * 1024 * 1024),
        ("100MB", 100 * 1024 * 1024),
    ];

    // Blake3
    let blake3_verifier = IntegrityVerifier::new(HashAlgorithm::Blake3);

    for (name, size) in &sizes {
        let data = vec![0u8; *size];

        let mut group = c.benchmark_group(format!("Blake3-{}", name));
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function("hash", |b| {
            b.iter(|| {
                let _ = blake3_verifier.hash_data(black_box(&data));
            });
        });

        group.finish();
    }

    // SHA256
    let sha256_verifier = IntegrityVerifier::new(HashAlgorithm::Sha256);

    for (name, size) in &sizes {
        let data = vec![0u8; *size];

        let mut group = c.benchmark_group(format!("SHA256-{}", name));
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function("hash", |b| {
            b.iter(|| {
                let _ = sha256_verifier.hash_data(black_box(&data));
            });
        });

        group.finish();
    }
}

criterion_group!(
    benches,
    benchmark_encryption,
    benchmark_key_derivation,
    benchmark_hashing
);
criterion_main!(benches);
