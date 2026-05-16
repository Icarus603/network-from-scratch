//! AEAD throughput baseline (ChaCha20-Poly1305 seal + open).
//!
//! This is the bound on Proteus's per-session bulk encryption rate.
//! Run with `cargo bench -p proteus-crypto --bench aead_throughput`.
//! On Apple Silicon M-series we expect ~1.5–2.5 GB/s seal + open at
//! 16 KiB chunks. On x86_64 with AES-NI the AES-256-GCM alternative
//! would be ~4 GB/s; we hold to ChaCha20 here because it's the
//! mandated default (spec §6).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use proteus_crypto::aead;

fn bench_seal(c: &mut Criterion) {
    let key = [0x42u8; aead::KEY_LEN];
    let iv = [0x11u8; aead::NONCE_LEN];
    let aad = [0u8; 8];

    let mut group = c.benchmark_group("aead_seal");
    for &size in &[1024usize, 4096, 16 * 1024, 64 * 1024] {
        let payload = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            let mut counter = 0u64;
            b.iter(|| {
                counter = counter.wrapping_add(1);
                let ct = aead::seal(
                    black_box(&key),
                    black_box(&iv),
                    counter,
                    black_box(&aad),
                    black_box(payload),
                )
                .expect("seal");
                black_box(ct);
            });
        });
    }
    group.finish();
}

fn bench_open(c: &mut Criterion) {
    let key = [0x42u8; aead::KEY_LEN];
    let iv = [0x11u8; aead::NONCE_LEN];
    let aad = [0u8; 8];

    let mut group = c.benchmark_group("aead_open");
    for &size in &[1024usize, 4096, 16 * 1024, 64 * 1024] {
        let payload = vec![0u8; size];
        // Pre-seal under a fixed nonce we'll re-use only inside this
        // benchmark loop (not in production, obviously).
        let ct = aead::seal(&key, &iv, 1, &aad, &payload).expect("seal for bench setup");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &ct, |b, ct| {
            b.iter(|| {
                let pt = aead::open(
                    black_box(&key),
                    black_box(&iv),
                    1,
                    black_box(&aad),
                    black_box(ct),
                )
                .expect("open");
                black_box(pt);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_seal, bench_open);
criterion_main!(benches);
