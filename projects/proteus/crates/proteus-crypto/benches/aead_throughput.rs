//! AEAD throughput baseline (ChaCha20-Poly1305 and AES-256-GCM seal + open).
//!
//! This is the bound on Proteus's per-session bulk encryption rate.
//! Run with `cargo bench -p proteus-crypto --bench aead_throughput`.
//! AES-256-GCM is benchmark-only until a versioned, transcript-bound,
//! downgrade-resistant suite negotiation is specified and tested.

use aws_lc_rs::aead::{
    Aad as AwsLcAad, LessSafeKey as AwsLcLessSafeKey, Nonce as AwsLcNonce,
    UnboundKey as AwsLcUnboundKey, AES_256_GCM as AWS_LC_AES_256_GCM,
};
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

/// `AeadKey::seal_into` is the cached-cipher hot path used by the α
/// data plane (iteration 10). This bench measures the per-record
/// AEAD cost when the ChaCha20-Poly1305 cipher is built ONCE and
/// reused — head-to-head with `bench_seal` above which rebuilds
/// the cipher every call. The delta is the per-record key-schedule
/// cost we eliminated.
fn bench_seal_cached(c: &mut Criterion) {
    let key = [0x42u8; aead::KEY_LEN];
    let iv = [0x11u8; aead::NONCE_LEN];
    let aad = [0u8; 8];
    let ak = aead::AeadKey::new(&key, &iv);

    let mut group = c.benchmark_group("aead_seal_cached");
    for &size in &[1024usize, 4096, 16 * 1024, 64 * 1024] {
        let payload = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            let mut counter = 0u64;
            // Reused buffer mirrors α sender's `tx_aead_scratch`:
            // capacity sticks across iterations, no allocation in
            // the loop.
            let mut buf: Vec<u8> = Vec::with_capacity(size + 16);
            b.iter(|| {
                counter = counter.wrapping_add(1);
                buf.clear();
                buf.extend_from_slice(payload);
                ak.seal_into(black_box(counter), black_box(&aad), black_box(&mut buf))
                    .expect("seal_into");
                black_box(&buf);
            });
        });
    }
    group.finish();
}

/// Mirror of `bench_seal_cached` for the open direction. Used to
/// quantify the recv-side AEAD speedup on the α data plane.
fn bench_open_cached(c: &mut Criterion) {
    let key = [0x42u8; aead::KEY_LEN];
    let iv = [0x11u8; aead::NONCE_LEN];
    let aad = [0u8; 8];
    let ak = aead::AeadKey::new(&key, &iv);

    let mut group = c.benchmark_group("aead_open_cached");
    for &size in &[1024usize, 4096, 16 * 1024, 64 * 1024] {
        let payload = vec![0u8; size];
        let mut sealed: Vec<u8> = payload.clone();
        ak.seal_into(1, &aad, &mut sealed).expect("seal for setup");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &sealed,
            |b, sealed_template| {
                let mut buf: Vec<u8> = Vec::with_capacity(size + 16);
                b.iter(|| {
                    buf.clear();
                    buf.extend_from_slice(sealed_template);
                    ak.open_in_place(black_box(1), black_box(&aad), black_box(&mut buf))
                        .expect("open_in_place");
                    black_box(&buf);
                });
            },
        );
    }
    group.finish();
}

/// AWS-LC candidate. The outer rustls/quinn stack already links this
/// implementation, so this measures whether its ARMv8 AES/PMULL path
/// can remove the inner-AEAD CPU bottleneck without adding a second
/// native crypto provider to production binaries.
fn bench_aws_lc_aes256_gcm_seal_cached(c: &mut Criterion) {
    let key = [0x42u8; aead::KEY_LEN];
    let iv = [0x11u8; aead::NONCE_LEN];
    let aad = [0u8; 8];
    let cipher = AwsLcLessSafeKey::new(
        AwsLcUnboundKey::new(&AWS_LC_AES_256_GCM, &key).expect("AWS-LC AES-256-GCM key"),
    );

    let mut group = c.benchmark_group("aws_lc_aes256_gcm_seal_cached");
    for &size in &[1024usize, 4096, 16 * 1024, 64 * 1024] {
        let payload = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            let mut counter = 0u64;
            let mut buf: Vec<u8> = Vec::with_capacity(size + aead::TAG_LEN);
            b.iter(|| {
                counter = counter.wrapping_add(1);
                buf.clear();
                buf.extend_from_slice(payload);
                let nonce = AwsLcNonce::assume_unique_for_key(aead::nonce_for(&iv, counter));
                cipher
                    .seal_in_place_append_tag(
                        nonce,
                        AwsLcAad::from(black_box(&aad[..])),
                        black_box(&mut buf),
                    )
                    .expect("AWS-LC AES-256-GCM seal_into");
                black_box(&buf);
            });
        });
    }
    group.finish();
}

/// AWS-LC open candidate, matched to all other cached-open paths.
fn bench_aws_lc_aes256_gcm_open_cached(c: &mut Criterion) {
    let key = [0x42u8; aead::KEY_LEN];
    let iv = [0x11u8; aead::NONCE_LEN];
    let aad = [0u8; 8];
    let cipher = AwsLcLessSafeKey::new(
        AwsLcUnboundKey::new(&AWS_LC_AES_256_GCM, &key).expect("AWS-LC AES-256-GCM key"),
    );

    let mut group = c.benchmark_group("aws_lc_aes256_gcm_open_cached");
    for &size in &[1024usize, 4096, 16 * 1024, 64 * 1024] {
        let payload = vec![0u8; size];
        let mut sealed = payload.clone();
        cipher
            .seal_in_place_append_tag(
                AwsLcNonce::assume_unique_for_key(aead::nonce_for(&iv, 1)),
                AwsLcAad::from(&aad[..]),
                &mut sealed,
            )
            .expect("AWS-LC AES-256-GCM seal for setup");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &sealed,
            |b, sealed_template| {
                let mut buf: Vec<u8> = Vec::with_capacity(size + aead::TAG_LEN);
                b.iter(|| {
                    buf.clear();
                    buf.extend_from_slice(sealed_template);
                    let plaintext = cipher
                        .open_in_place(
                            AwsLcNonce::assume_unique_for_key(aead::nonce_for(&iv, 1)),
                            AwsLcAad::from(black_box(&aad[..])),
                            black_box(&mut buf),
                        )
                        .expect("AWS-LC AES-256-GCM open_in_place");
                    black_box(plaintext);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_seal,
    bench_open,
    bench_seal_cached,
    bench_open_cached,
    bench_aws_lc_aes256_gcm_seal_cached,
    bench_aws_lc_aes256_gcm_open_cached
);
criterion_main!(benches);
