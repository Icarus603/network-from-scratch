//! Hybrid KEX latency baseline. Measures the slowest CPU-bound piece
//! of the handshake: ML-KEM-768 Encaps + Decaps, X25519 keygen + DH.
//!
//! Spec §17.2 budgets ~80 µs of server-side ML-KEM Decap + X25519
//! per handshake. These benches let us catch regressions there.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ml_kem::{KemCore, MlKem768};
use proteus_crypto::kex;
use rand_core::OsRng;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

fn bench_client_ephemeral(c: &mut Criterion) {
    let mut rng = OsRng;
    let (_sk, pk) = MlKem768::generate(&mut rng);
    c.bench_function(
        "client_ephemeral (X25519 keygen + ML-KEM-768 Encaps)",
        |b| {
            b.iter(|| {
                let eph = kex::client_ephemeral(&mut rng, black_box(&pk)).expect("ephemeral");
                black_box(eph);
            });
        },
    );
}

fn bench_server_combine(c: &mut Criterion) {
    let mut rng = OsRng;
    let (sk, pk) = MlKem768::generate(&mut rng);
    let server_x_sk = StaticSecret::random_from_rng(rng);
    let server_x_pub = XPublicKey::from(&server_x_sk).to_bytes();

    let eph = kex::client_ephemeral(&mut rng, &pk).unwrap();
    let _check = kex::client_combine(&eph, &server_x_pub).unwrap();

    c.bench_function("server_combine (X25519 DH + ML-KEM-768 Decaps)", |b| {
        b.iter(|| {
            let combined = kex::server_combine(
                black_box(&server_x_sk),
                black_box(&sk),
                black_box(&eph.x25519_pub),
                black_box(&eph.mlkem_ct),
            )
            .expect("combine");
            black_box(combined);
        });
    });
}

criterion_group!(benches, bench_client_ephemeral, bench_server_combine);
criterion_main!(benches);
