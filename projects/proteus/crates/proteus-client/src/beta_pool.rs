//! Process-wide pool of reusable β QUIC carriers.
//!
//! This is intentionally separate from [`crate::endpoint_pool`].
//! `EndpointPool` chooses a healthy VPS; `BetaConnectionPool`
//! amortizes QUIC/TLS setup for each chosen concrete endpoint.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{Mutex, OnceCell};

use proteus_transport_beta::client::BetaClientConnection;

/// Identity of one reusable carrier. Performance and trust settings
/// are process-lifetime configuration, so endpoint + SNI completely
/// identify a carrier inside one client process.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BetaPoolKey {
    server_addr: SocketAddr,
    server_name: String,
}

impl BetaPoolKey {
    #[must_use]
    pub fn new(server_addr: SocketAddr, server_name: impl Into<String>) -> Self {
        Self {
            server_addr,
            server_name: server_name.into(),
        }
    }
}

type CarrierCell = Arc<OnceCell<BetaClientConnection>>;

/// Async single-flight carrier cache.
///
/// Concurrent SOCKS requests for the same endpoint share one
/// initialization future instead of creating a QUIC handshake
/// stampede. Failed initializations are removed, so the next request
/// can recover. Closed carriers are also discarded before reuse.
#[derive(Default)]
pub struct BetaConnectionPool {
    entries: Mutex<HashMap<BetaPoolKey, CarrierCell>>,
}

impl BetaConnectionPool {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_or_try_init<E, F, Fut>(
        &self,
        key: BetaPoolKey,
        init: F,
    ) -> Result<BetaClientConnection, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<BetaClientConnection, E>>,
    {
        let cell = {
            let mut entries = self.entries.lock().await;
            if let Some(existing) = entries.get(&key) {
                match existing.get() {
                    // Initialization is already in flight. Join the
                    // same OnceCell instead of replacing it and
                    // creating a handshake stampede.
                    None => Arc::clone(existing),
                    Some(carrier) if carrier.is_usable() => Arc::clone(existing),
                    Some(_) => {
                        let fresh = Arc::new(OnceCell::new());
                        entries.insert(key.clone(), Arc::clone(&fresh));
                        fresh
                    }
                }
            } else {
                let fresh = Arc::new(OnceCell::new());
                entries.insert(key.clone(), Arc::clone(&fresh));
                fresh
            }
        };

        match cell.get_or_try_init(init).await {
            Ok(carrier) => Ok(carrier.clone()),
            Err(error) => {
                let mut entries = self.entries.lock().await;
                if entries
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &cell))
                {
                    entries.remove(&key);
                }
                Err(error)
            }
        }
    }

    /// Evict `carrier` only if it is still the current value for
    /// `key`; this avoids a stale stream failure deleting a newer
    /// replacement installed by another task.
    pub async fn evict_if_current(&self, key: &BetaPoolKey, carrier: &BetaClientConnection) {
        let mut entries = self.entries.lock().await;
        let should_remove = entries
            .get(key)
            .and_then(|cell| cell.get())
            .is_some_and(|current| current.stable_id() == carrier.stable_id());
        if should_remove {
            entries.remove(key);
        }
    }

    /// Remove every cached carrier so subsequent CONNECTs redial
    /// against freshly reloaded endpoint policy. Active sessions
    /// retain their own carrier lease and continue to completion;
    /// idle carriers close when their final cache handle drops.
    pub async fn invalidate_all(&self) {
        self.entries.lock().await.clear();
    }

    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_initialization_is_single_flight_and_closed_carrier_recovers() {
        let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(ck.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
        let endpoint = proteus_transport_beta::server::make_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![cert_der.clone()],
            key_der,
        )
        .unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    if let Ok(connection) = incoming.await {
                        let _ = connection.closed().await;
                    }
                });
            }
        });

        let crypto = Arc::new(
            proteus_transport_beta::client::build_client_crypto_cache(vec![cert_der]).unwrap(),
        );
        let pool = Arc::new(BetaConnectionPool::new());
        let key = BetaPoolKey::new(server_addr, "localhost");
        let initializations = Arc::new(AtomicUsize::new(0));

        let get = |pool: Arc<BetaConnectionPool>| {
            let key = key.clone();
            let crypto = Arc::clone(&crypto);
            let initializations = Arc::clone(&initializations);
            async move {
                pool.get_or_try_init(key, || async move {
                    initializations.fetch_add(1, Ordering::SeqCst);
                    proteus_transport_beta::client::connect_carrier_with_timeout_perf_cached_crypto(
                        "localhost",
                        server_addr,
                        &crypto,
                        Duration::from_secs(5),
                        proteus_transport_beta::PerfProfile::default(),
                    )
                    .await
                })
                .await
            }
        };

        let (first, second) = tokio::join!(get(Arc::clone(&pool)), get(Arc::clone(&pool)));
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.stable_id(), second.stable_id());
        assert_eq!(initializations.load(Ordering::SeqCst), 1);
        assert_eq!(pool.len().await, 1);

        first.close();
        assert!(!first.is_usable());
        let replacement = get(Arc::clone(&pool)).await.unwrap();
        assert_ne!(replacement.stable_id(), first.stable_id());
        assert_eq!(initializations.load(Ordering::SeqCst), 2);

        pool.invalidate_all().await;
        assert_eq!(pool.len().await, 0);
        replacement.close();
        server_task.abort();
    }
}
