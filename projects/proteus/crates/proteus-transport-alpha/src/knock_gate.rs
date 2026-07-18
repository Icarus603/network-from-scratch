//! The Path A pre-auth gate: sniff the inbound ClientHello,
//! verify the embedded knock against the operator's PSK,
//! return a routing verdict.
//!
//! Composes the iteration-5 sniffer with the iteration-4
//! wire-format verifier. The accept-loop integration
//! (iteration 6) calls [`evaluate`] for every inbound
//! connection and dispatches based on the [`GateVerdict`].
//!
//! ## Verdicts (operator-actionable)
//!
//! Three outcomes drive three different behaviors:
//!
//!   * `Pass` — valid knock; caller should re-feed
//!     `peeked_bytes` into the local TLS terminator and
//!     proceed with the Proteus handshake.
//!   * `RouteToCover { reason }` — no knock OR bad knock;
//!     caller should splice `peeked_bytes` + the rest of the
//!     stream to the cover endpoint. The `reason` enum lets
//!     the throttled-log layer distinguish "no knock present"
//!     (the common case for non-Proteus clients including
//!     probers) from "knock present but invalid" (likely a
//!     misconfigured client or a sophisticated forge attempt).
//!   * Sniff failures — malformed, partial, slow, and non-TLS
//!     inputs are also routed to cover with their exact consumed
//!     prefix. A local drop would expose an active-probing oracle.
//!
//! ## Gate-disabled mode
//!
//! When the operator hasn't configured a `knock_psk_file:`, the
//! gate's `evaluate_with_psk` returns `Pass` immediately
//! WITHOUT sniffing. This preserves the existing accept-loop
//! semantics for operators who haven't opted into Path A —
//! their deploys keep working unchanged.

use std::time::Duration;

use proteus_handshake::knock::KnockPsk;
use proteus_handshake::knock_wire::{decode_and_verify_session_id, KnockWireError};
use tokio::io::AsyncRead;

use crate::clienthello_sniffer::{
    sniff_client_hello_with_limits, SniffError, SniffedClientHello, DEFAULT_PEEK_LIMIT,
    DEFAULT_PEEK_TIMEOUT,
};

/// Outcome of the gate evaluation. Drives the accept-loop's
/// dispatch decision.
#[derive(Debug)]
pub enum GateVerdict {
    /// The connection carried a valid knock. Caller should
    /// terminate TLS locally and proceed with the Proteus
    /// handshake. The carried [`SniffedClientHello`] gives
    /// the caller the raw bytes to re-feed into the TLS
    /// terminator (so it sees an unmodified handshake stream).
    Pass {
        /// Sniffer output — re-feed `peeked_bytes` into the
        /// local TLS terminator.
        sniffed: SniffedClientHello,
    },
    /// The connection should be transparently spliced to the
    /// cover endpoint. The carried [`SniffedClientHello`]'s
    /// `peeked_bytes` MUST be written to the cover socket first
    /// so the cover sees the original ClientHello.
    RouteToCover {
        /// Sniffer output — `peeked_bytes` is the prefix that
        /// must be written to the cover socket first.
        sniffed: SniffedClientHello,
        /// Why this connection is being routed to cover.
        /// Distinct variants drive distinct operational logs.
        reason: CoverReason,
    },
    /// The connection is unrecoverably bad — close silently.
    Drop {
        /// Why we're dropping.
        reason: DropReason,
    },
}

/// Reason a connection was routed to cover. Separate variants
/// support throttled per-reason logging at the call site.
#[derive(Debug)]
pub enum CoverReason {
    /// Peer closed before a complete ClientHello was available.
    IncompleteClientHello {
        /// Bytes consumed before EOF.
        bytes_read: usize,
    },
    /// The sniff deadline fired. The captured prefix, including
    /// an empty prefix, is still replayed to cover.
    PeekTimeout {
        /// Bytes consumed before timeout.
        bytes_read: usize,
    },
    /// The bytes were not a parseable TLS ClientHello. They are
    /// forwarded verbatim so plaintext and malformed probes see
    /// the same endpoint behavior as a direct cover connection.
    MalformedClientHello {
        /// Parser detail for throttled operator logs.
        detail: String,
    },
    /// The inbound read itself failed after consuming a prefix.
    SniffIo {
        /// Error detail for throttled operator logs.
        detail: String,
    },
    /// session_id wasn't the expected 32 bytes — the common
    /// case for non-Proteus clients (a real curl, a probe with
    /// random session_id length, a TLS 1.3 stack that uses
    /// 0-byte session_id). NOT a security event; the gate
    /// simply has no signal to terminate locally.
    NoKnockPresent {
        /// Length of the session_id we observed.
        session_id_len: usize,
    },
    /// session_id WAS 32 bytes but the embedded HMAC didn't
    /// verify. Either a sophisticated forge attempt, a
    /// genuinely misconfigured Proteus client (wrong PSK), or
    /// — the canonical case — a GFW prober that happened to
    /// send a 32-byte randomized session_id (Chrome's default).
    BadKnock,
    /// session_id verified BUT the timestamp was outside the
    /// ±90 s window. Suggests broken NTP on EITHER side; the
    /// gate routes to cover to be safe (could be replay).
    /// Operator alert: cross-check `clock_sync` host-preflight
    /// gauge.
    TimestampSkew {
        /// Skew in seconds (positive = client behind, negative = ahead).
        skew_secs: i64,
    },
    /// The knock was cryptographically valid and fresh, but this exact
    /// `(client_random, timestamp)` pair already passed the gate. A
    /// captured ClientHello is being replayed; route it to cover so the
    /// observer learns no local-termination oracle.
    ReplayKnock,
}

/// Reason a connection was dropped (not cover-routed). These
/// are operational failures, not security routing decisions.
#[derive(Debug)]
pub enum DropReason {
    /// Peer closed before sending enough bytes for the gate
    /// to make a decision.
    ConnectionClosed {
        /// Bytes received before EOF.
        bytes_read: usize,
    },
    /// Sniff timed out — peer accepted the TCP connection but
    /// never sent any ClientHello bytes. Common scan
    /// signature.
    Timeout,
    /// Bytes on the wire weren't TLS — likely a misconfigured
    /// client or a probe of a non-TLS protocol on this port.
    NotTls {
        /// Error from the parser, for tracing.
        detail: String,
    },
    /// Underlying I/O failure.
    Io {
        /// Error description.
        detail: String,
    },
}

/// Evaluate the gate using DEFAULT_PEEK_LIMIT + DEFAULT_PEEK_TIMEOUT.
/// `psk = None` short-circuits to `Pass` without sniffing (the
/// operator hasn't opted into Path A).
pub async fn evaluate<R>(
    reader: &mut R,
    psk: Option<&KnockPsk>,
    now_unix_seconds: u64,
) -> GateVerdict
where
    R: AsyncRead + Unpin,
{
    evaluate_with_limits(
        reader,
        psk,
        now_unix_seconds,
        DEFAULT_PEEK_LIMIT,
        DEFAULT_PEEK_TIMEOUT,
    )
    .await
}

/// Evaluate with operator-supplied limits. Mostly for tests.
pub async fn evaluate_with_limits<R>(
    reader: &mut R,
    psk: Option<&KnockPsk>,
    now_unix_seconds: u64,
    peek_limit: usize,
    peek_timeout: Duration,
) -> GateVerdict
where
    R: AsyncRead + Unpin,
{
    // Path A disabled (no PSK configured) — return Pass with a
    // synthetic sniffer result that just records "we didn't
    // look at the bytes". The accept loop's caller treats this
    // as the legacy path: hand the stream straight to TLS
    // terminator without any re-feed needed.
    //
    // CRITICAL: in this mode peeked_bytes is empty AND record_len
    // is 0; the caller must NOT re-feed — the original socket
    // is still positioned at byte 0.
    let Some(psk) = psk else {
        return GateVerdict::Pass {
            sniffed: SniffedClientHello {
                peeked_bytes: Vec::new(),
                record_len: 0,
                client_random: [0u8; 32],
                session_id: Vec::new(),
            },
        };
    };

    let sniffed = match sniff_client_hello_with_limits(reader, peek_limit, peek_timeout).await {
        Ok(s) => s,
        Err(SniffError::ConnectionClosed { peeked_bytes }) => {
            let bytes_read = peeked_bytes.len();
            return GateVerdict::RouteToCover {
                sniffed: raw_sniffed(peeked_bytes),
                reason: CoverReason::IncompleteClientHello { bytes_read },
            };
        }
        Err(SniffError::Timeout { peeked_bytes, .. }) => {
            let bytes_read = peeked_bytes.len();
            return GateVerdict::RouteToCover {
                sniffed: raw_sniffed(peeked_bytes),
                reason: CoverReason::PeekTimeout { bytes_read },
            };
        }
        Err(SniffError::BadRecord {
            detail,
            peeked_bytes,
        }) => {
            return GateVerdict::RouteToCover {
                sniffed: raw_sniffed(peeked_bytes),
                reason: CoverReason::MalformedClientHello { detail },
            };
        }
        Err(SniffError::Io {
            source,
            peeked_bytes,
        }) => {
            return GateVerdict::RouteToCover {
                sniffed: raw_sniffed(peeked_bytes),
                reason: CoverReason::SniffIo {
                    detail: source.to_string(),
                },
            };
        }
    };

    // Map the wire-format verifier's verdict into our gate
    // verdict. `Pass` proceeds to local TLS termination;
    // anything else routes to cover with a reason classification.
    match decode_and_verify_session_id(
        psk,
        &sniffed.client_random,
        &sniffed.session_id,
        now_unix_seconds,
    ) {
        Ok(()) => GateVerdict::Pass { sniffed },
        Err(KnockWireError::Decode(_)) => {
            let session_id_len = sniffed.session_id.len();
            GateVerdict::RouteToCover {
                sniffed,
                reason: CoverReason::NoKnockPresent { session_id_len },
            }
        }
        Err(KnockWireError::Knock(proteus_handshake::knock::KnockError::BadTokenLength {
            ..
        })) => {
            // Wire-format Decode catches WrongLength first, so
            // this branch is unreachable in practice. Still
            // route to cover for safety.
            let session_id_len = sniffed.session_id.len();
            GateVerdict::RouteToCover {
                sniffed,
                reason: CoverReason::NoKnockPresent { session_id_len },
            }
        }
        Err(KnockWireError::Knock(proteus_handshake::knock::KnockError::BadTag)) => {
            GateVerdict::RouteToCover {
                sniffed,
                reason: CoverReason::BadKnock,
            }
        }
        Err(KnockWireError::Knock(proteus_handshake::knock::KnockError::TimestampStale {
            skew,
        }))
        | Err(KnockWireError::Knock(proteus_handshake::knock::KnockError::TimestampFuture {
            skew,
        })) => GateVerdict::RouteToCover {
            sniffed,
            reason: CoverReason::TimestampSkew { skew_secs: skew },
        },
    }
}

fn raw_sniffed(peeked_bytes: Vec<u8>) -> SniffedClientHello {
    SniffedClientHello {
        peeked_bytes,
        record_len: 0,
        client_random: [0u8; 32],
        session_id: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_handshake::knock::{compute_knock, KnockPsk, KNOCK_PSK_LEN};
    use proteus_handshake::knock_wire::encode_session_id;
    use std::io::Cursor;

    fn psk_alpha() -> KnockPsk {
        KnockPsk::from_bytes([0xA1; KNOCK_PSK_LEN])
    }

    fn craft_clienthello(client_random: &[u8; 32], session_id: &[u8]) -> Vec<u8> {
        let mut ch_body = Vec::with_capacity(256);
        ch_body.extend_from_slice(&[0x03, 0x03]);
        ch_body.extend_from_slice(client_random);
        ch_body.push(session_id.len() as u8);
        ch_body.extend_from_slice(session_id);
        ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        ch_body.extend_from_slice(&[0x01, 0x00]);
        ch_body.extend_from_slice(&[0x00, 0x00]);
        let hs_len = ch_body.len();
        let mut hs = Vec::with_capacity(4 + hs_len);
        hs.push(0x01);
        hs.extend_from_slice(&[
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ]);
        hs.extend_from_slice(&ch_body);
        let rec_len = hs.len();
        let mut rec = Vec::with_capacity(5 + rec_len);
        rec.extend_from_slice(&[0x16, 0x03, 0x01]);
        rec.extend_from_slice(&[((rec_len >> 8) & 0xff) as u8, (rec_len & 0xff) as u8]);
        rec.extend_from_slice(&hs);
        rec
    }

    #[tokio::test]
    async fn gate_passes_legitimate_client_with_valid_knock() {
        let psk = psk_alpha();
        let client_random = [0x42; 32];
        let now = 1_715_900_000u64;
        let token = compute_knock(&psk, &client_random, now);
        let session_id = encode_session_id(&token);
        let bytes = craft_clienthello(&client_random, &session_id);

        let mut cursor = Cursor::new(bytes.clone());
        let verdict = evaluate(&mut cursor, Some(&psk), now).await;
        match verdict {
            GateVerdict::Pass { sniffed } => {
                // Re-feed-able: peeked_bytes is the original
                // ClientHello so the local TLS terminator sees
                // an unmodified handshake.
                assert_eq!(sniffed.peeked_bytes, bytes);
                assert_eq!(sniffed.client_random, client_random);
            }
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gate_routes_to_cover_when_probe_has_random_session_id() {
        let psk = psk_alpha();
        let client_random = [0x33; 32];
        let now = 1_715_900_000u64;
        // GFW prober: 32-byte random session_id (Chrome
        // default — looks legitimate at the TLS layer).
        let probe_session_id = [0xCD; 32];
        let bytes = craft_clienthello(&client_random, &probe_session_id);

        let mut cursor = Cursor::new(bytes.clone());
        let verdict = evaluate(&mut cursor, Some(&psk), now).await;
        match verdict {
            GateVerdict::RouteToCover { reason, sniffed } => {
                // BadKnock specifically — 32-byte session_id
                // passed length check but failed HMAC verify.
                assert!(matches!(reason, CoverReason::BadKnock), "got {reason:?}");
                // peeked_bytes must be intact for the caller
                // to write to the cover socket.
                assert_eq!(sniffed.peeked_bytes, bytes);
            }
            other => panic!("expected RouteToCover, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gate_routes_to_cover_when_session_id_is_empty() {
        // Real curl with a TLS 1.3 stack that emits 0-byte
        // session_id. NOT a probe — legitimate non-Proteus
        // client. Gate routes to cover so curl sees the cover
        // backend's TLS handshake.
        let psk = psk_alpha();
        let client_random = [0x44; 32];
        let now = 1_715_900_000u64;
        let bytes = craft_clienthello(&client_random, &[]);

        let mut cursor = Cursor::new(bytes);
        let verdict = evaluate(&mut cursor, Some(&psk), now).await;
        match verdict {
            GateVerdict::RouteToCover { reason, .. } => {
                assert!(
                    matches!(reason, CoverReason::NoKnockPresent { session_id_len: 0 }),
                    "got {reason:?}"
                );
            }
            other => panic!("expected RouteToCover, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gate_routes_to_cover_on_replayed_knock_with_fresh_random() {
        // Captured a real knock token. Replay against a fresh
        // ClientHello with a NEW client_random. Must fail at
        // the BadKnock layer (HMAC bound to original random).
        let psk = psk_alpha();
        let now = 1_715_900_000u64;
        let original_random = [0x11; 32];
        let token = compute_knock(&psk, &original_random, now);
        let session_id = encode_session_id(&token);

        let new_random = [0x22; 32];
        let bytes = craft_clienthello(&new_random, &session_id);
        let mut cursor = Cursor::new(bytes);
        let verdict = evaluate(&mut cursor, Some(&psk), now).await;
        assert!(
            matches!(
                verdict,
                GateVerdict::RouteToCover {
                    reason: CoverReason::BadKnock,
                    ..
                }
            ),
            "got {verdict:?}"
        );
    }

    #[tokio::test]
    async fn gate_routes_to_cover_on_timestamp_skew() {
        let psk = psk_alpha();
        let client_random = [0x55; 32];
        let issued_at = 1_715_900_000u64;
        let token = compute_knock(&psk, &client_random, issued_at);
        let session_id = encode_session_id(&token);
        let bytes = craft_clienthello(&client_random, &session_id);

        // Server's clock is 200s ahead — way out of the ±90s window.
        let mut cursor = Cursor::new(bytes);
        let verdict = evaluate(&mut cursor, Some(&psk), issued_at + 200).await;
        match verdict {
            GateVerdict::RouteToCover { reason, .. } => {
                assert!(
                    matches!(reason, CoverReason::TimestampSkew { .. }),
                    "got {reason:?}"
                );
            }
            other => panic!("expected RouteToCover, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gate_routes_partial_clienthello_to_cover() {
        let psk = psk_alpha();
        let now = 1_715_900_000u64;
        let truncated = vec![0x16, 0x03]; // 2 bytes only
        let mut cursor = Cursor::new(truncated);
        let verdict = evaluate(&mut cursor, Some(&psk), now).await;
        assert!(
            matches!(
                verdict,
                GateVerdict::RouteToCover {
                    reason: CoverReason::IncompleteClientHello { bytes_read: 2 },
                    ..
                }
            ),
            "got {verdict:?}"
        );
    }

    #[tokio::test]
    async fn gate_routes_non_tls_bytes_to_cover() {
        let psk = psk_alpha();
        let now = 1_715_900_000u64;
        let mut cursor = Cursor::new(b"GET / HTTP/1.1\r\n\r\n".to_vec());
        let verdict = evaluate(&mut cursor, Some(&psk), now).await;
        assert!(
            matches!(
                verdict,
                GateVerdict::RouteToCover {
                    reason: CoverReason::MalformedClientHello { .. },
                    ..
                }
            ),
            "got {verdict:?}"
        );
    }

    #[tokio::test]
    async fn gate_passes_immediately_when_psk_is_none() {
        // Path A disabled. Gate returns Pass without reading
        // ANY bytes — the accept loop hands the stream
        // straight to TLS as it always has.
        let mut cursor = Cursor::new(b"any garbage".to_vec());
        let verdict = evaluate(&mut cursor, None, 1_715_900_000u64).await;
        match verdict {
            GateVerdict::Pass { sniffed } => {
                // The "no PSK" Pass returns empty bytes — the
                // caller MUST NOT re-feed (the cursor was
                // never read from).
                assert!(sniffed.peeked_bytes.is_empty());
                assert_eq!(sniffed.record_len, 0);
            }
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gate_routes_peer_stall_to_cover() {
        // PendingReader stalls forever. Gate's deadline fires.
        struct PendingReader;
        impl AsyncRead for PendingReader {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Pending
            }
        }
        let psk = psk_alpha();
        let mut r = PendingReader;
        let verdict = evaluate_with_limits(
            &mut r,
            Some(&psk),
            1_715_900_000u64,
            DEFAULT_PEEK_LIMIT,
            Duration::from_millis(50),
        )
        .await;
        assert!(
            matches!(
                verdict,
                GateVerdict::RouteToCover {
                    reason: CoverReason::PeekTimeout { bytes_read: 0 },
                    ..
                }
            ),
            "got {verdict:?}"
        );
    }
}
