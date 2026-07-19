//! Authenticated, bounded matched-probe wire primitive.
//!
//! Probe streams are ordinary QUIC bidirectional streams on a carrier that
//! has already completed at least one full Proteus inner handshake. The
//! command is therefore encrypted by QUIC and possession-bound to the same
//! carrier; the server never serves it on an unauthenticated connection.

use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;

use crate::recovery::{RecoveryCounters, RecoveryDirection, RecoveryProfile};

pub(crate) const CONTROL_MARKER: [u8; 16] = *b"proteus-probe-v1";
const RESPONSE_MARKER: [u8; 8] = *b"prb-res1";
const HEADER_TAIL_LEN: usize = 16;
const RESPONSE_LEN: usize = 33;
pub const PROBE_PAYLOAD_BYTES: u32 = 4 * 1024 * 1024;
pub const MAX_PROBE_PAYLOAD_BYTES: u32 = PROBE_PAYLOAD_BYTES;
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

fn read_error(error: quinn::ReadExactError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, error.to_string())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProbeResult {
    pub direction: RecoveryDirection,
    pub profile: RecoveryProfile,
    pub payload_bytes: u64,
    pub completion_time: Duration,
    pub counters: RecoveryCounters,
}

fn direction_byte(direction: RecoveryDirection) -> u8 {
    match direction {
        RecoveryDirection::ClientToServer => 0,
        RecoveryDirection::ServerToClient => 1,
    }
}

fn profile_byte(profile: RecoveryProfile) -> u8 {
    match profile {
        RecoveryProfile::Standard => 0,
        RecoveryProfile::ReorderTolerant => 1,
    }
}

fn parse_direction(value: u8) -> Option<RecoveryDirection> {
    match value {
        0 => Some(RecoveryDirection::ClientToServer),
        1 => Some(RecoveryDirection::ServerToClient),
        _ => None,
    }
}

fn parse_profile(value: u8) -> Option<RecoveryProfile> {
    match value {
        0 => Some(RecoveryProfile::Standard),
        1 => Some(RecoveryProfile::ReorderTolerant),
        _ => None,
    }
}

pub(crate) fn encode_command(
    direction: RecoveryDirection,
    profile: RecoveryProfile,
    thresholds: crate::recovery::RecoveryThresholds,
    payload_bytes: u32,
) -> [u8; 32] {
    let mut command = [0u8; 32];
    command[..CONTROL_MARKER.len()].copy_from_slice(&CONTROL_MARKER);
    command[16] = 1;
    command[17] = direction_byte(direction);
    command[18] = profile_byte(profile);
    command[20..24].copy_from_slice(&thresholds.packet_threshold.to_be_bytes());
    command[24..28].copy_from_slice(&thresholds.time_threshold.to_bits().to_be_bytes());
    command[28..32].copy_from_slice(&payload_bytes.to_be_bytes());
    command
}

fn decode_header(
    tail: [u8; HEADER_TAIL_LEN],
) -> Option<(
    RecoveryDirection,
    RecoveryProfile,
    crate::recovery::RecoveryThresholds,
    u32,
)> {
    if tail[0] != 1 || tail[3] != 0 {
        return None;
    }
    let direction = parse_direction(tail[1])?;
    let profile = parse_profile(tail[2])?;
    let thresholds = crate::recovery::RecoveryThresholds {
        packet_threshold: u32::from_be_bytes(tail[4..8].try_into().ok()?),
        time_threshold: f32::from_bits(u32::from_be_bytes(tail[8..12].try_into().ok()?)),
    };
    if !(3..=64).contains(&thresholds.packet_threshold)
        || !thresholds.time_threshold.is_finite()
        || !(1.125..=4.0).contains(&thresholds.time_threshold)
    {
        return None;
    }
    let payload_bytes = u32::from_be_bytes(tail[12..16].try_into().ok()?);
    if payload_bytes > MAX_PROBE_PAYLOAD_BYTES
        || (payload_bytes == 0 && !matches!(direction, RecoveryDirection::ServerToClient))
    {
        return None;
    }
    Some((direction, profile, thresholds, payload_bytes))
}

fn delta(before: &quinn::ConnectionStats, after: &quinn::ConnectionStats) -> RecoveryCounters {
    RecoveryCounters {
        sent_packets: after
            .path
            .sent_packets
            .saturating_sub(before.path.sent_packets),
        declared_lost_packets: after
            .path
            .lost_packets
            .saturating_sub(before.path.lost_packets),
        spurious_lost_packets: after
            .path
            .spurious_lost_packets
            .saturating_sub(before.path.spurious_lost_packets),
    }
}

fn encode_response(counters: RecoveryCounters) -> [u8; RESPONSE_LEN] {
    let mut response = [0u8; RESPONSE_LEN];
    response[..8].copy_from_slice(&RESPONSE_MARKER);
    response[8] = 0;
    response[9..17].copy_from_slice(&counters.sent_packets.to_be_bytes());
    response[17..25].copy_from_slice(&counters.declared_lost_packets.to_be_bytes());
    response[25..33].copy_from_slice(&counters.spurious_lost_packets.to_be_bytes());
    response
}

pub(crate) fn decode_response(response: [u8; RESPONSE_LEN]) -> Option<RecoveryCounters> {
    if response[..8] != RESPONSE_MARKER || response[8] != 0 {
        return None;
    }
    Some(RecoveryCounters {
        sent_packets: u64::from_be_bytes(response[9..17].try_into().ok()?),
        declared_lost_packets: u64::from_be_bytes(response[17..25].try_into().ok()?),
        spurious_lost_packets: u64::from_be_bytes(response[25..33].try_into().ok()?),
    })
}

pub(crate) async fn handle_control_stream(
    recv: &mut quinn::RecvStream,
    send: &mut quinn::SendStream,
    connection: &quinn::Connection,
) -> std::io::Result<()> {
    let mut tail = [0u8; HEADER_TAIL_LEN];
    recv.read_exact(&mut tail).await.map_err(read_error)?;
    let (direction, _profile, thresholds, payload_bytes) = decode_header(tail)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid probe"))?;
    let chunk = [0x5au8; 64 * 1024];
    let mut received = vec![0u8; chunk.len()];
    let mut remaining = payload_bytes as usize;

    if payload_bytes == 0 {
        connection
            .set_loss_detection_thresholds(thresholds.packet_threshold, thresholds.time_threshold);
        connection.enable_adaptive_reordering(
            crate::ADAPTIVE_PACKET_THRESHOLD_MAX,
            crate::ADAPTIVE_TIME_THRESHOLD_MAX,
        );
        send.write_all(&encode_response(RecoveryCounters::default()))
            .await?;
        send.finish()?;
        return Ok(());
    }

    match direction {
        RecoveryDirection::ClientToServer => {
            while remaining > 0 {
                let take = remaining.min(chunk.len());
                recv.read_exact(&mut received[..take])
                    .await
                    .map_err(read_error)?;
                if received[..take].iter().any(|byte| *byte != 0x5a) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "probe payload mismatch",
                    ));
                }
                remaining -= take;
            }
            send.write_all(&encode_response(RecoveryCounters::default()))
                .await?;
        }
        RecoveryDirection::ServerToClient => {
            connection.disable_adaptive_packet_reordering();
            connection.set_loss_detection_thresholds(
                thresholds.packet_threshold,
                thresholds.time_threshold,
            );
            tokio::time::sleep(
                connection
                    .rtt()
                    .clamp(Duration::from_millis(1), Duration::from_millis(500)),
            )
            .await;
            let before = connection.stats();
            while remaining > 0 {
                let take = remaining.min(chunk.len());
                send.write_all(&chunk[..take]).await?;
                remaining -= take;
            }
            send.flush().await?;
            let mut receipt = [0u8; 1];
            recv.read_exact(&mut receipt).await.map_err(read_error)?;
            if receipt[0] != 0xa5 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid probe receipt",
                ));
            }
            // The receipt proves application delivery, while its QUIC packet
            // normally carries ACKs for the tail of the probe. Give those
            // ACKs one bounded RTT to settle before taking loss/spurious
            // counters. Client completion time was captured at payload
            // delivery and therefore excludes this telemetry-only wait.
            tokio::time::sleep(
                connection
                    .rtt()
                    .clamp(Duration::from_millis(1), Duration::from_millis(500)),
            )
            .await;
            send.write_all(&encode_response(delta(&before, &connection.stats())))
                .await?;
        }
    }
    send.finish()?;
    Ok(())
}

pub(crate) async fn run_client_probe(
    connection: &quinn::Connection,
    direction: RecoveryDirection,
    profile: RecoveryProfile,
    thresholds: crate::recovery::RecoveryThresholds,
    payload_bytes: u32,
) -> std::io::Result<ProbeResult> {
    if payload_bytes == 0 || payload_bytes > MAX_PROBE_PAYLOAD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "probe payload outside bounded range",
        ));
    }
    if matches!(direction, RecoveryDirection::ClientToServer) {
        connection.disable_adaptive_packet_reordering();
        connection
            .set_loss_detection_thresholds(thresholds.packet_threshold, thresholds.time_threshold);
        tokio::time::sleep(
            connection
                .rtt()
                .clamp(Duration::from_millis(1), Duration::from_millis(500)),
        )
        .await;
    }
    let before = connection.stats();
    let started = Instant::now();
    let mut completion_time = None;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&encode_command(
        direction,
        profile,
        thresholds,
        payload_bytes,
    ))
    .await?;
    let chunk = [0x5au8; 64 * 1024];

    match direction {
        RecoveryDirection::ClientToServer => {
            let mut remaining = payload_bytes as usize;
            while remaining > 0 {
                let take = remaining.min(chunk.len());
                send.write_all(&chunk[..take]).await?;
                remaining -= take;
            }
            send.flush().await?;
        }
        RecoveryDirection::ServerToClient => {
            let mut remaining = payload_bytes as usize;
            let mut received = vec![0u8; chunk.len()];
            while remaining > 0 {
                let take = remaining.min(chunk.len());
                recv.read_exact(&mut received[..take])
                    .await
                    .map_err(read_error)?;
                if received[..take].iter().any(|byte| *byte != 0x5a) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "probe payload mismatch",
                    ));
                }
                remaining -= take;
            }
            completion_time = Some(started.elapsed());
            send.write_all(&[0xa5]).await?;
            send.flush().await?;
        }
    }

    let mut response = [0u8; RESPONSE_LEN];
    recv.read_exact(&mut response).await.map_err(read_error)?;
    let remote_counters = decode_response(response).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid probe response")
    })?;
    if matches!(direction, RecoveryDirection::ClientToServer) {
        completion_time = Some(started.elapsed());
        tokio::time::sleep(
            connection
                .rtt()
                .clamp(Duration::from_millis(1), Duration::from_millis(500)),
        )
        .await;
    }
    let local_counters = delta(&before, &connection.stats());
    Ok(ProbeResult {
        direction,
        profile,
        payload_bytes: u64::from(payload_bytes),
        completion_time: completion_time.unwrap_or_else(|| started.elapsed()),
        counters: match direction {
            RecoveryDirection::ClientToServer => local_counters,
            RecoveryDirection::ServerToClient => remote_counters,
        },
    })
}

pub(crate) async fn apply_remote_profile(
    connection: &quinn::Connection,
    profile: RecoveryProfile,
    thresholds: crate::recovery::RecoveryThresholds,
) -> std::io::Result<()> {
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&encode_command(
        RecoveryDirection::ServerToClient,
        profile,
        thresholds,
        0,
    ))
    .await?;
    send.flush().await?;
    let mut response = [0u8; RESPONSE_LEN];
    recv.read_exact(&mut response).await.map_err(read_error)?;
    decode_response(response).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid profile-apply response",
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_is_versioned_bounded_and_directional() {
        let command = encode_command(
            RecoveryDirection::ServerToClient,
            RecoveryProfile::ReorderTolerant,
            crate::recovery::RecoveryPolicy::default().reorder_tolerant,
            PROBE_PAYLOAD_BYTES,
        );
        assert_eq!(&command[..16], &CONTROL_MARKER);
        assert_eq!(
            decode_header(command[16..].try_into().unwrap()),
            Some((
                RecoveryDirection::ServerToClient,
                RecoveryProfile::ReorderTolerant,
                crate::recovery::RecoveryPolicy::default().reorder_tolerant,
                PROBE_PAYLOAD_BYTES
            ))
        );
    }

    #[test]
    fn zero_payload_is_reserved_for_remote_profile_apply() {
        let command = encode_command(
            RecoveryDirection::ServerToClient,
            RecoveryProfile::Standard,
            crate::recovery::RecoveryPolicy::default().standard,
            0,
        );
        assert_eq!(
            decode_header(command[16..].try_into().unwrap()),
            Some((
                RecoveryDirection::ServerToClient,
                RecoveryProfile::Standard,
                crate::recovery::RecoveryPolicy::default().standard,
                0
            ))
        );
        let invalid = encode_command(
            RecoveryDirection::ClientToServer,
            RecoveryProfile::Standard,
            crate::recovery::RecoveryPolicy::default().standard,
            0,
        );
        assert_eq!(decode_header(invalid[16..].try_into().unwrap()), None);
    }

    #[test]
    fn command_rejects_out_of_range_or_non_finite_thresholds() {
        for thresholds in [
            crate::recovery::RecoveryThresholds {
                packet_threshold: 2,
                time_threshold: 1.125,
            },
            crate::recovery::RecoveryThresholds {
                packet_threshold: 65,
                time_threshold: 1.125,
            },
            crate::recovery::RecoveryThresholds {
                packet_threshold: 10,
                time_threshold: f32::NAN,
            },
            crate::recovery::RecoveryThresholds {
                packet_threshold: 10,
                time_threshold: 4.001,
            },
        ] {
            let command = encode_command(
                RecoveryDirection::ServerToClient,
                RecoveryProfile::ReorderTolerant,
                thresholds,
                PROBE_PAYLOAD_BYTES,
            );
            assert_eq!(decode_header(command[16..].try_into().unwrap()), None);
        }
    }

    #[test]
    fn response_round_trips_counters() {
        let counters = RecoveryCounters {
            sent_packets: 9,
            declared_lost_packets: 4,
            spurious_lost_packets: 2,
        };
        assert_eq!(decode_response(encode_response(counters)), Some(counters));
    }
}
