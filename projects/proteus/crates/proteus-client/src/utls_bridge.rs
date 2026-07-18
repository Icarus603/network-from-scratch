//! Client side of the local Proteus uTLS bridge protocol.
//!
//! The Go bridge owns only the outer TLS connection. It returns the
//! TLS 1.3 exporter and then behaves as a transparent byte stream.
//! The Rust client keeps the hybrid Proteus handshake and commits it
//! to that exporter through `handshake_over_split_bound`.

use std::path::Path;

use proteus_transport_alpha::client::{self, CHANNEL_BINDING_LEN};
use proteus_transport_alpha::session::AlphaSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"PUTL";
const VERSION: u8 = 1;
const MAX_TARGET_LEN: usize = 1024;
const MAX_SERVER_NAME_LEN: usize = 253;
const MAX_ERROR_LEN: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("uTLS bridge I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("uTLS bridge rejected dial: {0}")]
    Rejected(String),
    #[error("uTLS bridge protocol violation: {0}")]
    Protocol(&'static str),
    #[error("inner Proteus handshake over uTLS bridge: {0}")]
    Alpha(#[from] proteus_transport_alpha::error::AlphaError),
}

pub async fn connect_stream(
    socket_path: &Path,
    target: &str,
    server_name: &str,
) -> Result<(UnixStream, Zeroizing<[u8; CHANNEL_BINDING_LEN]>), BridgeError> {
    if target.is_empty() || target.len() > MAX_TARGET_LEN {
        return Err(BridgeError::Protocol("target length outside 1..1024"));
    }
    if server_name.is_empty() || server_name.len() > MAX_SERVER_NAME_LEN {
        return Err(BridgeError::Protocol("server-name length outside 1..253"));
    }
    let target_len =
        u16::try_from(target.len()).map_err(|_| BridgeError::Protocol("target too long"))?;
    let server_name_len = u16::try_from(server_name.len())
        .map_err(|_| BridgeError::Protocol("server name too long"))?;

    let mut stream = UnixStream::connect(socket_path).await?;
    let mut request = Vec::with_capacity(9 + target.len() + server_name.len());
    request.extend_from_slice(MAGIC);
    request.push(VERSION);
    request.extend_from_slice(&target_len.to_be_bytes());
    request.extend_from_slice(&server_name_len.to_be_bytes());
    request.extend_from_slice(target.as_bytes());
    request.extend_from_slice(server_name.as_bytes());
    stream.write_all(&request).await?;

    let status = stream.read_u8().await?;
    match status {
        0 => {
            let mut exporter = Zeroizing::new([0u8; CHANNEL_BINDING_LEN]);
            stream.read_exact(&mut exporter[..]).await?;
            Ok((stream, exporter))
        }
        1 => {
            let error_len = usize::from(stream.read_u16().await?);
            if error_len > MAX_ERROR_LEN {
                return Err(BridgeError::Protocol("bridge error message too long"));
            }
            let mut message = vec![0u8; error_len];
            stream.read_exact(&mut message).await?;
            let message = String::from_utf8(message)
                .map_err(|_| BridgeError::Protocol("bridge error is not UTF-8"))?;
            Err(BridgeError::Rejected(message))
        }
        _ => Err(BridgeError::Protocol("unknown bridge response status")),
    }
}

pub async fn handshake(
    socket_path: &Path,
    target: &str,
    server_name: &str,
    config: &client::ClientConfig,
) -> Result<AlphaSession<OwnedReadHalf, OwnedWriteHalf>, BridgeError> {
    let (stream, exporter) = connect_stream(socket_path, target, server_name).await?;
    let (read, write) = stream.into_split();
    Ok(client::handshake_over_split_bound(read, write, config, Some(*exporter)).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn request_and_exporter_round_trip() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("bridge.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let expected_exporter = [0x5au8; CHANNEL_BINDING_LEN];

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 9];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[..4], MAGIC);
            assert_eq!(header[4], VERSION);
            let target_len = usize::from(u16::from_be_bytes([header[5], header[6]]));
            let name_len = usize::from(u16::from_be_bytes([header[7], header[8]]));
            let mut payload = vec![0u8; target_len + name_len];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload[..target_len], b"198.51.100.42:443");
            assert_eq!(&payload[target_len..], b"vps.example.com");
            stream.write_all(&[0]).await.unwrap();
            stream.write_all(&expected_exporter).await.unwrap();
        });

        let (_, exporter) = connect_stream(&socket, "198.51.100.42:443", "vps.example.com")
            .await
            .unwrap();
        assert_eq!(&*exporter, &expected_exporter);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_bridge_error_is_rejected_before_allocation() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("bridge.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 9];
            stream.read_exact(&mut header).await.unwrap();
            let target_len = usize::from(u16::from_be_bytes([header[5], header[6]]));
            let name_len = usize::from(u16::from_be_bytes([header[7], header[8]]));
            let mut payload = vec![0u8; target_len + name_len];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&[1]).await.unwrap();
            stream
                .write_all(&u16::try_from(MAX_ERROR_LEN + 1).unwrap().to_be_bytes())
                .await
                .unwrap();
        });

        let err = connect_stream(&socket, "198.51.100.42:443", "vps.example.com")
            .await
            .unwrap_err();
        assert!(matches!(err, BridgeError::Protocol(_)));
        server.await.unwrap();
    }
}
