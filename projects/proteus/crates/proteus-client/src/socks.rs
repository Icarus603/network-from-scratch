//! Minimal SOCKS5 inbound (RFC 1928) → Proteus α outbound.
//!
//! Supported: TCP CONNECT, no auth (`0x00`). UDP-ASSOCIATE / BIND not
//! implemented (Proteus α is TCP-only; UDP is a γ/β profile concern).

use std::sync::Arc;

use proteus_transport_alpha::client as p_client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::ClientConfig;

#[derive(thiserror::Error, Debug)]
pub enum SocksError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("config: {0}")]
    Config(#[from] crate::config::ConfigError),

    #[error("alpha: {0}")]
    Alpha(#[from] proteus_transport_alpha::error::AlphaError),

    #[error("socks5: {0}")]
    Socks(&'static str),
}

pub async fn handle_socks5(mut sock: TcpStream, cfg: &Arc<ClientConfig>) -> Result<(), SocksError> {
    sock.set_nodelay(true).ok();

    // ----- SOCKS5 greeting -----
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(SocksError::Socks("not SOCKS5"));
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xff]).await?;
        return Err(SocksError::Socks("no acceptable auth method"));
    }
    sock.write_all(&[0x05, 0x00]).await?;

    // ----- SOCKS5 request -----
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        // CMD must be CONNECT (0x01).
        sock.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(SocksError::Socks("unsupported SOCKS5 cmd"));
    }
    let (host, port) = match req[3] {
        0x01 => {
            // IPv4
            let mut buf = [0u8; 6];
            sock.read_exact(&mut buf).await?;
            (
                format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]),
                u16::from_be_bytes([buf[4], buf[5]]),
            )
        }
        0x03 => {
            // domain name
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            let mut port_b = [0u8; 2];
            sock.read_exact(&mut port_b).await?;
            (
                std::str::from_utf8(&name)
                    .map_err(|_| SocksError::Socks("invalid hostname"))?
                    .to_string(),
                u16::from_be_bytes(port_b),
            )
        }
        0x04 => {
            // IPv6
            let mut buf = [0u8; 18];
            sock.read_exact(&mut buf).await?;
            let segs: Vec<String> = buf[..16]
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            (segs.join(":"), u16::from_be_bytes([buf[16], buf[17]]))
        }
        _ => {
            sock.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(SocksError::Socks("unsupported ATYP"));
        }
    };

    // ----- Open Proteus session (TLS or plain TCP per cfg) -----
    let hs_cfg = cfg.build_handshake_config()?;
    let target_bytes = {
        let mut v = Vec::with_capacity(1 + host.len() + 2);
        v.push(host.len() as u8);
        v.extend_from_slice(host.as_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v
    };

    if let Some(tls_cfg) = cfg.tls.as_ref() {
        let connector = match tls_cfg.trusted_ca.as_ref() {
            Some(ca) => proteus_transport_alpha::tls::build_connector_with_ca(ca)
                .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?,
            None => proteus_transport_alpha::tls::build_connector_webpki_roots()
                .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?,
        };
        let tcp = tokio::net::TcpStream::connect(&cfg.server_endpoint).await?;
        let session =
            p_client::handshake_over_tls(tcp, &connector, &tls_cfg.server_name, &hs_cfg).await?;
        let proteus_transport_alpha::session::AlphaSession {
            mut sender,
            mut receiver,
            ..
        } = session;
        sender.send_record(&target_bytes).await?;
        sender.flush().await?;
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        pump(&mut sock, &mut sender, &mut receiver).await;
        return Ok(());
    }

    let session = p_client::connect(&cfg.server_endpoint, &hs_cfg).await?;
    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = session;
    sender.send_record(&target_bytes).await?;
    sender.flush().await?;
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    pump(&mut sock, &mut sender, &mut receiver).await;
    Ok(())
}

/// Bidirectional pump between SOCKS5 inbound and Proteus session.
async fn pump<R, W>(
    sock: &mut TcpStream,
    sender: &mut proteus_transport_alpha::session::AlphaSender<W>,
    receiver: &mut proteus_transport_alpha::session::AlphaReceiver<R>,
) where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let (mut sock_r, mut sock_w) = tokio::io::split(sock);
    let client_to_server = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match sock_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sender.send_record(&buf[..n]).await.is_err() {
                        break;
                    }
                    if sender.flush().await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    let server_to_client = async {
        loop {
            match receiver.recv_record().await {
                Ok(Some(buf)) if !buf.is_empty() => {
                    if sock_w.write_all(&buf).await.is_err() {
                        break;
                    }
                }
                Ok(Some(_)) => {} // keepalive
                Ok(None) | Err(_) => break,
            }
        }
        let _ = sock_w.shutdown().await;
    };
    tokio::join!(client_to_server, server_to_client);
}
