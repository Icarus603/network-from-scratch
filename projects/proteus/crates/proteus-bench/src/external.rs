//! Protocol-neutral TCP echo and SOCKS5 round-trip workload.
//!
//! External proxy implementations such as TUIC expose a local SOCKS5
//! listener instead of a bespoke speed-test command.  This module keeps
//! their benchmark contract identical to Proteus β: send `payload_bytes`
//! through the proxy, receive the same bytes from an echo server, verify
//! every byte, and divide one-direction payload by total round-trip time.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[derive(Debug, Clone, Copy)]
pub struct SocksRoundtripReport {
    pub payload_bytes: usize,
    pub chunk_bytes: usize,
    pub elapsed_secs: f64,
    pub mib_per_sec: f64,
    pub socks_addr: SocketAddr,
    pub target_addr: SocketAddr,
}

impl SocksRoundtripReport {
    #[must_use]
    pub fn to_json(self) -> String {
        format!(
            "{{\"profile\":\"socks5-tcp\",\"payload_bytes\":{},\
             \"chunk_bytes\":{},\"elapsed_secs\":{:.6},\
             \"mib_per_sec\":{:.6},\"socks_addr\":\"{}\",\
             \"target_addr\":\"{}\"}}\n",
            self.payload_bytes,
            self.chunk_bytes,
            self.elapsed_secs,
            self.mib_per_sec,
            self.socks_addr,
            self.target_addr,
        )
    }
}

/// Run a forever TCP echo server. Each accepted connection is isolated
/// in its own task, so a failed competitor attempt cannot poison later
/// observations.
pub async fn serve_tcp_echo(listener: TcpListener) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let (mut reader, mut writer) = stream.into_split();
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
        });
    }
}

async fn socks5_connect(socks_addr: SocketAddr, target_addr: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        return Err(io::Error::other(format!(
            "SOCKS5 server rejected no-auth method: {method:02x?}"
        )));
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match target_addr.ip() {
        IpAddr::V4(address) => {
            request.push(0x01);
            request.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            request.push(0x04);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 CONNECT failed with reply 0x{:02x}",
            response[1]
        )));
    }
    let address_len = match response[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0])
        }
        atyp => {
            return Err(io::Error::other(format!(
                "SOCKS5 CONNECT returned invalid ATYP 0x{atyp:02x}"
            )));
        }
    };
    let mut bound_address_and_port = vec![0_u8; address_len + 2];
    stream.read_exact(&mut bound_address_and_port).await?;
    Ok(stream)
}

fn fill_pattern(buffer: &mut [u8], absolute_offset: usize) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = ((absolute_offset + index) % 251) as u8;
    }
}

/// Measure a byte-verified TCP echo through a SOCKS5 proxy.
pub async fn run_socks5_roundtrip(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload_bytes: usize,
    chunk_bytes: usize,
    timeout: Duration,
) -> io::Result<SocksRoundtripReport> {
    if payload_bytes == 0 || chunk_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload_bytes and chunk_bytes must be non-zero",
        ));
    }

    let stream = tokio::time::timeout(timeout, socks5_connect(socks_addr, target_addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 CONNECT timed out"))??;
    let (mut reader, mut writer) = stream.into_split();
    let started = Instant::now();

    let transfer = async {
        let send = async {
            let mut buffer = vec![0_u8; chunk_bytes];
            let mut offset = 0;
            while offset < payload_bytes {
                let length = chunk_bytes.min(payload_bytes - offset);
                fill_pattern(&mut buffer[..length], offset);
                writer.write_all(&buffer[..length]).await?;
                offset += length;
            }
            writer.flush().await
        };
        let receive = async {
            let mut actual = vec![0_u8; chunk_bytes];
            let mut expected = vec![0_u8; chunk_bytes];
            let mut offset = 0;
            while offset < payload_bytes {
                let length = chunk_bytes.min(payload_bytes - offset);
                reader.read_exact(&mut actual[..length]).await?;
                fill_pattern(&mut expected[..length], offset);
                if actual[..length] != expected[..length] {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("echo mismatch at absolute offset {offset}"),
                    ));
                }
                offset += length;
            }
            Ok(())
        };
        tokio::try_join!(send, receive)?;
        Ok::<(), io::Error>(())
    };

    tokio::time::timeout(timeout, transfer)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "round-trip transfer timed out"))??;

    let elapsed_secs = started.elapsed().as_secs_f64();
    Ok(SocksRoundtripReport {
        payload_bytes,
        chunk_bytes,
        elapsed_secs,
        mib_per_sec: payload_bytes as f64 / elapsed_secs / (1024.0 * 1024.0),
        socks_addr,
        target_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pattern_depends_on_absolute_offset() {
        let mut whole = vec![0; 1024];
        fill_pattern(&mut whole, 0);
        let mut tail = vec![0; 513];
        fill_pattern(&mut tail, 511);
        assert_eq!(&whole[511..], tail.as_slice());
    }

    #[tokio::test]
    async fn socks5_roundtrip_verifies_echoed_payload() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(serve_tcp_echo(echo_listener));

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let socks_task = tokio::spawn(async move {
            let (mut inbound, _) = socks_listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            inbound.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            inbound.write_all(&[0x05, 0x00]).await.unwrap();

            let mut request = [0_u8; 10];
            inbound.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[0x05, 0x01, 0x00, 0x01]);
            let requested = SocketAddr::from((
                [request[4], request[5], request[6], request[7]],
                u16::from_be_bytes([request[8], request[9]]),
            ));
            assert_eq!(requested, echo_addr);
            let mut outbound = TcpStream::connect(requested).await.unwrap();
            inbound
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                .await
                .unwrap();
        });

        let report = run_socks5_roundtrip(
            socks_addr,
            echo_addr,
            1024 * 1024,
            64 * 1024,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(report.payload_bytes, 1024 * 1024);
        assert!(report.mib_per_sec > 0.0);

        socks_task.abort();
        echo_task.abort();
    }
}
