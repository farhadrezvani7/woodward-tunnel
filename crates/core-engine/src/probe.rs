//! Tunnel verification. `Connected` is only reported when a probe actually crosses the tunnel.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout, Instant};

/// Wait until something listens on `addr` (engine start-up), or fail after `limit`.
pub async fn wait_listening(addr: SocketAddr, limit: Duration) -> io::Result<()> {
    let end = Instant::now() + limit;
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if Instant::now() >= end {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "engine did not start listening",
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Open a TCP connection to `target` through a SOCKS5 proxy (no auth); returns the stream.
pub async fn socks5_connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    limit: Duration,
) -> io::Result<TcpStream> {
    timeout(limit, async {
        let mut s = TcpStream::connect(proxy).await?;
        s.write_all(&[5, 1, 0]).await?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await?;
        if r != [5, 0] {
            return Err(io::Error::other("socks auth refused"));
        }
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "host too long"));
        }
        let mut req = vec![5, 1, 0, 3, hb.len() as u8];
        req.extend_from_slice(hb);
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await?;
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await?;
        if head[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("socks error {}", head[1]),
            ));
        }
        let skip = match head[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            3 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await?;
                l[0] as usize + 2
            }
            _ => return Err(io::Error::other("bad socks reply")),
        };
        let mut sink = vec![0u8; skip];
        s.read_exact(&mut sink).await?;
        Ok(s)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks connect timed out"))?
}

/// Send a tiny HTTP request through the proxy and return the response body start.
/// Success means data really flowed through the tunnel.
pub async fn http_get_via_socks(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    limit: Duration,
) -> io::Result<String> {
    let mut s = socks5_connect(proxy, host, port, limit).await?;
    let req = format!("GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    timeout(limit, s.read_to_end(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))??;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// TUN mode probe: a direct TCP connect goes through the system tunnel route.
pub async fn tcp_reachable(addr: SocketAddr, limit: Duration) -> io::Result<()> {
    timeout(limit, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "probe timed out"))??;
    Ok(())
}
