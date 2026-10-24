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

/// Encode a DNS query (RD set). `name` may be `.` (root, type NS) or a host name (type A).
pub fn dns_query(id: u16, name: &str) -> io::Result<Vec<u8>> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    let name = name.trim_end_matches('.');
    if name.len() > 253 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
    }
    for label in name.split('.').filter(|l| !l.is_empty()) {
        if label.len() > 63 || !label.is_ascii() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad label"));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    let qtype: u16 = if name.is_empty() { 2 } else { 1 };
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    Ok(q)
}

/// A response proves the path only if it answers our query and is not a server failure.
pub fn dns_response_ok(id: u16, resp: &[u8]) -> bool {
    if resp.len() < 12 || resp[0..2] != id.to_be_bytes() || resp[2] & 0x80 == 0 {
        return false;
    }
    matches!(resp[3] & 0x0f, 0 | 3)
}

fn probe_id() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    (std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
        & 0xffff) as u16
}

/// TUN mode, engine-verified probe: send one DNS query to `server`. The engine hijacks DNS, so
/// the answer comes from the resolver configured in the engine, reached through the VPN server.
/// The query leaves the machine only inside the tunnel; no third party sees the user's address.
pub async fn dns_udp(server: SocketAddr, name: &str, limit: Duration) -> io::Result<()> {
    let id = probe_id();
    let q = dns_query(id, name)?;
    timeout(limit, async {
        let bind: SocketAddr = if server.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let sock = tokio::net::UdpSocket::bind(bind).await?;
        sock.connect(server).await?;
        let mut buf = [0u8; 1500];
        // UDP may be lost during route setup: retry the query within the limit.
        loop {
            sock.send(&q).await?;
            if let Ok(Ok(n)) = timeout(Duration::from_millis(1500), sock.recv(&mut buf)).await {
                if dns_response_ok(id, &buf[..n]) {
                    return Ok(());
                }
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns probe timed out"))?
}

/// Proxy mode probe: DNS over TCP to `server` through the SOCKS proxy.
pub async fn dns_tcp_via_socks(
    proxy: SocketAddr,
    server: SocketAddr,
    name: &str,
    limit: Duration,
) -> io::Result<()> {
    let id = probe_id();
    let q = dns_query(id, name)?;
    let mut s = socks5_connect(proxy, &server.ip().to_string(), server.port(), limit).await?;
    timeout(limit, async {
        s.write_all(&(q.len() as u16).to_be_bytes()).await?;
        s.write_all(&q).await?;
        let mut l = [0u8; 2];
        s.read_exact(&mut l).await?;
        let n = u16::from_be_bytes(l) as usize;
        let mut buf = vec![0u8; n.min(4096)];
        s.read_exact(&mut buf).await?;
        if dns_response_ok(id, &buf) {
            Ok(())
        } else {
            Err(io::Error::other("bad dns answer"))
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns probe timed out"))?
}

/// TUN mode probe: a direct TCP connect goes through the system tunnel route.
pub async fn tcp_reachable(addr: SocketAddr, limit: Duration) -> io::Result<()> {
    timeout(limit, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "probe timed out"))??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_wire_format() {
        let q = dns_query(0x1234, "example.com").unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..25], b"\x07example\x03com\x00");
        assert_eq!(&q[25..], &[0, 1, 0, 1]);
        let root = dns_query(1, ".").unwrap();
        assert_eq!(&root[12..], &[0, 0, 2, 0, 1]);
        assert!(dns_query(1, &"a".repeat(64)).is_err());
    }

    #[test]
    fn response_must_match_id_and_not_be_servfail() {
        let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        assert!(dns_response_ok(0x1234, &r));
        assert!(!dns_response_ok(0x9999, &r));
        r[3] = 0x82; // SERVFAIL
        assert!(!dns_response_ok(0x1234, &r));
        r[3] = 0x83; // NXDOMAIN still proves the path
        assert!(dns_response_ok(0x1234, &r));
        assert!(!dns_response_ok(0x1234, &[1, 2]));
    }
}
