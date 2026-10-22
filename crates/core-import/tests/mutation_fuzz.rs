//! Stable-toolchain fuzzing: mutate valid inputs thousands of ways and require that `analyze`
//! never panics, never hangs, and never echoes a credential into an issue label.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_import::{analyze, analyze_bytes};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const K: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn seeds() -> Vec<String> {
    vec![
        format!("vless://{UUID}@h.example.com:443?type=ws&security=tls&sni=h.example.com&path=%2Fws#a"),
        "trojan://s3cr3t-pass@h.example.com:443?sni=h.example.com#t".into(),
        "ss://YWVzLTI1Ni1nY206cHc@h.example.com:8388#s".into(),
        "hysteria2://auth-secret@h.example.com:443?obfs=salamander&obfs-password=xyz#h".into(),
        format!("tuic://{UUID}:pw1234@h.example.com:443?congestion_control=bbr#t"),
        format!("[Interface]\nPrivateKey = {K}\nAddress = 10.0.0.2/32\nJc = 5\n[Peer]\nPublicKey = {K}\nEndpoint = h.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"),
        "client\ndev tun\nremote h.example.com 1194\n<ca>\nCA\n</ca>\n<key>\nSECRETKEYDATA\n</key>\n".into(),
        format!("{{\"outbounds\":[{{\"type\":\"vless\",\"server\":\"h\",\"server_port\":443,\"uuid\":\"{UUID}\"}}]}}"),
        format!("proxies:\n  - {{name: a, type: ss, server: s, port: 1, cipher: aes-256-gcm, password: pw1234}}\n  - {{name: b, type: vless, server: v, port: 443, uuid: {UUID}}}\n"),
        "vpn://AAAAAAAAeJyrVkrLz1eyUkpKLFKyUkpMKS0pyU9LTy3Kz1WyUkrNT1ayUsooTS3KS8xNVaoFAHHVDqY".into(),
    ]
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(r: &mut Rng, s: &str) -> Vec<u8> {
    let mut b = s.as_bytes().to_vec();
    for _ in 0..1 + r.below(6) {
        if b.is_empty() {
            b.push(b'a');
        }
        let i = r.below(b.len());
        match r.below(7) {
            0 => b[i] = r.next() as u8,
            1 => {
                b.remove(i);
            }
            2 => {
                const SPECIAL: &[u8] = b"@:/?#&=%\n[]{}\"'<>\\ \0";
                b.insert(i, SPECIAL[r.below(SPECIAL.len())]);
            }
            3 => b.truncate(i),
            4 => {
                let end = (i + r.below(20)).min(b.len());
                let chunk = b[i..end].to_vec();
                b.splice(i..i, chunk);
            }
            5 => b
                .splice(i..i, b"9999999999999999999999".iter().copied())
                .for_each(drop),
            _ => b.extend_from_slice(&b.clone()[..r.below(b.len() + 1)]),
        }
    }
    b
}

#[test]
fn analyze_never_panics_on_mutated_input() {
    let mut r = Rng(std::env::var("WT_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x9E3779B97F4A7C15));
    let seeds = seeds();
    let start = std::time::Instant::now();
    let iters: usize = std::env::var("WT_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30_000);
    for n in 0..iters {
        let seed = &seeds[n % seeds.len()];
        let bytes = mutate(&mut r, seed);
        let a = analyze_bytes(&bytes);
        let text = String::from_utf8_lossy(&bytes);
        let _ = analyze(&text);
        for i in &a.issues {
            // Labels are shown to users and may be logged: no credentials in them.
            for secret in [
                "s3cr3t-pass",
                "auth-secret",
                "pw1234",
                UUID,
                "SECRETKEYDATA",
            ] {
                assert!(
                    !i.issue.user_message().contains(secret) && !i.label.contains(secret),
                    "{secret} leaked in {:?}",
                    i
                );
            }
        }
        assert!(
            start.elapsed().as_secs() < 120,
            "fuzz loop too slow, possible hang on {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

#[test]
fn pathological_inputs_finish_quickly() {
    let cases: Vec<String> = vec![
        "[".repeat(100_000),
        "{\"a\":".repeat(10_000),
        format!("vless://{}@h:1", "a".repeat(200_000)),
        "proxies:\n".to_string() + &"  - {a: [".repeat(5_000),
        "remote ".repeat(50_000),
        "<ca>\n".repeat(50_000),
        "\n".repeat(300_000),
        "ss://".to_string() + &"A".repeat(250_000),
    ];
    for c in cases {
        let t = std::time::Instant::now();
        let _ = analyze(&c);
        assert!(
            t.elapsed().as_secs() < 5,
            "slow on pathological input of {} bytes",
            c.len()
        );
    }
}
