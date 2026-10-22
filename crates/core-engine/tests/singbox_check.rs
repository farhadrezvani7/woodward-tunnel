//! Every protocol's generated config must pass `sing-box check` (skipped if the binary is absent).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core_engine::{singbox, Mode};
use core_import::detect;
use std::process::Command;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const K: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn links() -> Vec<String> {
    vec![
        format!("vless://{UUID}@example.com:443?type=ws&security=tls&sni=example.com&path=%2Fws&host=example.com#a"),
        format!("vless://{UUID}@example.com:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01&sni=a.com&flow=xtls-rprx-vision&fp=chrome#b"),
        format!("vless://{UUID}@example.com:443?type=grpc&security=tls&serviceName=svc#g"),
        "trojan://pw1234@example.com:443?sni=example.com#t".into(),
        "hysteria2://auth@example.com:8443?sni=example.com&obfs=salamander&obfs-password=xx1234#h".into(),
        "ss://aes-256-gcm:pw1234@example.com:8388#s".into(),
        format!("[Interface]\nPrivateKey = {K}\nAddress = 10.0.0.2/32\nMTU = 1380\n[Peer]\nPublicKey = {K}\nPresharedKey = {K}\nEndpoint = example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"),
    ]
}

#[test]
fn all_generated_configs_pass_sing_box_check() {
    if Command::new("sing-box").arg("version").output().is_err() {
        eprintln!("sing-box not installed; skipping");
        return;
    }
    let dir = std::env::temp_dir().join(format!("wt-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut vmess_json = String::new();
    vmess_json.push_str(&format!(r#"{{"add":"example.com","port":"443","id":"{UUID}","aid":"0","net":"ws","tls":"tls","path":"/p"}}"#));
    let mut all = links();
    all.push(format!("vmess://{}", base64_std(vmess_json.as_bytes())));
    for (i, l) in all.iter().enumerate() {
        let profile = detect(l).unwrap();
        for mode in [Mode::Tun, Mode::Proxy { socks_port: 10808 }] {
            let built = singbox::build(&profile, &mode, &[]).unwrap();
            let path = dir.join(format!("c{i}.json"));
            std::fs::write(&path, serde_json::to_vec_pretty(&built.config).unwrap()).unwrap();
            let out = Command::new("sing-box")
                .args(["check", "-c"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{:?} {:?}: {}",
                profile.protocol,
                mode,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    std::fs::remove_dir_all(dir).ok();
}

fn base64_std(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        o.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    o
}
