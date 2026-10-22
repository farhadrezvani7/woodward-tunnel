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
        format!("tuic://{UUID}:pw1234@example.com:443?congestion_control=bbr&udp_relay_mode=native&sni=example.com#tu"),
        "hysteria://example.com:443?auth=secret1&peer=example.com&upmbps=50&downmbps=100#h1".into(),
        "anytls://pw1234@example.com:443?sni=example.com#at".into(),
        "socks5://u:p@example.com:1080#so".into(),
        "http-proxy://u:p@example.com:8080#ht".into(),
        "ssh://root:pw@example.com:22#ssh".into(),
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

#[test]
fn imported_json_and_clash_configs_pass_sing_box_check() {
    if Command::new("sing-box").arg("version").output().is_err() {
        return;
    }
    let sb = format!(
        r#"{{"outbounds":[{{"type":"vless","tag":"a","server":"h.example.com","server_port":443,"uuid":"{UUID}","tls":{{"enabled":true,"server_name":"h.example.com"}}}},{{"type":"hysteria2","tag":"b","server":"h.example.com","server_port":443,"password":"pw1234","tls":{{"enabled":true,"server_name":"h.example.com"}}}}]}}"#
    );
    let xr = format!(
        r#"{{"outbounds":[{{"protocol":"vmess","settings":{{"vnext":[{{"address":"v.example.com","port":443,"users":[{{"id":"{UUID}","security":"auto"}}]}}]}},"streamSettings":{{"network":"ws","security":"tls","wsSettings":{{"path":"/p"}}}}}}]}}"#
    );
    let cl = format!("proxies:\n  - {{name: a, type: tuic, server: t.example.com, port: 443, uuid: {UUID}, password: pw1234, sni: t.example.com}}\n  - {{name: w, type: wireguard, server: w.example.com, port: 51820, ip: 10.0.0.2, private-key: {K}, public-key: {K}}}\n");
    let dir = std::env::temp_dir().join(format!("wt-check2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut n = 0;
    for src in [sb, xr, cl] {
        let a = core_import::analyze(&src);
        assert!(!a.profiles.is_empty(), "{:?}", a.issues);
        for p in &a.profiles {
            let built = singbox::build(p, &Mode::Proxy { socks_port: 10808 }, &[]).unwrap();
            let path = dir.join(format!("i{n}.json"));
            n += 1;
            std::fs::write(&path, serde_json::to_vec(&built.config).unwrap()).unwrap();
            let out = Command::new("sing-box")
                .args(["check", "-c"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{:?}: {}",
                p.protocol,
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
