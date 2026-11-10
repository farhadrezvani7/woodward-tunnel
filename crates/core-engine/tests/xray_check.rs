//! Every Xray config the generator can produce must pass `xray run -test` (skipped if xray is absent).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_engine::{xray, Upstream};
use core_import::detect;
use std::path::{Path, PathBuf};
use std::process::Command;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PBK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn xray_bin() -> Option<PathBuf> {
    [
        std::env::var("WT_XRAY").ok().map(PathBuf::from),
        Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../engines/bin/xray")),
        Some(PathBuf::from("xray")),
    ]
    .into_iter()
    .flatten()
    .find(|p| Command::new(p).arg("version").output().is_ok())
}

fn mldsa_verify(x: &Path) -> String {
    let out = Command::new(x).arg("mldsa65").output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("Verify: "))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn generated_configs_pass_xray_test() {
    let Some(x) = xray_bin() else {
        eprintln!("xray not installed; skipping");
        return;
    };
    let hash = "ab".repeat(32);
    let pqv = mldsa_verify(&x);
    let enc = "mlkem768x25519plus.native.0rtt.nXp0evemrIo_vz7xwbbnSPyFtnqOcTgEnx9Sa13saFU";
    let links = vec![
        format!("vless://{UUID}@example.com:443?type=xhttp&security=tls&path=%2Fx&host=cdn.example.com&mode=stream-up&alpn=h2&fp=chrome"),
        format!("vless://{UUID}@example.com:443?type=xhttp&security=tls&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%2C%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%7D%7D"),
        format!("vless://{UUID}@example.com:80?type=splithttp&path=/&security=tls"),
        format!("vless://{UUID}@example.com:443?type=kcp&seed=abc&headerType=wechat-video&security=tls"),
        format!("vless://{UUID}@example.com:443?type=kcp&headerType=dns&host=front.example&security=tls"),
        format!("vless://{UUID}@example.com:443?type=kcp&security=tls"),
        format!("vless://{UUID}@example.com:443?encryption={enc}"),
        format!("vless://{UUID}@example.com:443?security=tls&pcs={hash}&vcn=a.example,b.example"),
        format!("vless://{UUID}@example.com:443?security=reality&sni=front.example&pbk={PBK}&sid=0a1b&fp=random&pqv={pqv}"),
        format!("vless://{UUID}@example.com:443?type=xhttp&security=reality&sni=front.example&pbk={PBK}&sid=0a1b"),
        format!("vless://{UUID}@example.com:443?type=ws&security=tls&path=%2Fw&pcs={hash}"),
        format!("vless://{UUID}@example.com:443?type=grpc&security=tls&serviceName=svc&vcn=example.com"),
        format!("vless://{UUID}@example.com:443?type=httpupgrade&security=tls&path=%2Fu&vcn=example.com"),
        format!("vless://{UUID}@example.com:443?type=xhttp&security=tls&fm=%7B%22udp%22%3A%5B%7B%22type%22%3A%22salamander%22%2C%22settings%22%3A%7B%22password%22%3A%22pw%22%7D%7D%5D%7D"),
        format!("trojan://pw1234@example.com:443?type=xhttp&sni=example.com&pcs={hash}"),
    ];
    let dir = std::env::temp_dir().join(format!("wt-xray-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let up = Upstream {
        addr: "127.0.0.1:10808".parse().unwrap(),
        username: "u".into(),
        password: "p".into(),
    };
    let mut all = links;
    // Unencrypted VLESS is accepted by Xray only towards private addresses.
    let private: Vec<String> = vec![
        format!("vless://{UUID}@example.com:80?headerType=http&path=%2Fa&host=x.example"),
        format!("vless://{UUID}@example.com:80?type=xhttp&path=%2Fx"),
        format!("vless://{UUID}@example.com:80?type=kcp&seed=abc"),
    ];
    // v2rayN style VMess JSON with mKCP and with an HTTP header.
    for j in [
        format!(
            r#"{{"add":"example.com","port":"443","id":"{UUID}","aid":"0","net":"kcp","type":"srtp","path":"sd"}}"#
        ),
        format!(
            r#"{{"add":"example.com","port":"80","id":"{UUID}","aid":"0","net":"tcp","type":"http","host":"x.example","path":"/a"}}"#
        ),
    ] {
        use base64::{engine::general_purpose::STANDARD, Engine};
        all.push(format!("vmess://{}", STANDARD.encode(j)));
    }
    let n = all.len();
    all.extend(private);
    for (i, l) in all.iter().enumerate() {
        let p = detect(l).unwrap_or_else(|e| panic!("{l}: {e:?}"));
        let ip = if i >= n { "10.1.2.3" } else { "203.0.113.7" };
        let built =
            xray::build(&p, ip.parse().unwrap(), &up).unwrap_or_else(|e| panic!("{l}: {e}"));
        let path = dir.join(format!("c{i}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&built.config).unwrap()).unwrap();
        let out = Command::new(&x)
            .args(["run", "-test", "-c"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}: {}{}",
            l.chars().take(70).collect::<String>(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}
