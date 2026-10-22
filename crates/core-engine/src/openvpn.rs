//! OpenVPN: render the sanitized profile to a config file for the `openvpn` binary.
//! The importer already rejected script/file directives; the renderer additionally forces safe options.

use crate::EngineError;
use core_model::Profile;

/// Optional credentials for `auth-user-pass`, written to a separate private file by the runner.
pub fn render(p: &Profile) -> Result<String, EngineError> {
    let directives = p
        .settings
        .get("directives")
        .ok_or(EngineError::Profile("directives"))?;
    let mut out = String::new();
    for l in directives.lines() {
        out.push_str(l);
        out.push('\n');
    }
    // Forced, in case the profile did not set them: never run scripts, never keep secrets in memory dumps.
    out.push_str("script-security 0\nauth-nocache\nverb 3\n");
    for tag in ["ca", "cert", "dh", "extra-certs", "crl-verify"] {
        if let Some(body) = p.settings.get(&format!("{tag}_inline")) {
            out.push_str(&format!("<{tag}>\n{body}</{tag}>\n"));
        }
    }
    for tag in ["key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12"] {
        if let Some(body) = p.secrets.get(tag) {
            out.push_str(&format!("<{tag}>\n{}</{tag}>\n", body.expose()));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_import::detect;

    #[test]
    fn rendered_config_keeps_inline_blocks_and_forces_safety() {
        let p = detect(
            "client\ndev tun\nremote vpn.example.com 1194\n<ca>\nCA\n</ca>\n<key>\nKEY\n</key>\n",
        )
        .unwrap();
        let t = render(&p).unwrap();
        assert!(
            t.contains("script-security 0")
                && t.contains("<ca>\nCA\n</ca>")
                && t.contains("<key>\nKEY\n</key>")
        );
        // Re-importing the rendered text must still pass the allowlist (round trip).
        assert!(detect(&t).is_ok(), "{:?}\n{t}", detect(&t));
    }
}
