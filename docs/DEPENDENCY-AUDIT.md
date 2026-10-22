# Dependency audit

`cargo audit` (advisory database as of 2026-10-23): **0 known vulnerabilities, 7 warnings**, all in
transitive dependencies. CI runs the same check and fails on vulnerabilities.

| Crate | Warning | Pulled in by | Assessment |
|---|---|---|---|
| lru 0.12.5 (2 advisories) | unsound (panic-safety, Stacked Borrows) | rqrr (QR decoding) | Used inside the image decoder on untrusted images; image size and pixel caps apply. Revisit when rqrr updates, or replace the decoder. |
| zbus_names, zvariant, zvariant_derive | unmaintained | keyring (Linux Secret Service) | Desktop Linux only. Track keyring releases. |
| unsafe-libyaml | unmaintained | serde_yaml_ng (Clash YAML import) | Input is size-capped (256 KiB). Consider a different YAML parser. |
| basic-toml | unmaintained | uniffi | Build-time only for bindings generation. |

Go helper (`engines/awg-socks`): depends on amneziawg-go and gVisor; run `govulncheck` in CI before releases (not yet wired).
