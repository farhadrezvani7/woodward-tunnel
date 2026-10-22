# Threat model (current state)

Each row says what exists in the code today and where it is tested. Anything not listed here is
not claimed.

| Threat | Control in code | Test |
|---|---|---|
| Malicious imported config reads local files or runs code | OpenVPN: allowlist, dangerous directives rejected, script directives dropped, forced `script-security 0`. sing-box JSON: any `*_path` key rejected, dialer options stripped | `core-import` openvpn and formats tests |
| Credentials in logs or issue lists | `Secret` has no Debug/Display; `core-log` redacts known secrets, UUIDs, 32-byte keys, PEM, URL userinfo; issue labels carry scheme and host only | `core-log` tests, loopback e2e asserts UUID absent from logs, AWG e2e asserts private key absent |
| Secrets at rest | OS secure store; the database never receives them; a store failure aborts the import | `core-store` tests |
| Traffic leak when the tunnel drops (Linux) | nftables table with default-drop output, allowed only via the tunnel interface and to the server | `scripts/test-tun-docker.sh` (real TUN, tunnel killed, direct traffic blocked) |
| Leak rules injection | interface names validated against a strict character set | `core-policy` tests |
| Subscription fetch abuse | https only, 5 MB cap, private/loopback/link-local targets refused, no following links found inside a subscription | `core-app` fetch tests |
| Hostile archives/images | size and pixel caps on QR images, zlib output cap on Amnezia links | `core-import` tests |
| Insecure TLS option in a profile | honoured only if the profile asks for it, surfaced as `insecure_tls` for the UI to warn | engine tests |

Not done yet: macOS pf and Windows firewall rule application (generators exist, untested on those
OSes), DNS leak automation per OS, fuzzing, signed updates, third-party security audit.
