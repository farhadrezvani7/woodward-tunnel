#!/usr/bin/env python3
"""Live test of every supported protocol on a real Android phone connected by USB.

Starts one local sing-box server with an inbound per protocol, forwards its ports to the phone with
`adb reverse` (UDP protocols go through relay.go, since adb reverse carries TCP only), imports one
share link per protocol into the installed app, connects each in turn and reports what the app shows
plus a real HTTPS request made from the phone's shell through the tunnel.

usage: run.py <workdir> <relay-host-bin> <relay-arm64-bin> [case ...]
Only touches its own processes and ports (21001+, 22001+), and removes them at the end.
"""
import base64, json, os, re, subprocess, sys, time, urllib.parse
from pathlib import Path

work, relay_host, relay_phone = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
only = set(sys.argv[4:])
ADB = os.path.expanduser("~/Android/Sdk/platform-tools/adb")
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
sb = lambda *a: subprocess.run(["sing-box", *a], capture_output=True, text=True).stdout
adb = lambda *a, t=60: subprocess.run([ADB, *a], capture_output=True, text=True, timeout=t).stdout

# ---- keys and certificate -------------------------------------------------------------
t = sb("generate", "tls-keypair", "example.com")
key = "-----BEGIN PRIVATE KEY-----" + t.split("-----BEGIN PRIVATE KEY-----")[1].split("-----END PRIVATE KEY-----")[0] + "-----END PRIVATE KEY-----\n"
crt = "-----BEGIN CERTIFICATE-----" + t.split("-----BEGIN CERTIFICATE-----")[1].split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
work.mkdir(parents=True, exist_ok=True)
(work / "k.pem").write_text(key); (work / "c.pem").write_text(crt)
def kp(cmd):
    d = dict(l.split(": ") for l in sb("generate", cmd).strip().splitlines()); return d["PrivateKey"], d["PublicKey"]
rl_priv, rl_pub = kp("reality-keypair"); wg_s_priv, wg_s_pub = kp("wg-keypair"); wg_c_priv, wg_c_pub = kp("wg-keypair")
tls = lambda alpn=None: {"enabled": True, "server_name": "example.com", "key_path": str(work / "k.pem"), "certificate_path": str(work / "c.pem"), **({"alpn": [alpn]} if alpn else {})}
q = lambda s: urllib.parse.quote(s, safe="")
vmess_json = lambda p: base64.b64encode(json.dumps({"v": "2", "ps": "T-vmess", "add": "127.0.0.1", "port": str(p), "id": UUID, "aid": "0", "net": "tcp"}).encode()).decode()

# name -> (needs_udp_relay, also_tcp, inbound-or-endpoint builder, link builder)
CASES = {
 "ss":        (False, True,  lambda p: {"type":"shadowsocks","listen":"127.0.0.1","listen_port":p,"method":"aes-256-gcm","password":"pw-e2e-1234"}, lambda p: f"ss://aes-256-gcm:pw-e2e-1234@127.0.0.1:{p}#T-ss"),
 "ss-udp":    (True,  True,  lambda p: {"type":"shadowsocks","listen":"127.0.0.1","listen_port":p,"method":"aes-256-gcm","password":"pw-e2e-1234"}, lambda p: f"ss://aes-256-gcm:pw-e2e-1234@127.0.0.1:{p}#T-ss-udp"),
 "vless":     (False, True,  lambda p: {"type":"vless","listen":"127.0.0.1","listen_port":p,"users":[{"uuid":UUID}]}, lambda p: f"vless://{UUID}@127.0.0.1:{p}?type=tcp&security=none#T-vless"),
 "vless-ws":  (False, True,  lambda p: {"type":"vless","listen":"127.0.0.1","listen_port":p,"users":[{"uuid":UUID}],"tls":tls(),"transport":{"type":"ws","path":"/ws"}}, lambda p: f"vless://{UUID}@127.0.0.1:{p}?type=ws&security=tls&sni=example.com&path=%2Fws&insecure=1#T-vless-ws"),
 "reality":   (False, True,  lambda p: {"type":"vless","listen":"127.0.0.1","listen_port":p,"users":[{"uuid":UUID,"flow":"xtls-rprx-vision"}],"tls":{"enabled":True,"server_name":"www.cloudflare.com","reality":{"enabled":True,"handshake":{"server":"104.16.133.229","server_port":443},"private_key":rl_priv,"short_id":["0123abcd"]}}}, lambda p: f"vless://{UUID}@127.0.0.1:{p}?type=tcp&security=reality&sni=www.cloudflare.com&fp=chrome&pbk={rl_pub}&sid=0123abcd&flow=xtls-rprx-vision#T-reality"),
 "vmess":     (False, True,  lambda p: {"type":"vmess","listen":"127.0.0.1","listen_port":p,"users":[{"uuid":UUID,"alterId":0}]}, lambda p: "vmess://" + vmess_json(p)),
 "trojan":    (False, True,  lambda p: {"type":"trojan","listen":"127.0.0.1","listen_port":p,"users":[{"password":"pw-trojan-1234"}],"tls":tls()}, lambda p: f"trojan://pw-trojan-1234@127.0.0.1:{p}?sni=example.com&insecure=1#T-trojan"),
 "anytls":    (False, True,  lambda p: {"type":"anytls","listen":"127.0.0.1","listen_port":p,"users":[{"password":"pw-any-1234"}],"tls":tls()}, lambda p: f"anytls://pw-any-1234@127.0.0.1:{p}?sni=example.com&insecure=1#T-anytls"),
 "socks":     (False, True,  lambda p: {"type":"socks","listen":"127.0.0.1","listen_port":p,"users":[{"username":"u1","password":"pw-socks-1234"}]}, lambda p: f"socks5://u1:pw-socks-1234@127.0.0.1:{p}#T-socks"),
 "http":      (False, True,  lambda p: {"type":"http","listen":"127.0.0.1","listen_port":p,"users":[{"username":"u1","password":"pw-http-1234"}]}, lambda p: f"http-proxy://u1:pw-http-1234@127.0.0.1:{p}#T-http"),
 "hysteria2": (True,  False, lambda p: {"type":"hysteria2","listen":"127.0.0.1","listen_port":p,"users":[{"password":"pw-hy2-1234"}],"tls":tls()}, lambda p: f"hysteria2://pw-hy2-1234@127.0.0.1:{p}?sni=example.com&insecure=1#T-hysteria2"),
 "tuic":      (True,  False, lambda p: {"type":"tuic","listen":"127.0.0.1","listen_port":p,"users":[{"uuid":UUID,"password":"pw-tuic-1234"}],"congestion_control":"bbr","tls":tls("h3")}, lambda p: f"tuic://{UUID}:pw-tuic-1234@127.0.0.1:{p}?sni=example.com&insecure=1&alpn=h3&congestion_control=bbr#T-tuic"),
 "hysteria1": (True,  False, lambda p: {"type":"hysteria","listen":"127.0.0.1","listen_port":p,"up_mbps":100,"down_mbps":100,"users":[{"auth_str":"pw-h1-1234"}],"tls":tls()}, lambda p: f"hysteria://127.0.0.1:{p}?auth=pw-h1-1234&peer=example.com&insecure=1&upmbps=50&downmbps=100#T-hysteria1"),
 "wireguard": (True,  False, lambda p: {"type":"wireguard","tag":"wg","address":["10.9.0.1/24"],"private_key":wg_s_priv,"listen_port":p,"peers":[{"public_key":wg_c_pub,"allowed_ips":["10.9.0.2/32"]}]}, lambda p: f"wireguard://{q(wg_c_priv)}@127.0.0.1:{p}?publickey={q(wg_s_pub)}&address=10.9.0.2/32&mtu=1280#T-wireguard"),
}
names = [n for n in CASES if not only or n in only]
port = {n: 21001 + i for i, n in enumerate(CASES) if n in names}

# ---- server, relays, port forwards ----------------------------------------------------
inb, eps = [], []
for n in names:
    c = CASES[n][2](port[n]); (eps if c["type"] == "wireguard" else inb).append({**c, **({} if c["type"] == "wireguard" else {"tag": "in-" + n})})
cfg = {"log": {"level": "info"}, "inbounds": inb, "endpoints": eps, "outbounds": [{"type": "direct", "tag": "direct"}]}
(work / "server.json").write_text(json.dumps(cfg))
chk = subprocess.run(["sing-box", "check", "-c", str(work / "server.json")], capture_output=True, text=True)
if chk.returncode: sys.exit("server config invalid: " + chk.stderr[:400])
mine = [subprocess.Popen(["sing-box", "run", "-c", str(work / "server.json")], stdout=open(work / "server.log", "w"), stderr=subprocess.STDOUT)]
adb("shell", "pkill", "-x", "relay")
for n in names:
    p = port[n]; udp, tcp = CASES[n][0], CASES[n][1]
    if tcp: adb("reverse", f"tcp:{p}", f"tcp:{p}")
    if udp:
        mine.append(subprocess.Popen([relay_host, "host", str(p + 1000), str(p)]))
        adb("reverse", f"tcp:{p+1000}", f"tcp:{p+1000}")
        subprocess.Popen([ADB, "shell", f"setsid nohup /data/local/tmp/relay phone {p} {p+1000} >/dev/null 2>&1 &"])
time.sleep(2)

# ---- UI helpers -----------------------------------------------------------------------
def dump():
    for _ in range(3):
        adb("shell", "uiautomator", "dump", "/sdcard/ui.xml")
        x = adb("shell", "cat", "/sdcard/ui.xml")
        if "<node" in x: break
    out = []
    for m in re.finditer(r'<node[^>]*?text="([^"]*)"[^>]*?content-desc="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', x):
        s, d, x1, y1, x2, y2 = m.groups(); s = s or d
        if s: out.append((s.replace("⁨", "").replace("⁩", "").replace("‎", ""), (int(x1)+int(x2))//2, (int(y1)+int(y2))//2))
    return out
def tap(x, y): adb("shell", "input", "tap", str(x), str(y))
def find(sub, exact=False, nodes=None):
    for n in (nodes or dump()):
        if (n[0] == sub) if exact else (sub in n[0]): return n
def swipe(a, b): adb("shell", "input", "swipe", "540", str(a), "540", str(b), "300")

def home():
    adb("shell", "am", "start", "-n", "app.woodwardtunnel/.ui.MainActivity"); time.sleep(1.5)

def tail_state(nodes): return [n[0] for n in nodes]

# ---- import ---------------------------------------------------------------------------
adb("shell", "pm", "clear", "app.woodwardtunnel")  # fresh profiles: stale ones would carry old ports and keys
adb("shell", "pm", "grant", "app.woodwardtunnel", "android.permission.POST_NOTIFICATIONS"); home()
links = "\n".join(CASES[n][3](port[n]) for n in names)
adb("shell", f"am start -a android.intent.action.SEND -t text/plain -n app.woodwardtunnel/.ui.MainActivity --es android.intent.extra.TEXT '{links}'")
time.sleep(3)
b = find("افزودن", exact=True)
if not b: sys.exit("import dialog not shown: " + str(tail_state(dump())[:8]))
tap(b[1], b[2]); time.sleep(3)

# ---- per-profile connect test ---------------------------------------------------------
rows = []
for n in names:
    label = "T-" + n
    nodes = dump()
    for _ in range(4): swipe(700, 1700)
    row = find(label, exact=True)
    for _ in range(8):
        if row: break
        swipe(1700, 700); row = find(label, exact=True)
    if not row: rows.append((n, "NOT-IMPORTED", "", "")); continue
    tap(row[1], row[2]); time.sleep(0.8)
    for _ in range(4): swipe(700, 1700)
    btn = find("اتصال", exact=True)
    if not btn: rows.append((n, "NO-BUTTON", "", "")); continue
    tap(btn[1], btn[2]); state, texts = "TIMEOUT", []
    for _ in range(14):
        time.sleep(3); nodes = dump(); texts = tail_state(nodes)
        if any("متصل هستید" in t for t in texts): state = "CONNECTED"; break
        if any("برقرار نشد" in t for t in texts): state = "FAILED"; break
    curl = adb("shell", "timeout 10 curl -s -o /dev/null -w '%{http_code}' https://www.google.com/generate_204 2>&1; echo", t=30).strip()
    udp_ok = "ok" if state == "CONNECTED" and not any("UDP (" in t for t in texts) else ("no" if state == "CONNECTED" else "-")
    i = next((k for k, s in enumerate(texts) if "برقرار نشد" in s or "UDP (" in s), None)
    note = " | ".join(texts[i:i + 2])[:160] if i is not None else ""
    rows.append((n, state, f"udp:{udp_ok}", f"curl:{curl}", note))
    d = find("قطع اتصال", exact=True) or find("لغو", exact=True)
    if d: tap(d[1], d[2])
    time.sleep(3)

print(f"{'case':10} {'state':10} {'udp':8} {'curl':9} note")
for r in rows: print(f"{r[0]:10} {r[1]:10} {r[2] if len(r)>2 else '':8} {r[3] if len(r)>3 else '':9} {r[4] if len(r)>4 else ''}")

# ---- clean up only what this script started -------------------------------------------
for p in mine: p.terminate()
adb("shell", "pkill", "-x", "relay")
for n in names:
    for pp in (port[n], port[n] + 1000): adb("reverse", "--remove", f"tcp:{pp}")
