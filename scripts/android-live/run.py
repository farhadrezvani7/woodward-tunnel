#!/usr/bin/env python3
"""Live test of every supported protocol on a real Android phone connected by USB.

Starts one local sing-box server with an inbound per protocol, forwards its ports to the phone with
`adb reverse` (UDP protocols go through relay.go, since adb reverse carries TCP only), imports one
share link per protocol into the installed app, connects each in turn and reports what the app shows
plus a real HTTPS request made from the phone's shell through the tunnel.

usage: run.py <workdir> <relay-host-bin> <relay-arm64-bin> [case ...]
Cases: the sing-box protocols below, the Xray ones (xhttp, vlessenc, tcp-http, mkcp), ssh and ssh-pinned
(test SSH server, ssh-testserver/), and the special phases awg (AmneziaWG test server; the connection check
is switched off in the app and traffic is proven with curl to a private address that exists only inside
the tunnel). Environment: WT_XRAY, WT_AWG_TESTSERVER, WT_SSH_TESTSERVER (built here with Go when unset).
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
# ---- Xray cases (server: the Xray binary) -----------------------------------------------
ROOT = Path(__file__).resolve().parents[2]
XRAY = os.environ.get("WT_XRAY", str(ROOT / "engines/bin/xray"))
def vlessenc():
    t = subprocess.run([XRAY, "vlessenc"], capture_output=True, text=True).stdout
    pick = lambda k: [l.split('"')[3] for l in t.splitlines() if l.strip().startswith(f'"{k}"')][0]
    return pick("decryption"), pick("encryption")
def xin(p, stream, dec="none"):
    return {"listen": "127.0.0.1", "port": p, "protocol": "vless", "settings": {"clients": [{"id": UUID}], "decryption": dec}, "streamSettings": stream}
_dec, _enc = vlessenc() if os.path.exists(XRAY) else ("none", "none")
_http = {"type": "http", "request": {"version": "1.1", "method": "GET", "path": ["/a"], "headers": {"Host": ["front.example"]}}}
# name -> (needs_udp_relay, inbound builder, link builder)
XCASES = {
 "xhttp":    (False, lambda p: xin(p, {"network": "xhttp", "xhttpSettings": {"path": "/x"}}), lambda p: f"vless://{UUID}@127.0.0.1:{p}?type=xhttp&path=%2Fx#T-xhttp"),
 "vlessenc": (False, lambda p: xin(p, {"network": "tcp"}, _dec), lambda p: f"vless://{UUID}@127.0.0.1:{p}?type=tcp&encryption={_enc}#T-vlessenc"),
 "tcp-http": (False, lambda p: xin(p, {"network": "tcp", "rawSettings": {"header": _http}}), lambda p: f"vless://{UUID}@127.0.0.1:{p}?type=tcp&headerType=http&path=%2Fa&host=front.example#T-tcp-http"),
 "mkcp":     (True,  lambda p: xin(p, {"network": "kcp", "kcpSettings": {}, "finalmask": {"udp": [{"type": "mkcp-legacy", "settings": {"value": "pw-kcp-1234"}}]}}), lambda p: f"vless://{UUID}@127.0.0.1:{p}?type=kcp&seed=pw-kcp-1234#T-mkcp"),
}
SSH_USER, SSH_PASS = "u1", "pw-ssh-1234"
SSH_CASES = ["ssh", "ssh-pinned"]
AWG = "awg"
names = [n for n in CASES if not only or n in only]
xnames = [n for n in XCASES if not only or n in only]
snames = [n for n in SSH_CASES if not only or n in only]
do_awg = not only or AWG in only
port = {n: 21001 + i for i, n in enumerate(CASES) if n in names}
for i, n in enumerate(XCASES):
    if n in xnames: port[n] = 21101 + i
for i, n in enumerate(SSH_CASES):
    if n in snames: port[n] = 21201 + i
AWG_PORT = 21301

# ---- server, relays, port forwards ----------------------------------------------------
inb, eps = [], []
for n in names:
    c = CASES[n][2](port[n]); (eps if c["type"] == "wireguard" else inb).append({**c, **({} if c["type"] == "wireguard" else {"tag": "in-" + n})})
cfg = {"log": {"level": "info"}, "inbounds": inb, "endpoints": eps, "outbounds": [{"type": "direct", "tag": "direct"}]}
(work / "server.json").write_text(json.dumps(cfg))
chk = subprocess.run(["sing-box", "check", "-c", str(work / "server.json")], capture_output=True, text=True)
if chk.returncode: sys.exit("server config invalid: " + chk.stderr[:400])
mine = [subprocess.Popen(["sing-box", "run", "-c", str(work / "server.json")], stdout=open(work / "server.log", "w"), stderr=subprocess.STDOUT)]
if xnames:
    xcfg = {"log": {"loglevel": "warning"}, "inbounds": [XCASES[n][1](port[n]) for n in xnames], "outbounds": [{"protocol": "freedom"}]}
    (work / "xray-server.json").write_text(json.dumps(xcfg))
    chk = subprocess.run([XRAY, "run", "-test", "-c", str(work / "xray-server.json")], capture_output=True, text=True)
    if chk.returncode: sys.exit("xray server config invalid: " + (chk.stdout + chk.stderr)[-400:])
    mine.append(subprocess.Popen([XRAY, "run", "-c", str(work / "xray-server.json")], stdout=open(work / "xray-server.log", "w"), stderr=subprocess.STDOUT))
ssh_keys = {}
if snames:
    ssh_bin = os.environ.get("WT_SSH_TESTSERVER")
    if not ssh_bin:
        ssh_bin = str(work / "ssh-testserver")
        env = {**os.environ, "GOFLAGS": "-mod=mod", "GOPROXY": "off", "GOTOOLCHAIN": "go1.26.10"}
        b = subprocess.run(["go", "build", "-o", ssh_bin, "."], cwd=Path(__file__).parent / "ssh-testserver", env=env, capture_output=True, text=True)
        if b.returncode: sys.exit("cannot build ssh-testserver: " + b.stderr[-300:])
    for n in snames:
        pr = subprocess.Popen([ssh_bin, str(port[n]), SSH_USER, SSH_PASS], stdout=subprocess.PIPE, text=True)
        mine.append(pr); ssh_keys[n] = json.loads(pr.stdout.readline())["host_key"]
adb("shell", "pkill", "-x", "relay")
for n in xnames:
    p = port[n]
    if XCASES[n][0]:
        mine.append(subprocess.Popen([relay_host, "host", str(p + 1000), str(p)]))
        adb("reverse", f"tcp:{p+1000}", f"tcp:{p+1000}")
        subprocess.Popen([ADB, "shell", f"setsid nohup /data/local/tmp/relay phone {p} {p+1000} >/dev/null 2>&1 &"])
    else:
        adb("reverse", f"tcp:{p}", f"tcp:{p}")
for n in snames: adb("reverse", f"tcp:{port[n]}", f"tcp:{port[n]}")
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
def fresh_app(text):
    adb("shell", "pm", "clear", "app.woodwardtunnel")  # fresh profiles: stale ones would carry old ports and keys
    adb("shell", "pm", "grant", "app.woodwardtunnel", "android.permission.POST_NOTIFICATIONS"); home()
    adb("shell", f"am start -a android.intent.action.SEND -t text/plain -n app.woodwardtunnel/.ui.MainActivity --es android.intent.extra.TEXT '{text}'")
    time.sleep(3)
    b = find("افزودن", exact=True)
    if not b: sys.exit("import dialog not shown: " + str(tail_state(dump())[:8]))
    tap(b[1], b[2]); time.sleep(3)

def verify_off():
    """Settings > "check internet after connecting" off (for a config that only routes a private network)."""
    s = find("تنظیمات"); tap(s[1], s[2]); time.sleep(1.5)
    for _ in range(8):
        t = find("بررسی اینترنت پس از اتصال")
        if t: break
        swipe(1500, 600); time.sleep(0.5)
    if not t: sys.exit("verify setting not found")
    # The switch is its own checkable node next to the title text.
    adb("shell", "uiautomator", "dump", "/sdcard/ui.xml")
    xml = adb("shell", "cat", "/sdcard/ui.xml")
    sw = [(int(a_), int(b_), int(c_), int(d_), chk) for chk, a_, b_, c_, d_ in re.findall(r'checkable="true" checked="(\w+)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml)]
    sw = sorted(sw, key=lambda w: abs((w[1] + w[3]) // 2 - t[2]))
    if not sw: sys.exit("verify switch not found")
    if sw[0][4] == "true": tap((sw[0][0] + sw[0][2]) // 2, (sw[0][1] + sw[0][3]) // 2)
    time.sleep(1)
    adb("shell", "input", "keyevent", "4"); time.sleep(1)

def diag_tail(n=14):
    """The app's own diagnostic report (redacted engine log tail), for a failed case."""
    s = find("تنظیمات")
    if not s: return []
    tap(s[1], s[2]); time.sleep(1.5)
    for _ in range(10):
        b = find("ساخت گزارش", exact=True)
        if b: break
        swipe(1500, 600); time.sleep(0.4)
    if not b: adb("shell", "input", "keyevent", "4"); return []
    tap(b[1], b[2]); time.sleep(2)
    lines = [t for t, _, _ in dump()]
    adb("shell", "input", "keyevent", "4"); time.sleep(0.5); adb("shell", "input", "keyevent", "4"); time.sleep(1)
    return lines[-n:]

def scroll_top():
    for _ in range(4): swipe(700, 1700)

def open_row(label):
    scroll_top()
    row = find(label, exact=True)
    for _ in range(8):
        if row: break
        swipe(1700, 700); row = find(label, exact=True)
    return row

def press_connect():
    tap_row_done = False
    for _ in range(4): swipe(700, 1700)
    btn = find("اتصال", exact=True)
    if not btn: return None
    tap(btn[1], btn[2]); state, texts = "TIMEOUT", []
    for _ in range(14):
        time.sleep(3); nodes = dump(); texts = tail_state(nodes)
        if any("متصل هستید" in t for t in texts): state = "CONNECTED"; break
        if any("برقرار نشد" in t for t in texts): state = "FAILED"; break
    return state, texts

def disconnect():
    d = find("قطع اتصال", exact=True) or find("لغو", exact=True)
    if d: tap(d[1], d[2])
    time.sleep(3)

# ---- per-profile connect test ---------------------------------------------------------
rows = []
def test_profile(n, label):
    row = open_row(label)
    if not row: rows.append((n, "NOT-IMPORTED", "", "", "")); return
    tap(row[1], row[2]); time.sleep(0.8)
    r = press_connect()
    if r is None: rows.append((n, "NO-BUTTON", "", "", "")); return
    state, texts = r
    curl = adb("shell", "timeout 10 curl -s -o /dev/null -w '%{http_code}' https://www.google.com/generate_204 2>&1; echo", t=30).strip()
    udp_ok = "ok" if state == "CONNECTED" and not any("UDP (" in t for t in texts) else ("no" if state == "CONNECTED" else "-")
    i = next((k for k, s in enumerate(texts) if "برقرار نشد" in s or "UDP (" in s), None)
    note = " | ".join(texts[i:i + 2])[:160] if i is not None else ""
    rows.append((n, state, f"udp:{udp_ok}", f"curl:{curl}", note))
    disconnect()
    if state != "CONNECTED":
        for l in diag_tail(): print("   diag:", l.replace("&#10;", " / ")[:1500])

all_names = names + xnames + snames
if all_names:
    links = []
    for n in names: links.append(CASES[n][3](port[n]))
    for n in xnames: links.append(XCASES[n][2](port[n]))
    for n in snames:
        k = urllib.parse.quote(ssh_keys[n], safe="")
        links.append(f"ssh://{SSH_USER}:{SSH_PASS}@127.0.0.1:{port[n]}" + (f"?host_key={k}" if n == "ssh-pinned" else "") + f"#T-{n}")
    fresh_app("\n".join(links))
    for n in all_names: test_profile(n, "T-" + n)

# ---- AmneziaWG: a real AmneziaWG server, tunnel carries only 10.0.0.0/24 -----------------
if do_awg:
    awg_bin = os.environ.get("WT_AWG_TESTSERVER", str(ROOT / "engines/bin/awg-testserver"))
    srv = subprocess.Popen([awg_bin, "obfuscated"], stdout=subprocess.PIPE, text=True); mine.append(srv)
    info = json.loads(srv.stdout.readline()); up = info["port"]
    conf = info["conf"].replace("127.0.0.1:%d" % up, "127.0.0.1:%d" % AWG_PORT)
    mine.append(subprocess.Popen([relay_host, "host", str(AWG_PORT + 1000), str(up)]))
    adb("reverse", f"tcp:{AWG_PORT+1000}", f"tcp:{AWG_PORT+1000}")
    subprocess.Popen([ADB, "shell", f"setsid nohup /data/local/tmp/relay phone {AWG_PORT} {AWG_PORT+1000} >/dev/null 2>&1 &"])
    time.sleep(2)
    fresh_app(conf); verify_off()
    scroll_top()
    row = next((n for n in dump() if "127.0.0.1" in n[0] or "AmneziaWG" in n[0]), None)
    before = adb("shell", "timeout 5 curl -s http://10.0.0.1:8080 2>&1; echo rc=$?", t=20).strip()
    if row:
        tap(row[1], row[2]); time.sleep(0.8)
        r = press_connect()
        state = r[0] if r else "NO-BUTTON"
        inside = adb("shell", "timeout 8 curl -s http://10.0.0.1:8080 2>&1; echo rc=$?", t=30).strip()
        disconnect()
        if state != "CONNECTED":
            for l in diag_tail(): print("   diag:", l.replace("&#10;", " / ")[:1500])
        after = adb("shell", "timeout 5 curl -s http://10.0.0.1:8080 2>&1; echo rc=$?", t=20).strip()
        ok = "hello-through-awg" in inside and "hello-through-awg" not in before and "hello-through-awg" not in after
        rows.append(("awg", state, "-", "inside:" + ("ok" if "hello-through-awg" in inside else "no"), f"before/after disconnect reachable: {'no' if ok else 'CHECK ' + before[:30] + ' / ' + after[:30]}"))
    else:
        rows.append(("awg", "NOT-IMPORTED", "", "", str(tail_state(dump())[:6])))

print(f"{'case':10} {'state':10} {'udp':8} {'curl':14} note")
for r in rows: print(f"{r[0]:10} {r[1]:10} {r[2]:8} {r[3]:14} {r[4]}")

# ---- clean up only what this script started -------------------------------------------
for p in mine: p.terminate()
adb("shell", "pkill", "-x", "relay")
for n in port:
    for pp in (port[n], port[n] + 1000): adb("reverse", "--remove", f"tcp:{pp}")
adb("reverse", "--remove", f"tcp:{AWG_PORT+1000}")
