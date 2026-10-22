#!/usr/bin/env bash
# Runs inside the builder image under Xvfb: starts a local sing-box server and a keyring, launches
# the built app, drives it with xdotool and stores screenshots in dist/screenshots.
# usage: inside-shots.sh <app-binary>
set -u
BIN="${1:?app binary}"
OUT=/work/apps/desktop/dist/screenshots
mkdir -p "$OUT"
export HOME=/tmp/home-ui; rm -rf "$HOME"; mkdir -p "$HOME/.local/share/app.woodward.tunnel"
echo '{"mode":"proxy","socks_port":18080}' > "$HOME/.local/share/app.woodward.tunnel/settings.json"

Xvfb :99 -screen 0 1100x900x24 >/tmp/xvfb.log 2>&1 &
export DISPLAY=:99
sleep 2
eval "$(echo '' | gnome-keyring-daemon --unlock --components=secrets 2>/dev/null)"
export GNOME_KEYRING_CONTROL SSH_AUTH_SOCK 2>/dev/null

SB="$(dirname "$BIN")/wt-sing-box"
cat > /tmp/ss.json <<JSON
{"log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":18388,"method":"aes-256-gcm","password":"pw-shots-1234"}],"outbounds":[{"type":"direct"}]}
JSON
"$SB" run -c /tmp/ss.json >/tmp/ss.log 2>&1 &
SSPID=$!

export WEBKIT_DISABLE_DMABUF_RENDERER=1 WEBKIT_DISABLE_COMPOSITING_MODE=1 LIBGL_ALWAYS_SOFTWARE=1 GDK_BACKEND=x11
"$BIN" >/tmp/app.log 2>&1 &
APP=$!
WID=$(xdotool search --sync --onlyvisible --name "Woodward Tunnel" | head -1)
xdotool windowmove "$WID" 0 0; xdotool windowsize "$WID" 460 800; xdotool windowfocus "$WID"
sleep 3

shot() { import -window root -crop 460x800+0+0 +repage "$OUT/$1.png"; echo "shot $1"; }
key() { xdotool key --window "$WID" "$@"; sleep 0.4; }
tabs() { for _ in $(seq "$1"); do xdotool key Tab; sleep 0.15; done; }

shot 01-empty-fa
click() { xdotool mousemove "$1" "$2" click 1; sleep 0.8; }
click 58 386          # paste button
shot 02-paste-dialog
xdotool type --delay 15 "ss://aes-256-gcm:pw-shots-1234@127.0.0.1:18388#Local-Server"; xdotool key Return
xdotool type --delay 15 "trojan://pw1234567890@example.com:443#Berlin"; xdotool key Return
xdotool type --delay 15 "https://sub.example.com/feed"
sleep 0.5; shot 03-paste-filled
click 385 524         # Add
sleep 1; shot 04-subscription-confirm
click 270 480; sleep 0.8   # "No" on the subscription question
shot 05-list
click 230 170         # connect
sleep 1; shot 06-connecting
sleep 5; shot 07-connected
click 78 34           # advanced settings
sleep 1; shot 08-advanced
xdotool key Escape; sleep 0.5
click 200 34          # language: English
sleep 1; shot 09-english-connected
click 230 170         # disconnect
sleep 3; shot 10-english-idle
kill "$SSPID"; sleep 1
click 230 170         # connect while the server is down
sleep 12; shot 11-server-down
click 248 34; sleep 0.5   # back to Persian (button sits elsewhere in the English layout)
sleep 1; shot 12-fa-final
echo "--- app log (redaction check):"; cat /tmp/app.log | head -20
kill "$APP" "$SSPID" 2>/dev/null
exit 0
