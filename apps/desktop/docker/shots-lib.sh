#!/usr/bin/env bash
# Helpers for driving the real desktop app under Xvfb with a real keyring and a local sing-box
# server. Sourced by inside-shots.sh. Everything is plain xdotool/ImageMagick; no test hooks in the app.
OUT=${OUT:-/work/apps/desktop/dist/screenshots}
W=${W:-460}; H=${H:-800}

env_up() {   # starts Xvfb, the keyring and the shadowsocks server once per container
  mkdir -p "$OUT"
  if ! pgrep -x Xvfb >/dev/null; then
    setsid nohup Xvfb :99 -screen 0 1100x900x24 >/tmp/xvfb.log 2>&1 &
    sleep 2
  fi
  export DISPLAY=:99
  if [ -z "${GNOME_KEYRING_CONTROL:-}" ] && [ "${NO_KEYRING:-0}" != 1 ]; then
    eval "$(echo '' | gnome-keyring-daemon --unlock --components=secrets 2>/dev/null)"
    export GNOME_KEYRING_CONTROL SSH_AUTH_SOCK 2>/dev/null
  fi
  SB="$(dirname "$BIN")/wt-sing-box"
  if ! pgrep -f "ss-ux.json" >/dev/null; then
    cat > /tmp/ss-ux.json <<JSON
{"log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":18388,"method":"aes-256-gcm","password":"pw-shots-1234"}],"outbounds":[{"type":"direct"}]}
JSON
    setsid nohup "$SB" run -c /tmp/ss-ux.json >/tmp/ss.log 2>&1 &
  fi
}

# app_up <lang-env> [settings-json]   fresh profile directory, then launch
app_up() {
  local loc="$1" settings="${2:-}"
  export HOME=/tmp/home-ui; rm -rf "$HOME"; mkdir -p "$HOME/.local/share/app.woodward.tunnel"
  [ -n "$settings" ] && echo "$settings" > "$HOME/.local/share/app.woodward.tunnel/settings.json"
  launch_app "$loc"
}
launch_app() {
  local loc="${1:-fa_IR.UTF-8}"
  export WEBKIT_DISABLE_DMABUF_RENDERER=1 WEBKIT_DISABLE_COMPOSITING_MODE=1 LIBGL_ALWAYS_SOFTWARE=1 GDK_BACKEND=x11
  LANG=$loc LANGUAGE=${loc%%.*} LC_ALL=$loc setsid nohup "$BIN" "${@:2}" >/tmp/app.log 2>&1 &
  APP=$!
  WID=$(xdotool search --sync --onlyvisible --name "Woodward Tunnel" | head -1)
  xdotool windowmove "$WID" 0 0; xdotool windowsize "$WID" "$W" "$H"; xdotool windowfocus "$WID"
  sleep 3
}
app_down() { pkill -f "$BIN" 2>/dev/null; pkill -f "wt-sing-box run -c .*home-ui" 2>/dev/null; sleep 1; }

shot()  { import -window root -crop ${W}x${H}+0+0 +repage "$OUT/$1.png"; echo "shot $1"; }
click() { xdotool mousemove "$1" "$2" click 1; sleep "${3:-0.8}"; }
key()   { xdotool key "$@"; sleep 0.4; }
tabs()  { for _ in $(seq "$1"); do xdotool key Tab; sleep 0.12; done; }
typ()   { xdotool type --delay "${DELAY:-12}" -- "$1"; }
