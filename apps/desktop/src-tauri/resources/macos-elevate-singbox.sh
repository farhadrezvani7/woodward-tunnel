#!/bin/sh
# macOS: run sing-box as root after one system administrator prompt, then behave like a plain
# child process of the app: engine output appears on stdout, SIGTERM stops the engine.
#
# Called by the app exactly like sing-box:   macos-elevate-singbox.sh run -c <config.json>
# Environment: WT_REAL_SING_BOX = path of the real sing-box executable.
#
# How stopping works without a second prompt: the root part watches (a) a stop flag file in the
# user's private run directory and (b) this wrapper's process id. Removing the flag, or this
# wrapper dying for any reason, makes the root part terminate sing-box.
set -u

if [ "${1:-}" = "--root" ]; then
    real=$2; cfg=$3; log=$4; stop=$5; parent=$6; running=$7
    : > "$running"
    chmod 600 "$log" 2>/dev/null
    "$real" run -c "$cfg" >> "$log" 2>&1 &
    child=$!
    while kill -0 "$child" 2>/dev/null && kill -0 "$parent" 2>/dev/null && [ -e "$stop" ]; do
        sleep 1
    done
    kill -TERM "$child" 2>/dev/null
    n=0
    while kill -0 "$child" 2>/dev/null && [ "$n" -lt 5 ]; do sleep 1; n=$((n + 1)); done
    kill -KILL "$child" 2>/dev/null
    rm -f "$running"
    exit 0
fi

[ "${1:-}" = "run" ] && [ "${2:-}" = "-c" ] && [ -n "${3:-}" ] || { echo "usage: $0 run -c CONFIG" >&2; exit 64; }
cfg=$3
real=${WT_REAL_SING_BOX:-}
[ -n "$real" ] && [ -x "$real" ] || { echo "sing-box not found" >&2; exit 66; }
dir=$(dirname "$cfg")
log="$dir/sing-box-root.log"
stop="$dir/stop.flag"
running="$dir/running.flag"
rm -f "$running"
: > "$log"; chmod 600 "$log"
: > "$stop"

tailpid=""
cleanup() {
    rm -f "$stop"
    n=0
    while [ -e "$running" ] && [ "$n" -lt 8 ]; do sleep 1; n=$((n + 1)); done
    [ -n "$tailpid" ] && kill "$tailpid" 2>/dev/null
    rm -f "$log"
    exit 0
}
trap cleanup TERM INT HUP

# The administrator prompt. Arguments are passed through argv and quoted by AppleScript.
osascript \
    -e 'on run argv' \
    -e 'set cmd to "/bin/sh"' \
    -e 'repeat with i from 1 to (count of argv)' \
    -e 'set cmd to cmd & " " & quoted form of (item i of argv)' \
    -e 'end repeat' \
    -e 'do shell script cmd & " > /dev/null 2>&1 &" with administrator privileges' \
    -e 'end run' \
    -- "$0" --root "$real" "$cfg" "$log" "$stop" "$$" "$running" || { echo "administrator permission was not granted" >&2; rm -f "$stop"; exit 77; }

tail -n +1 -f "$log" &
tailpid=$!

# Wait until the root part is up, then until it ends.
n=0
while [ ! -e "$running" ] && [ "$n" -lt 30 ]; do sleep 1; n=$((n + 1)); done
while [ -e "$running" ]; do sleep 1; done
kill "$tailpid" 2>/dev/null
rm -f "$stop" "$log"
exit 1
