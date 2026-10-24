#!/usr/bin/env bash
# Real TUN end-to-end test in Docker: client container tunnels through a server container to a
# web container; the web container reports the source address it sees, which proves the path.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
cargo build -q -p core-app --example tunnel_e2e
SB="$(command -v sing-box)"
EX="${CARGO_TARGET_DIR:-$root/target}/debug/examples/tunnel_e2e"
NET=wt-e2e-net
NET2=wt-e2e-net2
IMG=fedora:latest
cleanup() { docker rm -f wt-e2e-server wt-e2e-web >/dev/null 2>&1 || true; docker network rm $NET $NET2 >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create --subnet 172.31.7.0/24 $NET >/dev/null
# The web server lives on a second network that only the VPN server can reach.
docker network create --subnet 172.31.8.0/24 --internal $NET2 >/dev/null
cat > /tmp/wt-e2e-server.json <<JSON
{"log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","listen":"::","listen_port":8388,"method":"aes-256-gcm","password":"tun-e2e-pw-1234"}],"outbounds":[{"type":"direct"}]}
JSON
docker create --name wt-e2e-server --network $NET --ip 172.31.7.10 -v "$SB":/usr/bin/sing-box:ro -v /tmp/wt-e2e-server.json:/c.json:ro $IMG sing-box run -c /c.json >/dev/null
docker network connect --ip 172.31.8.10 $NET2 wt-e2e-server
docker start wt-e2e-server >/dev/null
cat > /tmp/wt-e2e-nginx.conf <<'NGINX'
server { listen 8080; location / { default_type text/plain; return 200 "$remote_addr"; } }
NGINX
docker run -d --name wt-e2e-web --network $NET2 --ip 172.31.8.20 -v /tmp/wt-e2e-nginx.conf:/etc/nginx/conf.d/default.conf:ro nginx:alpine >/dev/null
sleep 3
out="$(docker run --rm --name wt-e2e-client --network $NET --ip 172.31.7.30 --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$SB":/usr/bin/sing-box:ro -v "$EX":/usr/bin/tunnel_e2e:ro $IMG bash -c '
dnf -y -q install nftables iproute procps-ng >/dev/null 2>&1
tunnel_e2e "ss://aes-256-gcm:tun-e2e-pw-1234@wt-e2e-server:8388#e2e" 172.31.8.20:8080
' 2>&1)" || { echo "$out"; echo "FAIL: client exited non-zero"; exit 1; }
echo "$out"
echo "$out" | grep -q "^RESULT fails=0" || { echo "FAIL"; exit 1; }
echo "PASS: kill switch integration"
