#!/usr/bin/env bash
# Starts awg-tunserver in a container with a real tun device and NAT, publishing <udp-port> on the host.
# Prints the client config JSON line (Endpoint is 127.0.0.1; the emulator reaches the host at 10.0.2.2).
#   run-docker.sh <udp-port> [awg2]      stop with: docker rm -f awg-tunserver
set -euo pipefail
port="${1:?udp port}"; mode="${2:-}"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
(cd "$here/../.." && CGO_ENABLED=0 GOOS=linux go build -trimpath -o "$work/awg-tunserver" ./cmd/awg-tunserver)
cat > "$work/Dockerfile" <<'DOCKER'
FROM alpine:3.20
RUN apk add --no-cache iptables iproute2
COPY awg-tunserver /usr/local/bin/awg-tunserver
ENTRYPOINT ["/usr/local/bin/awg-tunserver"]
DOCKER
docker build -q -t awg-tunserver "$work" >/dev/null
docker rm -f awg-tunserver >/dev/null 2>&1 || true
docker run -d --name awg-tunserver --cap-add NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 -p "$port:$port/udp" awg-tunserver "$port" $mode >/dev/null
for _ in $(seq 1 30); do
  line="$(docker logs awg-tunserver 2>/dev/null | grep '^{' | head -1 || true)"
  [ -n "$line" ] && { echo "$line"; exit 0; }
  sleep 1
done
docker logs awg-tunserver >&2; exit 1
