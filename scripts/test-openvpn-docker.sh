#!/usr/bin/env bash
# Real OpenVPN end-to-end test in Docker: generates a PKI, runs an OpenVPN server container that
# forwards into a network only it can reach, then imports a real .ovpn through the app's importer,
# starts it through the runner and proves traffic crosses the VPN.
#
# MINIMUM OPENVPN: 2.7.8. Every older 2.7.x release is affected by published security advisories
# (https://community.openvpn.net/Security%20Announcements), among them CVE-2026-84790 (remote
# certificate identity bypass via an embedded NUL byte, fixed in 2.7.8) and CVE-2026-88964
# (underflow on a malicious PUSH_UPDATE, fixed in 2.7.8). Both containers verify the version they
# installed and the test fails when the distribution ships an older openvpn; it never silently
# tests against a vulnerable build.
set -euo pipefail
export MIN_OPENVPN="2.7.8"
# Shell snippet evaluated inside each container after "dnf install openvpn": exits 1 when too old.
export CHECK_OVPN='v=$(openvpn --version | head -n1 | sed -E "s/^OpenVPN ([0-9]+\.[0-9]+\.[0-9]+).*/\1/")
if [ "$(printf "%s\n%s\n" "$MIN_OPENVPN" "$v" | sort -V | head -n1)" != "$MIN_OPENVPN" ]; then
  echo "FATAL: openvpn $v is older than the required minimum $MIN_OPENVPN" >&2; exit 1; fi
echo "openvpn $v (>= $MIN_OPENVPN)"'
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
cargo build -q -p core-engine --example ovpn_e2e
EX="$root/target/debug/examples/ovpn_e2e"
W="$(mktemp -d)"; NET=wt-ovpn-net; NET2=wt-ovpn-net2; IMG=fedora:latest
cleanup() { docker rm -f wt-ovpn-server wt-ovpn-web >/dev/null 2>&1 || true; docker network rm $NET $NET2 >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT
cleanup 2>/dev/null || true; W="$(mktemp -d)"

# --- PKI (EC keys, short-lived) ---
cd "$W"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
openssl req -x509 -new -key ca.key -sha256 -days 2 -subj "/CN=wt-test-ca" -out ca.crt 2>/dev/null
for n in server client; do
  openssl ecparam -name prime256v1 -genkey -noout -out $n.key 2>/dev/null
  openssl req -new -key $n.key -subj "/CN=$n" -out $n.csr 2>/dev/null
  if [ $n = server ]; then eku="serverAuth"; else eku="clientAuth"; fi
  printf "keyUsage=digitalSignature,keyAgreement\nextendedKeyUsage=%s\nbasicConstraints=CA:FALSE\n" $eku > $n.ext
  openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -sha256 -extfile $n.ext -out $n.crt 2>/dev/null
done
cat > server.conf <<CONF
port 1194
proto udp
dev tun
server 10.8.0.0 255.255.255.0
ca /pki/ca.crt
cert /pki/server.crt
key /pki/server.key
dh none
ecdh-curve prime256v1
topology subnet
push "redirect-gateway def1"
keepalive 5 30
data-ciphers AES-256-GCM
verb 3
CONF
cat > client.ovpn <<CONF
client
dev tun
proto udp
remote 172.31.9.10 1194
nobind
persist-key
persist-tun
remote-cert-tls server
data-ciphers AES-256-GCM
verb 3
<ca>
$(cat ca.crt)
</ca>
<cert>
$(cat client.crt)
</cert>
<key>
$(cat client.key)
</key>
CONF
cat > nginx.conf <<'NGINX'
server { listen 8080; location / { default_type text/plain; return 200 "$remote_addr"; } }
NGINX
cd "$root"

docker network create --subnet 172.31.9.0/24 $NET >/dev/null
docker network create --subnet 172.31.10.0/24 --internal $NET2 >/dev/null
docker create --name wt-ovpn-server --network $NET --ip 172.31.9.10 --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 -e MIN_OPENVPN -e CHECK_OVPN \
  -v "$W":/pki:ro $IMG bash -c 'dnf -y -q install openvpn iptables-nft >/dev/null 2>&1; eval "$CHECK_OVPN" || exit 1; iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j MASQUERADE; exec openvpn --config /pki/server.conf' >/dev/null
docker network connect --ip 172.31.10.10 $NET2 wt-ovpn-server
docker start wt-ovpn-server >/dev/null
docker run -d --name wt-ovpn-web --network $NET2 --ip 172.31.10.20 -v "$W/nginx.conf":/etc/nginx/conf.d/default.conf:ro nginx:alpine >/dev/null
# wait for the server to finish installing and start listening
for i in $(seq 1 60); do docker logs wt-ovpn-server 2>&1 | grep -q "Initialization Sequence Completed" && break; sleep 2; done
docker logs wt-ovpn-server 2>&1 | tail -3
docker run --rm --network $NET --ip 172.31.9.30 --cap-add NET_ADMIN --device /dev/net/tun -e MIN_OPENVPN -e CHECK_OVPN \
  -v "$EX":/usr/bin/ovpn_e2e:ro -v "$W/client.ovpn":/client.ovpn:ro $IMG bash -c '
dnf -y -q install openvpn iproute >/dev/null 2>&1
eval "$CHECK_OVPN" || exit 1
ovpn_e2e /client.ovpn 172.31.10.20:8080'
