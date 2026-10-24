// awg-tunserver is a test helper: an AmneziaWG server on a REAL tun device that NATs clients to the
// network it runs on (run it in a container with NET_ADMIN; see run-docker.sh). It prints one JSON line
// with a ready-made full-tunnel client config and keeps running until killed. Linux only.
//
// Usage: awg-tunserver <udp-port> [awg2]
//
//	awg2  use AmneziaWG 2.0 style parameters (S3/S4, header ranges, I1 signature packet)
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/crypto/curve25519"
)

func keypair() (priv, pub [32]byte) {
	rand.Read(priv[:])
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	p, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	copy(pub[:], p)
	return
}

func sh(cmd string) {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n%s", cmd, err, out)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: awg-tunserver <udp-port> [awg2]")
		os.Exit(2)
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	awg2 := len(os.Args) > 2 && os.Args[2] == "awg2"
	sPriv, sPub := keypair()
	cPriv, cPub := keypair()

	t, err := tun.CreateTUN("wg0", 1280)
	if err != nil {
		panic(err)
	}
	dev := device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "srv: "))
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\n", hex.EncodeToString(sPriv[:]), port)
	var awg strings.Builder
	set := func(k, v string) {
		fmt.Fprintf(&b, "%s=%s\n", k, v)
		fmt.Fprintf(&awg, "%s = %s\n", strings.ToUpper(k[:1])+k[1:], v)
	}
	set("jc", "4")
	set("jmin", "40")
	set("jmax", "70")
	set("s1", "15")
	set("s2", "23")
	if awg2 {
		set("s3", "18")
		set("s4", "9")
		set("h1", "100000-200000")
		set("h2", "300000-400000")
		set("h3", "500000-600000")
		set("h4", "700000-800000")
		set("i1", "<b 0xc0000000010800000000><r 16>")
	} else {
		set("h1", "1234567")
		set("h2", "2345678")
		set("h3", "3456789")
		set("h4", "4567890")
	}
	fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=10.77.0.2/32\n", hex.EncodeToString(cPub[:]))
	if err := dev.IpcSet(b.String()); err != nil {
		panic(err)
	}
	if err := dev.Up(); err != nil {
		panic(err)
	}
	sh("ip addr add 10.77.0.1/24 dev wg0 && ip link set wg0 up mtu 1280")
	sh("iptables -t nat -A POSTROUTING -s 10.77.0.0/24 ! -o wg0 -j MASQUERADE")
	sh("iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT")

	enc := base64.StdEncoding.EncodeToString
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.77.0.2/32\nDNS = 1.1.1.1\n%s\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
		enc(cPriv[:]), awg.String(), enc(sPub[:]), port)
	out, _ := json.Marshal(map[string]any{"conf": conf, "port": port})
	fmt.Println(string(out))
	select {}
}
