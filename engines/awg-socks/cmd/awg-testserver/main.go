// awg-testserver is a test helper: an AmneziaWG server on a user-space network stack serving
// "hello-through-awg" over HTTP at 10.0.0.1:8080 inside the tunnel. It prints one JSON line with
// a ready-made client config and keeps running until killed.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
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

func main() {
	obfuscate := len(os.Args) > 1 && os.Args[1] == "obfuscated"
	sPriv, sPub := keypair()
	cPriv, cPub := keypair()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 1280)
	if err != nil {
		panic(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "srv: "))
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\n", hex.EncodeToString(sPriv[:]), port)
	awg := ""
	if obfuscate {
		for _, kv := range [][2]string{{"jc", "4"}, {"jmin", "40"}, {"jmax", "70"}, {"s1", "15"}, {"s2", "23"}, {"h1", "1234567"}, {"h2", "2345678"}, {"h3", "3456789"}, {"h4", "4567890"}} {
			fmt.Fprintf(&b, "%s=%s\n", kv[0], kv[1])
			awg += fmt.Sprintf("%s = %s\n", map[string]string{"jc": "Jc", "jmin": "Jmin", "jmax": "Jmax", "s1": "S1", "s2": "S2", "h1": "H1", "h2": "H2", "h3": "H3", "h4": "H4"}[kv[0]], kv[1])
		}
	}
	fmt.Fprintf(&b, "public_key=%s\nallowed_ip=10.0.0.2/32\n", hex.EncodeToString(cPub[:]))
	if err := dev.IpcSet(b.String()); err != nil {
		panic(err)
	}
	if err := dev.Up(); err != nil {
		panic(err)
	}
	ln, err := tnet.ListenTCP(&net.TCPAddr{Port: 8080})
	if err != nil {
		panic(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello-through-awg") }))

	enc := base64.StdEncoding.EncodeToString
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n%s\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 1\n", enc(cPriv[:]), awg, enc(sPub[:]), port)
	out, _ := json.Marshal(map[string]any{"conf": conf, "port": port})
	fmt.Println(string(out))
	select {}
}
