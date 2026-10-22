package main

import (
	"bufio"
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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
)

func keypair(t *testing.T) (priv, pub [32]byte) {
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pub[:], p)
	return
}

func freeUDP(t *testing.T) int {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// Obfuscation parameters must match on both ends; the test uses non-default values.
var obf = map[string]string{"jc": "4", "jmin": "40", "jmax": "70", "s1": "15", "s2": "23", "h1": "1234567", "h2": "2345678", "h3": "3456789", "h4": "4567890"}

func TestAmneziaWgCarriesTraffic(t *testing.T) {
	sPriv, sPub := keypair(t)
	cPriv, cPub := keypair(t)
	port := freeUDP(t)

	// In-process AmneziaWG server on a userspace network stack, serving HTTP at 10.0.0.1:8080.
	stun, snet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	sdev := device.NewDevice(stun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "srv: "))
	defer sdev.Close()
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\n", hex.EncodeToString(sPriv[:]), port)
	for k, v := range obf {
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	fmt.Fprintf(&b, "public_key=%s\nallowed_ip=10.0.0.2/32\n", hex.EncodeToString(cPub[:]))
	if err := sdev.IpcSet(b.String()); err != nil {
		t.Fatal(err)
	}
	if err := sdev.Up(); err != nil {
		t.Fatal(err)
	}
	ln, err := snet.ListenTCP(&net.TCPAddr{Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello-through-awg") }))

	// Client: the real binary, configured from JSON.
	dir := t.TempDir()
	cfg := Config{
		PrivateKey: base64.StdEncoding.EncodeToString(cPriv[:]),
		Addresses:  []string{"10.0.0.2/32"},
		Peer: Peer{PublicKey: base64.StdEncoding.EncodeToString(sPub[:]), Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
			AllowedIPs: []string{"10.0.0.0/24"}, Keepalive: 1},
		Awg: obf,
	}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "c.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "awg-socks")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cmd := exec.Command(bin, path)
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "LISTEN ") {
		t.Fatalf("no listen line: %q %v", line, err)
	}
	addr := strings.TrimSpace(strings.TrimPrefix(line, "LISTEN "))

	// SOCKS5 CONNECT 10.0.0.1:8080 and speak HTTP over it.
	var body string
	var last error
	for i := 0; i < 20 && body == ""; i++ {
		body, last = fetch(addr)
		if body == "" {
			time.Sleep(300 * time.Millisecond)
		}
	}
	if !strings.Contains(body, "hello-through-awg") {
		t.Fatalf("no data through AmneziaWG tunnel: %q %v", body, last)
	}
}

func fetch(socks string) (string, error) {
	c, err := net.DialTimeout("tcp", socks, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	c.Write([]byte{5, 1, 0})
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil {
		return "", err
	}
	c.Write([]byte{5, 1, 0, 1, 10, 0, 0, 1, 0x1f, 0x90})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return "", err
	}
	if rep[1] != 0 {
		return "", fmt.Errorf("socks reply %d", rep[1])
	}
	c.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
	b, _ := io.ReadAll(c)
	return string(b), nil
}
