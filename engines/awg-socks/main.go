// awg-socks runs an AmneziaWG peer entirely in user space (no TUN device, no root) and exposes it
// as a local SOCKS5 proxy. The main engine (sing-box) then routes system traffic into it, so
// routing, DNS and kill-switch are implemented once for every protocol.
//
// Usage: awg-socks <config.json>   (config must be readable only by the current user)
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

type Config struct {
	PrivateKey string            `json:"private_key"` // base64
	Addresses  []string          `json:"addresses"`   // CIDR
	DNS        []string          `json:"dns"`
	MTU        int               `json:"mtu"`
	Peer       Peer              `json:"peer"`
	Awg        map[string]string `json:"awg"` // jc, jmin, jmax, s1..s4, h1..h4, i1..i5
	Listen     string            `json:"listen"`
}

type Peer struct {
	PublicKey    string   `json:"public_key"`
	PresharedKey string   `json:"preshared_key"`
	Endpoint     string   `json:"endpoint"` // host:port (IP literal or resolvable name)
	AllowedIPs   []string `json:"allowed_ips"`
	Keepalive    int      `json:"keepalive"`
}

func b64hex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", errors.New("key must be 32 bytes of base64")
	}
	return hex.EncodeToString(b), nil
}

// awgKeys lists the obfuscation options passed through; anything else is ignored.
var awgKeys = map[string]bool{"jc": true, "jmin": true, "jmax": true, "s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "i1": true, "i2": true, "i3": true, "i4": true, "i5": true}

func uapi(c *Config, endpoint string) (string, error) {
	priv, err := b64hex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private_key: %w", err)
	}
	pub, err := b64hex(c.Peer.PublicKey)
	if err != nil {
		return "", fmt.Errorf("public_key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	for k, v := range c.Awg {
		k = strings.ToLower(k)
		if awgKeys[k] && !strings.ContainsAny(v, "\n\r") {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if c.Peer.PresharedKey != "" {
		psk, err := b64hex(c.Peer.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("preshared_key: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	if c.Peer.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.Peer.Keepalive)
	}
	allowed := c.Peer.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	for _, a := range allowed {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}
	return b.String(), nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: awg-socks <config.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		fatal(err)
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	var local []netip.Addr
	for _, a := range cfg.Addresses {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			fatal(fmt.Errorf("address %q: %w", a, err))
		}
		local = append(local, p.Addr())
	}
	var dns []netip.Addr
	for _, d := range cfg.DNS {
		a, err := netip.ParseAddr(d)
		if err != nil {
			fatal(fmt.Errorf("dns %q: %w", d, err))
		}
		dns = append(dns, a)
	}
	if len(local) == 0 {
		fatal(errors.New("no address"))
	}
	if len(dns) == 0 {
		dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	// The engine needs an IP endpoint; resolve a hostname once, outside the tunnel.
	ep := cfg.Peer.Endpoint
	if host, port, err := net.SplitHostPort(ep); err == nil {
		if _, err := netip.ParseAddr(host); err != nil {
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				fatal(fmt.Errorf("cannot resolve endpoint %q", host))
			}
			ep = net.JoinHostPort(ips[0].String(), port)
		}
	} else {
		fatal(errors.New("endpoint must be host:port"))
	}
	conf, err := uapi(&cfg, ep)
	if err != nil {
		fatal(err)
	}
	tdev, tnet, err := netstack.CreateNetTUN(local, dns, cfg.MTU)
	if err != nil {
		fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg: "))
	if err := dev.IpcSet(conf); err != nil {
		fatal(err)
	}
	if err := dev.Up(); err != nil {
		fatal(err)
	}
	defer dev.Close()

	listen := cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fatal(err)
	}
	// Parent reads the chosen address from this line.
	fmt.Printf("LISTEN %s\n", ln.Addr().String())

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c, tnet)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ln.Close()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// serve handles one SOCKS5 CONNECT (no authentication, loopback listener only).
func serve(c net.Conn, tnet *netstack.Net) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(h[1])); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	r := make([]byte, 4)
	if _, err := io.ReadFull(c, r); err != nil || r[0] != 5 || r[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch r[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		b := make([]byte, l[0])
		io.ReadFull(c, b)
		host = string(b)
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)
	var dest netip.AddrPort
	if ip, err := netip.ParseAddr(host); err == nil {
		dest = netip.AddrPortFrom(ip, port)
	} else {
		addrs, err := tnet.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		ip, _ := netip.ParseAddr(addrs[0])
		dest = netip.AddrPortFrom(ip, port)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	up, err := tnet.DialContextTCPAddrPort(ctx, dest)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}
