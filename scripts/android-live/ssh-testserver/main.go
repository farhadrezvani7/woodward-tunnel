// ssh-testserver is a minimal SSH server for the live phone test: password authentication and
// direct-tcpip forwarding only (what sing-box's SSH outbound uses). Test tool, never shipped.
//
//	ssh-testserver <port> <user> <password>
//
// Prints one JSON line {"port":N,"host_key":"ssh-ed25519 AAAA..."} when it is listening.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: ssh-testserver <port> <user> <password>")
		os.Exit(2)
	}
	port, user, pass := os.Args[1], os.Args[2], os.Args[3]
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	signer, err := ssh.NewSignerFromKey(priv)
	check(err)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if subtle.ConstantTimeCompare([]byte(c.User()), []byte(user)) == 1 && subtle.ConstantTimeCompare(p, []byte(pass)) == 1 {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	check(err)
	n, _ := strconv.Atoi(port)
	out, _ := json.Marshal(map[string]any{"port": n, "host_key": string(trim(ssh.MarshalAuthorizedKey(signer.PublicKey())))})
	fmt.Println(string(out))
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go serve(c, cfg)
	}
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "direct-tcpip" {
			nch.Reject(ssh.UnknownChannelType, "only direct-tcpip")
			continue
		}
		go forward(nch)
	}
}

// direct-tcpip payload (RFC 4254 7.2): string host, uint32 port, string origin, uint32 origin port.
func forward(nch ssh.NewChannel) {
	p := nch.ExtraData()
	if len(p) < 4 {
		nch.Reject(ssh.ConnectionFailed, "bad request")
		return
	}
	l := int(binary.BigEndian.Uint32(p))
	if len(p) < 4+l+4 {
		nch.Reject(ssh.ConnectionFailed, "bad request")
		return
	}
	host := string(p[4 : 4+l])
	port := binary.BigEndian.Uint32(p[4+l:])
	up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		nch.Reject(ssh.ConnectionFailed, "dial failed")
		return
	}
	ch, reqs, err := nch.Accept()
	if err != nil {
		up.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { io.Copy(up, ch); up.Close() }()
	go func() { io.Copy(ch, up); ch.Close() }()
}
