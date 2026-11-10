package awgsocks

import (
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func key(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return base64.StdEncoding.EncodeToString(k)
}

func TestUapiPassesAllKnownKeysAndRejectsInjection(t *testing.T) {
	c := &Config{PrivateKey: key(1), Peer: Peer{PublicKey: key(2), Endpoint: "192.0.2.1:51820"},
		Awg: map[string]string{
			"JC": "4", "h1": "100-200", "s3": "18", "i1": "<b 0xdeadbeef><r 16>", "itime": "1",
			"random_trailers": "1", "evil": "x", "s1": "1\nallowed_ip=0.0.0.0/0",
		}}
	out, err := uapi(c, "192.0.2.1:51820")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"jc=4\n", "h1=100-200\n", "s3=18\n", "i1=<b 0xdeadbeef><r 16>\n", "random_trailers=1\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	for _, bad := range []string{"evil", "itime", "s1="} {
		if strings.Contains(out, bad) {
			t.Errorf("unexpected %q in %q", bad, out)
		}
	}
	if strings.Count(out, "allowed_ip=") != 2 { // default full tunnel pair only, nothing smuggled
		t.Errorf("allowed_ip lines: %q", out)
	}
}

func greet(t *testing.T, user, pass string, hello []byte) ([]byte, bool) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	done := make(chan bool, 1)
	go func() { done <- negotiate(b, user, pass); b.Close() }()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	a.Write(hello)
	buf := make([]byte, 16)
	n, _ := io.ReadAtLeast(a, buf, 2)
	reply := append([]byte{}, buf[:n]...)
	if n >= 2 && reply[1] == 2 {
		// continue with the username/password sub-negotiation supplied by the caller
		return reply, true
	}
	a.Close()
	return reply, <-done
}

func TestNegotiateWithoutCredentialsAcceptsNoAuth(t *testing.T) {
	r, ok := greet(t, "", "", []byte{5, 1, 0})
	if !ok || r[1] != 0 {
		t.Fatalf("reply %v ok %v", r, ok)
	}
}

func TestNegotiateWithCredentialsRefusesNoAuth(t *testing.T) {
	r, ok := greet(t, "u", "p", []byte{5, 1, 0})
	if ok || r[1] != 0xff {
		t.Fatalf("reply %v ok %v", r, ok)
	}
}

func TestNegotiateChecksPassword(t *testing.T) {
	for _, c := range []struct {
		pass string
		ok   bool
	}{{"secret", true}, {"wrong!", false}} {
		a, b := net.Pipe()
		done := make(chan bool, 1)
		go func() { done <- negotiate(b, "user", "secret"); b.Close() }()
		a.SetDeadline(time.Now().Add(3 * time.Second))
		a.Write([]byte{5, 2, 0, 2})
		m := make([]byte, 2)
		io.ReadFull(a, m)
		if m[1] != 2 {
			t.Fatalf("method %v", m)
		}
		a.Write(append(append([]byte{1, 4}, "user"...), append([]byte{byte(len(c.pass))}, c.pass...)...))
		v := make([]byte, 2)
		io.ReadFull(a, v)
		if (v[1] == 0) != c.ok || <-done != c.ok {
			t.Fatalf("pass %q: status %v", c.pass, v)
		}
		a.Close()
	}
}
