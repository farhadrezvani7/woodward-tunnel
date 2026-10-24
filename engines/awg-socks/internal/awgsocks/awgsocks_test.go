package awgsocks

import (
	"encoding/base64"
	"strings"
	"testing"
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
