package awgmobile

import "testing"

func TestSummarize(t *testing.T) {
	in := "private_key=aa\nlisten_port=0\npublic_key=bb\nendpoint=1.2.3.4:5\nlast_handshake_time_sec=100\nlast_handshake_time_nsec=5\ntx_bytes=10\nrx_bytes=20\npublic_key=cc\nlast_handshake_time_sec=250\ntx_bytes=1\nrx_bytes=2\nerrno=0\n"
	want := `{"last_handshake_time_sec":250,"rx_bytes":22,"tx_bytes":11,"peers":2}`
	if got := summarize(in); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if got := summarize(""); got != `{"last_handshake_time_sec":0,"rx_bytes":0,"tx_bytes":0,"peers":0}` {
		t.Fatal(got)
	}
}

func TestStatsUnknownHandle(t *testing.T) {
	if Stats(12345) != "" || Protect(12345) {
		t.Fatal("unknown handle must be inert")
	}
	TurnOff(12345)
}

func TestTurnOnRequiresProtector(t *testing.T) {
	if _, err := TurnOn(-1, "", nil); err == nil {
		t.Fatal("expected error")
	}
}
