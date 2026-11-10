package xraymobile

import "testing"

type refuse struct{}

func (refuse) Protect(int) bool { return false }

func TestStartRejectsBadInput(t *testing.T) {
	if Start("{}", nil) == nil {
		t.Fatal("nil protector must fail")
	}
	if Start("not json", refuse{}) == nil {
		t.Fatal("bad json must fail")
	}
	Stop()
}

func TestVersion(t *testing.T) {
	if Version() == "" {
		t.Fatal("empty version")
	}
}

func TestLoopback(t *testing.T) {
	if !isLoopback("127.0.0.1:80") || !isLoopback("[::1]:80") || isLoopback("203.0.113.1:80") {
		t.Fatal("loopback detection")
	}
}
