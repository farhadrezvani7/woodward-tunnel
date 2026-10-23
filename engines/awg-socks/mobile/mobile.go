// Package awgmobile is the gomobile entry point for the AmneziaWG user-space peer: the Android
// app calls Start with the helper JSON produced by the Rust core, then points sing-box at the
// returned loopback SOCKS5 address. Only one peer runs at a time.
package awgmobile

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/farhadrezvani7/woodward-tunnel/engines/awg-socks/internal/awgsocks"
)

var (
	mu      sync.Mutex
	current *awgsocks.Instance
)

// Start parses configJSON (same schema as the desktop helper) and returns the SOCKS5 listen address.
// A previous instance is stopped first. Errors never include the configuration.
func Start(configJSON string) (string, error) {
	var cfg awgsocks.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "", errors.New("invalid helper configuration")
	}
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		current.Close()
		current = nil
	}
	inst, err := awgsocks.Start(cfg)
	if err != nil {
		return "", err
	}
	current = inst
	return inst.Addr(), nil
}

// Stop shuts the peer down. Safe to call when nothing is running.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		current.Close()
		current = nil
	}
}
