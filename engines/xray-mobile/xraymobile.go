// Package xraymobile is the gomobile entry point for Xray-core on Android. It runs configurations that
// sing-box cannot (XHTTP, mKCP, VLESS encryption, TCP HTTP header obfuscation ...): the Rust core
// generates a complete Xray JSON with one authenticated loopback SOCKS5 inbound, the app starts it here
// and then points sing-box (which still owns the TUN device, DNS and routing) at that inbound.
//
// Every socket Xray opens towards the network is excluded from the VPN with VpnService.protect through
// the platform's Protector, otherwise its own traffic would loop back into the tunnel.
package xraymobile

import (
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"

	// Registers the proxies, transports and features a configuration can name.
	_ "github.com/xtls/xray-core/main/distro/all"
)

// Protector is implemented by the platform (VpnService.protect). It must return true on success.
type Protector interface {
	Protect(fd int) bool
}

var (
	mu        sync.Mutex
	current   *core.Instance
	protector Protector
	hooked    bool
)

func isLoopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// control protects the socket with the protector of the running instance. When no instance is
// running, or the platform refuses, the dial fails instead of leaking into the tunnel.
func control(skipLoopback bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		if skipLoopback && isLoopback(address) {
			return nil
		}
		mu.Lock()
		p := protector
		mu.Unlock()
		if p == nil {
			return errors.New("no protector")
		}
		var ok bool
		if err := c.Control(func(fd uintptr) { ok = p.Protect(int(fd)) }); err != nil {
			return err
		}
		if !ok {
			return errors.New("cannot exclude the socket from the VPN")
		}
		return nil
	}
}

// Start parses configJSON and starts Xray. A previous instance is stopped first. Errors never include
// the configuration (it holds the server address and credentials).
func Start(configJSON string, p Protector) error {
	if p == nil {
		return errors.New("no protector")
	}
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		_ = current.Close()
		current = nil
	}
	protector = p
	if !hooked {
		// Both hooks are process-wide and can only be added, so they go in once and look the
		// protector up at call time.
		if err := internet.RegisterDialerController(control(false)); err != nil {
			return errors.New("cannot hook the Xray dialer")
		}
		if err := internet.RegisterListenerController(control(true)); err != nil {
			return errors.New("cannot hook the Xray listener")
		}
		hooked = true
	}
	cfg, err := serial.LoadJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		return errors.New("invalid Xray configuration")
	}
	inst, err := core.New(cfg)
	if err != nil {
		return errors.New("cannot create the Xray instance")
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return errors.New("cannot start Xray")
	}
	current = inst
	return nil
}

// Stop shuts Xray down. Safe to call when nothing is running.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		_ = current.Close()
		current = nil
	}
	protector = nil
}

// Version returns the Xray-core version string.
func Version() string { return core.Version() }
