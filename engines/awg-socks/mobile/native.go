package awgmobile

// Native WireGuard / AmneziaWG data path for Android, mirroring the official app (amneziawg-android,
// tunnel/tools/libwg-go/api-android.go): the platform's VpnService TUN file descriptor is handed straight to
// amneziawg-go; there is no user-space network stack, no SOCKS proxy and no second engine in between.
// The device's UDP sockets are excluded from the VPN with the platform's protect().

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
)

// Protector is implemented by the platform (VpnService.protect). It must return true on success.
type Protector interface {
	Protect(fd int) bool
}

type handleEntry struct {
	dev       *device.Device
	protector Protector
}

var (
	nativeMu sync.Mutex
	handles  = map[int]*handleEntry{}

	logMu    sync.Mutex
	logLines []string
)

const maxLogLines = 100

func logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	if len(line) > 300 {
		line = line[:300]
	}
	logMu.Lock()
	defer logMu.Unlock()
	if len(logLines) >= maxLogLines {
		logLines = logLines[1:]
	}
	logLines = append(logLines, line)
}

// LogTail returns the recent engine log lines (newest last), one per line. Errors may name the peer
// endpoint, so callers must treat the text as sensitive (the Rust diagnostic report redacts it).
func LogTail() string {
	logMu.Lock()
	defer logMu.Unlock()
	return strings.Join(logLines, "\n")
}

// TurnOn takes ownership of tunFd, starts the device with the given UAPI settings and protects its UDP sockets.
// It returns a handle for TurnOff / Stats / Protect. Errors never include the settings.
func TurnOn(tunFd int, uapi string, protector Protector) (int, error) {
	if protector == nil {
		unix.Close(tunFd)
		return -1, errors.New("no protector")
	}
	t, _, err := tun.CreateUnmonitoredTUNFromFD(tunFd)
	if err != nil {
		unix.Close(tunFd)
		logf("tun from fd: %v", err)
		return -1, errors.New("cannot use the tunnel interface")
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(format string, args ...any) { logf("error: "+format, args...) },
	}
	dev := device.NewDevice(t, conn.NewStdNetBind(), logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		logf("ipc set failed")
		return -1, errors.New("invalid WireGuard settings")
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
	if err := dev.Up(); err != nil {
		dev.Close()
		logf("device up: %v", err)
		return -1, errors.New("cannot start the WireGuard device")
	}
	e := &handleEntry{dev: dev, protector: protector}
	if err := protect(e); err != nil {
		dev.Close()
		return -1, err
	}
	nativeMu.Lock()
	defer nativeMu.Unlock()
	h := 0
	for ; h < math.MaxInt32; h++ {
		if _, used := handles[h]; !used {
			break
		}
	}
	handles[h] = e
	return h, nil
}

func protect(e *handleEntry) error {
	bind, _ := e.dev.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return errors.New("cannot reach the device sockets")
	}
	found := 0
	if fd, err := bind.PeekLookAtSocketFd4(); err == nil {
		found++
		if !e.protector.Protect(fd) {
			return errors.New("cannot exclude the IPv4 socket from the VPN")
		}
	}
	if fd, err := bind.PeekLookAtSocketFd6(); err == nil {
		found++
		if !e.protector.Protect(fd) {
			return errors.New("cannot exclude the IPv6 socket from the VPN")
		}
	}
	if found == 0 {
		return errors.New("the device opened no sockets")
	}
	return nil
}

// Protect re-protects the device's UDP sockets (call after a network change; harmless when nothing changed).
func Protect(handle int) bool {
	nativeMu.Lock()
	e := handles[handle]
	nativeMu.Unlock()
	if e == nil {
		return false
	}
	return protect(e) == nil
}

// TurnOff stops the device and closes the TUN file descriptor.
func TurnOff(handle int) {
	nativeMu.Lock()
	e := handles[handle]
	delete(handles, handle)
	nativeMu.Unlock()
	if e != nil {
		e.dev.Close()
	}
}

// Stats returns JSON: {"last_handshake_time_sec":N,"rx_bytes":N,"tx_bytes":N,"peers":N} summed over peers
// (the newest handshake wins). Endpoints and keys are never included. Empty string for an unknown handle.
func Stats(handle int) string {
	nativeMu.Lock()
	e := handles[handle]
	nativeMu.Unlock()
	if e == nil {
		return ""
	}
	s, err := e.dev.IpcGet()
	if err != nil {
		return ""
	}
	return summarize(s)
}

func summarize(ipc string) string {
	var hs, rx, tx, peers int64
	for _, line := range strings.Split(ipc, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "public_key":
			peers++
		case "last_handshake_time_sec":
			if n > hs {
				hs = n
			}
		case "rx_bytes":
			rx += n
		case "tx_bytes":
			tx += n
		}
	}
	return fmt.Sprintf(`{"last_handshake_time_sec":%d,"rx_bytes":%d,"tx_bytes":%d,"peers":%d}`, hs, rx, tx, peers)
}
