// awg-socks runs an AmneziaWG peer entirely in user space (no TUN device, no root) and exposes it
// as a local SOCKS5 proxy. The main engine (sing-box) then routes system traffic into it, so
// routing, DNS and kill-switch are implemented once for every protocol.
//
// Usage: awg-socks <config.json>   (config must be readable only by the current user)
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/farhadrezvani7/woodward-tunnel/engines/awg-socks/internal/awgsocks"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: awg-socks <config.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal(err)
	}
	var cfg awgsocks.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		fatal(err)
	}
	inst, err := awgsocks.Start(cfg)
	if err != nil {
		fatal(err)
	}
	defer inst.Close()
	// Parent reads the chosen address from this line.
	fmt.Printf("LISTEN %s\n", inst.Addr())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
