// relay carries UDP over a TCP connection so that `adb reverse` (TCP only) can reach a UDP server on the
// host from a phone connected by USB. Test tool only, never shipped.
//
//	relay phone <udp-port> <tcp-port>   on the phone: UDP 127.0.0.1:<udp> <-> TCP 127.0.0.1:<tcp> (adb reverse)
//	relay host  <tcp-port> <udp-port>   on the host:  TCP 127.0.0.1:<tcp> <-> UDP server 127.0.0.1:<udp>
//
// Frames are a 2-byte big-endian length followed by the datagram. One TCP connection per UDP peer.
package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
)

func writeFrame(c net.Conn, b []byte) error {
	h := make([]byte, 2, 2+len(b))
	binary.BigEndian.PutUint16(h, uint16(len(b)))
	_, err := c.Write(append(h, b...))
	return err
}

func readFrame(c net.Conn) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(h[:]))
	_, err := io.ReadFull(c, b)
	return b, err
}

func main() {
	if len(os.Args) != 4 {
		os.Exit(2)
	}
	if os.Args[1] == "phone" {
		phone(os.Args[2], os.Args[3])
	} else {
		host(os.Args[2], os.Args[3])
	}
}

func phone(udpPort, tcpPort string) {
	u, err := net.ListenPacket("udp", "127.0.0.1:"+udpPort)
	if err != nil {
		panic(err)
	}
	var mu sync.Mutex
	peers := map[string]net.Conn{}
	buf := make([]byte, 65535)
	for {
		n, src, err := u.ReadFrom(buf)
		if err != nil {
			return
		}
		mu.Lock()
		c := peers[src.String()]
		if c == nil {
			c, err = net.Dial("tcp", "127.0.0.1:"+tcpPort)
			if err != nil {
				mu.Unlock()
				continue
			}
			peers[src.String()] = c
			go func(c net.Conn, src net.Addr) {
				for {
					b, err := readFrame(c)
					if err != nil {
						mu.Lock()
						delete(peers, src.String())
						mu.Unlock()
						return
					}
					u.WriteTo(b, src)
				}
			}(c, src)
		}
		mu.Unlock()
		writeFrame(c, buf[:n])
	}
}

func host(tcpPort, udpPort string) {
	l, err := net.Listen("tcp", "127.0.0.1:"+tcpPort)
	if err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			u, err := net.Dial("udp", "127.0.0.1:"+udpPort)
			if err != nil {
				return
			}
			defer u.Close()
			go func() {
				b := make([]byte, 65535)
				for {
					n, err := u.Read(b)
					if err != nil {
						c.Close()
						return
					}
					writeFrame(c, b[:n])
				}
			}()
			for {
				b, err := readFrame(c)
				if err != nil {
					return
				}
				u.Write(b)
			}
		}(c)
	}
}
