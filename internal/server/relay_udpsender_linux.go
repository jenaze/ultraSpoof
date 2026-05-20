//go:build linux

package server

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// relayUDPSender ارسال UDP دانلود بدون raw socket؛ مقصد همان relay است (کرنل واسط SNAT/DNAT می‌زند).
// از WriteTo به‌جای Connect استفاده می‌شود تا کراس‌کامپایل از ویندوز به linux/amd64 بدون وابستگی به UDPConn.Connect بماند.
type relayUDPSender struct {
	conns []*net.UDPConn
	relay *net.UDPAddr
	rr    atomic.Uint64
}

func newRelayUDPSender(relay *net.UDPAddr, workers int, sndBuf int, iface string) (udpDownloadSender, error) {
	if workers < 1 {
		workers = 1
	}
	if relay == nil {
		return nil, fmt.Errorf("relay address is nil")
	}
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			err := c.Control(func(fd uintptr) {
				if iface != "" {
					ctrlErr = unix.BindToDevice(int(fd), iface)
				}
				if sndBuf > 0 {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, sndBuf)
					// دور زدن wmem_max در صورت داشتن CAP_NET_ADMIN
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sndBuf)
				}
			})
			if err != nil {
				return err
			}
			return ctrlErr
		},
	}

	conns := make([]*net.UDPConn, workers)
	for i := 0; i < workers; i++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", ":0")
		if err != nil {
			closeRelayConns(conns)
			return nil, fmt.Errorf("listen udp for relay: %w", err)
		}
		uc := pc.(*net.UDPConn)
		conns[i] = uc
	}
	return &relayUDPSender{conns: conns, relay: relay}, nil
}

func closeRelayConns(conns []*net.UDPConn) {
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
}

func (r *relayUDPSender) pick() *net.UDPConn {
	if len(r.conns) == 1 {
		return r.conns[0]
	}
	i := r.rr.Add(1) % uint64(len(r.conns))
	return r.conns[i]
}

func (r *relayUDPSender) SendBatch(_ net.IP, _ uint16, _ net.IP, _ uint16, payloads [][]byte) error {
	if len(payloads) == 0 {
		return nil
	}
	conn := r.pick()
	for _, p := range payloads {
		if p == nil {
			break
		}
		if _, err := conn.WriteTo(p, r.relay); err != nil {
			return fmt.Errorf("relay udp write: %w", err)
		}
	}
	return nil
}

func (r *relayUDPSender) SendUDP(_ net.IP, _ uint16, _ net.IP, _ uint16, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	_, err := r.pick().WriteTo(payload, r.relay)
	if err != nil {
		return fmt.Errorf("relay udp write: %w", err)
	}
	return nil
}

func (r *relayUDPSender) Close() error {
	var first error
	for _, c := range r.conns {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
