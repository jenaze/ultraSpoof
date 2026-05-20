//go:build linux

package client

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenUDPReusePort یک سوکت UDP با SO_REUSEPORT می‌سازد. اگر چند سوکت با همان
// آدرس bind شوند، کرنل بسته‌های ورودی را بر اساس هش 4-tuple بین آن‌ها توزیع می‌کند
// تا softirq روی چند CPU پخش شود.
func listenUDPReusePort(addr string, recvBufBytes int) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctlErr error
			err := c.Control(func(fd uintptr) {
				if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
					ctlErr = fmt.Errorf("SO_REUSEADDR: %w", e)
					return
				}
				if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); e != nil {
					ctlErr = fmt.Errorf("SO_REUSEPORT: %w", e)
					return
				}
				if recvBufBytes > 0 {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, recvBufBytes)
					// اگر CAP_NET_ADMIN داشته باشیم، سقف net.core.rmem_max را دور می‌زند.
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, recvBufBytes)
				}
			})
			if err != nil {
				return err
			}
			return ctlErr
		},
	}
	// "udp4" به جای "udp": تضمین می‌کند سوکت AF_INET (نه AF_INET6 dual-stack) باشد
	// تا ساختار sockaddr در recvmmsg همیشه sockaddr_in (۱۶ بایت) باشد.
	pc, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("expected *net.UDPConn, got %T", pc)
	}
	return uc, nil
}
