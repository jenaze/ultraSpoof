//go:build linux && !amd64

package spoof

import (
	"net"
	"syscall"
)

// sendmmsgIPv4 fallback برای آرشیتکچرهای لینوکسی که شمارهٔ syscall sendmmsg
// در این پروژه برایشان مشخص نشده. صرفاً Sendto در یک حلقه.
func sendmmsgIPv4(fd int, d4 net.IP, pkts [][]byte) error {
	sa := &syscall.SockaddrInet4{Addr: [4]byte{d4[0], d4[1], d4[2], d4[3]}}
	for _, p := range pkts {
		if err := syscall.Sendto(fd, p, 0, sa); err != nil {
			return err
		}
	}
	return nil
}
