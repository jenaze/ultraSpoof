//go:build linux && amd64

package spoof

import (
	"net"
	"syscall"
	"unsafe"
)

// sysSendmmsg شمارهٔ syscall sendmmsg روی linux/amd64.
const sysSendmmsg uintptr = 307

// mmsghdr ساختار خام برای syscall sendmmsg/recvmmsg.
type mmsghdr struct {
	Hdr syscall.Msghdr
	Len uint32
	_   [4]byte
}

// sendmmsgIPv4 ارسال چند بسته به همان مقصد IPv4 در یک syscall واحد.
// در صورت partial send، حلقه ادامه می‌دهد تا همهٔ بسته‌ها فرستاده شوند.
func sendmmsgIPv4(fd int, d4 net.IP, pkts [][]byte) error {
	sa := syscall.RawSockaddrInet4{
		Family: syscall.AF_INET,
	}
	copy(sa.Addr[:], d4)
	saLen := uint32(unsafe.Sizeof(sa))

	msgs := make([]mmsghdr, len(pkts))
	iovs := make([]syscall.Iovec, len(pkts))
	for i, p := range pkts {
		if len(p) > 0 {
			iovs[i].Base = &p[0]
			iovs[i].Len = uint64(len(p))
		}
		msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sa))
		msgs[i].Hdr.Namelen = saLen
		msgs[i].Hdr.Iov = &iovs[i]
		msgs[i].Hdr.Iovlen = 1
	}

	sent := 0
	for sent < len(msgs) {
		remain := msgs[sent:]
		n, _, errno := syscall.Syscall6(sysSendmmsg,
			uintptr(fd),
			uintptr(unsafe.Pointer(&remain[0])),
			uintptr(len(remain)),
			0, 0, 0)
		if errno != 0 {
			if errno == syscall.EINTR {
				continue
			}
			if errno == syscall.EAGAIN {
				// بافر کرنل پر است؛ یک تک بسته را با Sendto بفرست تا فشار آزاد شود.
				p := pkts[sent]
				saSingle := &syscall.SockaddrInet4{Addr: [4]byte{d4[0], d4[1], d4[2], d4[3]}}
				if err := syscall.Sendto(fd, p, 0, saSingle); err != nil {
					return err
				}
				sent++
				continue
			}
			return errno
		}
		if n == 0 {
			break
		}
		sent += int(n)
	}
	return nil
}
