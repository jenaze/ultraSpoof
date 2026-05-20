//go:build linux && amd64

package client

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"unsafe"
)

const sysRecvmmsg uintptr = 299

type recvmmsghdr struct {
	Hdr syscall.Msghdr
	Len uint32
	_   [4]byte
}

type recvBatchSlot struct {
	msgs    []recvmmsghdr
	iovs    []syscall.Iovec
	sas     []syscall.RawSockaddrInet4
	bufs    []*[]byte
	bufSize int
	pool    *sync.Pool
}

func newRecvBatchSlot(n, bufSize int, pool *sync.Pool) *recvBatchSlot {
	return &recvBatchSlot{
		msgs:    make([]recvmmsghdr, n),
		iovs:    make([]syscall.Iovec, n),
		sas:     make([]syscall.RawSockaddrInet4, n),
		bufs:    make([]*[]byte, n),
		bufSize: bufSize,
		pool:    pool,
	}
}

func (r *recvBatchSlot) prepare() {
	saLen := uint32(unsafe.Sizeof(r.sas[0]))
	for i := range r.msgs {
		bp := r.pool.Get().(*[]byte)
		r.bufs[i] = bp
		r.iovs[i].Base = &(*bp)[0]
		r.iovs[i].Len = uint64(r.bufSize)
		r.msgs[i].Hdr = syscall.Msghdr{}
		r.msgs[i].Hdr.Iov = &r.iovs[i]
		r.msgs[i].Hdr.Iovlen = 1
		r.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&r.sas[i]))
		r.msgs[i].Hdr.Namelen = saLen
		r.msgs[i].Len = 0
	}
}

func (r *recvBatchSlot) releasePrepared(pool *sync.Pool) {
	for i := range r.bufs {
		if r.bufs[i] != nil {
			pool.Put(r.bufs[i])
			r.bufs[i] = nil
		}
	}
}

func recvmmsgIPv4(fd int, msgs []recvmmsghdr, flags int) (int, syscall.Errno) {
	n, _, errno := syscall.Syscall6(sysRecvmmsg,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		uintptr(flags),
		0, 0)
	return int(n), errno
}

const recvmmsgFlags = syscall.MSG_DONTWAIT | 0x10000 // MSG_WAITFORONE

// recvmmsgShouldRetry: روی لینوکس EAGAIN و EWOULDBLOCK یک مقدارند؛ در switch نمی‌توان هر دو را
// نوشت چون «duplicate case» می‌دهد. با تابع یکسان تشخیص می‌دهیم.
func recvmmsgShouldRetry(errno syscall.Errno) bool {
	return errno == syscall.EINTR || errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK
}

// recvLoopBatched دریافت batch با recvmmsg. روی EAGAIN از callback false برمی‌گردد
// و هرگز EAGAIN را به‌عنوان خطای مرگبار به hub تحویل نمی‌دهد.
func recvLoopBatched(conn *net.UDPConn, batchSize, bufSize int, pool *sync.Pool, emit func(buf *[]byte, size int, src *net.UDPAddr)) error {
	sysconn, err := conn.SyscallConn()
	if err != nil {
		return recvLoopReadFromUDP(conn, pool, emit)
	}
	slot := newRecvBatchSlot(batchSize, bufSize, pool)

	for {
		slot.prepare()
		var n int
		var sysErr syscall.Errno
		readErr := sysconn.Read(func(fd uintptr) bool {
			n, sysErr = recvmmsgIPv4(int(fd), slot.msgs, recvmmsgFlags)
			if sysErr == 0 {
				return true
			}
			if recvmmsgShouldRetry(sysErr) {
				return false
			}
			return true
		})
		if readErr != nil {
			slot.releasePrepared(pool)
			if isRecvTransient(readErr) {
				continue
			}
			var errno syscall.Errno
			if errors.As(readErr, &errno) && errno == syscall.EINTR {
				continue
			}
			return readErr
		}
		if sysErr != 0 {
			if recvmmsgShouldRetry(sysErr) {
				slot.releasePrepared(pool)
				continue
			}
			slot.releasePrepared(pool)
			return sysErr
		}
		if n <= 0 {
			slot.releasePrepared(pool)
			continue
		}

		for i := 0; i < n; i++ {
			pktLen := int(slot.msgs[i].Len)
			ip := net.IPv4(slot.sas[i].Addr[0], slot.sas[i].Addr[1], slot.sas[i].Addr[2], slot.sas[i].Addr[3])
			port := int(slot.sas[i].Port>>8) | (int(slot.sas[i].Port&0xff) << 8)
			src := &net.UDPAddr{IP: ip, Port: port}
			emit(slot.bufs[i], pktLen, src)
			slot.bufs[i] = nil
		}
		for i := n; i < len(slot.bufs); i++ {
			if slot.bufs[i] != nil {
				pool.Put(slot.bufs[i])
				slot.bufs[i] = nil
			}
		}
	}
}
