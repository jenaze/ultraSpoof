package client

import (
	"net"
	"sync"
)

// recvLoopReadFromUDP دریافت پایدار UDP از طریق net.UDPConn (سازگار با poller داخلی Go).
// recvmmsg روی fd غیرمسدود Go گاهی EAGAIN را به‌عنوان خطای مرگبار برمی‌گرداند؛ این مسیر
// همان رفتار قبل از بهینه‌سازی recvmmsg را بازمی‌گرداند.
func recvLoopReadFromUDP(conn *net.UDPConn, pool *sync.Pool, emit func(buf *[]byte, size int, src *net.UDPAddr)) error {
	for {
		bp := pool.Get().(*[]byte)
		n, raddr, err := conn.ReadFromUDP(*bp)
		if err != nil {
			pool.Put(bp)
			return err
		}
		emit(bp, n, raddr)
	}
}
