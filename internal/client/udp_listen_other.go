//go:build !linux

package client

import (
	"net"
)

// listenUDPReusePort روی پلتفرم‌های غیر لینوکسی فقط یک سوکت معمولی برمی‌گرداند
// (SO_REUSEPORT در دسترس نیست). recvBufBytes با SetReadBuffer اعمال می‌شود.
func listenUDPReusePort(addr string, recvBufBytes int) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, err
	}
	if recvBufBytes > 0 {
		_ = conn.SetReadBuffer(recvBufBytes)
	}
	return conn, nil
}
