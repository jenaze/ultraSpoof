package client

import (
	"net"
	"time"
)

// tuneClientTCP اعمال TCP_NODELAY و بافرهای بزرگ بر کلاینت.
// روی کانال کنترل (به سرور ترکیه) و اتصال کاربر هر دو فراخوانی می‌شود.
// keepAlivePeriod ≤ 0 یعنی ۳۰ ثانیه (رفتار پیش‌فرض).
func tuneClientTCP(c net.Conn, recvBuf, sendBuf int, keepAlivePeriod time.Duration) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	if keepAlivePeriod <= 0 {
		keepAlivePeriod = 30 * time.Second
	}
	_ = tc.SetKeepAlivePeriod(keepAlivePeriod)
	if recvBuf > 0 {
		_ = tc.SetReadBuffer(recvBuf)
	}
	if sendBuf > 0 {
		_ = tc.SetWriteBuffer(sendBuf)
	}
}
