package server

import (
	"net"
	"time"
)

// tuneServerTCP اعمال تنظیمات سرعت روی TCPConn:
//   - TCP_NODELAY برای کاهش تاخیر مسیر کنترل و رله
//   - SetReadBuffer / SetWriteBuffer برای بازکردن پنجرهٔ throughput
//   - KeepAlive برای تشخیص سریع‌تر اتصالات مرده
// keepAlivePeriod ≤ 0 یعنی ۳۰ ثانیه.
func tuneServerTCP(c net.Conn, recvBuf, sendBuf int, keepAlivePeriod time.Duration) {
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
