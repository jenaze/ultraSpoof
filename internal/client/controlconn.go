package client

import (
	"net"
	"sync"

	"github.com/ultraspoof/ultraspoof/internal/protocol"
)

// controlConn یک wrapper روی net.Conn است که همهٔ نوشتن‌های پروتکل را
// تحت یک mutex سریالیزه می‌کند. در هر session چند goroutine به صورت همزمان
// روی همان TCP می‌نویسند:
//
//   - pumpUserToServer → WriteData و WriteClose
//   - pumpNackSender    → WriteNack
//
// بدون mutex، دو Write همزمان از یک goroutine می‌توانند بایت‌های فریم‌ها را
// interleave کنند و سرور ErrBadMagic ببیند و اتصال را ببندد.
type controlConn struct {
	c  net.Conn
	mu sync.Mutex
}

// newControlConn wrapper را می‌سازد. conn همان net.Conn اصلی است.
func newControlConn(conn net.Conn) *controlConn {
	return &controlConn{c: conn}
}

// WriteData فریم DATA را اتمیک می‌نویسد.
func (cc *controlConn) WriteData(sessionID, payload []byte) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return protocol.WriteData(cc.c, sessionID, payload)
}

// WriteNack فریم NACK (درخواست retransmit) را اتمیک می‌نویسد.
func (cc *controlConn) WriteNack(sessionID []byte, seqs []uint32) error {
	if len(seqs) == 0 {
		return nil
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return protocol.WriteNack(cc.c, sessionID, seqs)
}

// WriteClose فریم CLOSE را اتمیک می‌نویسد.
func (cc *controlConn) WriteClose(sessionID []byte) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return protocol.WriteClose(cc.c, sessionID)
}

// Raw اشاره به net.Conn پایه برای ReadFrame / Close.
// ReadFrame همیشه از یک goroutine تک (pumpServerControl) صدا زده می‌شود، پس
// نیازی به قفل ندارد. Close هم thread-safe است روی net.TCPConn.
func (cc *controlConn) Raw() net.Conn {
	return cc.c
}
