package connmanager

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ultraspoof/ultraspoof/internal/applog"
)

// Manager is responsible for tracking connections and closing idle ones.
type Manager struct {
	idleTimeout time.Duration
	interval    time.Duration
	conns       sync.Map
	lg          *applog.Logger
	done        chan struct{}
}

// New creates a new Manager.
// If deadConnIdleSec is 0, the manager is effectively disabled.
func New(deadConnIdleSec int, lg *applog.Logger) *Manager {
	if deadConnIdleSec <= 0 {
		return &Manager{}
	}

	m := &Manager{
		idleTimeout: time.Duration(deadConnIdleSec) * time.Second,
		interval:    time.Duration(deadConnIdleSec) * time.Second / 2,
		lg:          lg,
		done:        make(chan struct{}),
	}
	if m.interval < time.Second {
		m.interval = time.Second
	}

	go m.loop()

	return m
}

func (m *Manager) loop() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			timeoutNs := m.idleTimeout.Nanoseconds()

			m.conns.Range(func(key, value interface{}) bool {
				conn := value.(*TrackedConn)
				lastActivity := atomic.LoadInt64(&conn.lastActivity)

				if now-lastActivity > timeoutNs {
					if m.lg != nil && m.lg.Level() >= applog.LevelDebug {
						m.lg.Debugf("connmanager: closing idle connection %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
					}
					conn.Close()
					m.conns.Delete(key)
				}
				return true
			})
		}
	}
}

// Stop stops the background goroutine.
func (m *Manager) Stop() {
	if m.done != nil {
		close(m.done)
	}
}

// Track wraps a net.Conn with a TrackedConn and adds it to the manager.
// If the manager is disabled, it returns the original connection.
func (m *Manager) Track(conn net.Conn) net.Conn {
	if m.idleTimeout <= 0 {
		return conn
	}

	tc := &TrackedConn{
		Conn:         conn,
		m:            m,
		lastActivity: time.Now().UnixNano(),
	}
	m.conns.Store(tc, tc)
	return tc
}

// TrackedConn is a net.Conn that updates its last activity timestamp on read/write.
type TrackedConn struct {
	lastActivity int64 // Moved to top for 64-bit alignment on 32-bit architectures
	net.Conn
	m *Manager
}

func (tc *TrackedConn) Read(b []byte) (n int, err error) {
	n, err = tc.Conn.Read(b)
	if n > 0 {
		atomic.StoreInt64(&tc.lastActivity, time.Now().UnixNano())
	}
	return
}

func (tc *TrackedConn) Write(b []byte) (n int, err error) {
	n, err = tc.Conn.Write(b)
	if n > 0 {
		atomic.StoreInt64(&tc.lastActivity, time.Now().UnixNano())
	}
	return
}

func (tc *TrackedConn) Close() error {
	tc.m.conns.Delete(tc)
	return tc.Conn.Close()
}
