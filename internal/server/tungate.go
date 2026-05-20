package server

import "sync"

// tunGate حداکثر یک نشست TUN فعال روی سرور را تضمین می‌کند.
type tunGate struct {
	mu   sync.Mutex
	held bool
}

func (g *tunGate) tryEnter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.held {
		return false
	}
	g.held = true
	return true
}

func (g *tunGate) exit() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.held = false
}
