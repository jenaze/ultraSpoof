package client

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ultraspoof/ultraspoof/internal/config"
)

// DialControlTransport همان مسیر TCP کنترل ultraSpoof را برقرار می‌کند:
// در صورت تنظیم upstream_socks از طریق SOCKS5 به remote، وگرنه dial مستقیم.
// برای tunmod و نشست‌های SOCKS از یک منطق استفاده می‌شود تا «مستقیم به سرور» دور زده نشود.
// با control_dial_retries پس از قطع موقت لینک واسط، dial تکرار می‌شود.
func DialControlTransport(c *config.ClientSpec) (net.Conn, error) {
	retries := c.ControlDialRetries
	if retries < 0 {
		retries = 0
	}
	interval := time.Duration(c.ControlDialRetryIntervalMs) * time.Millisecond
	if retries > 0 && interval <= 0 {
		interval = 200 * time.Millisecond
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			time.Sleep(interval)
		}
		conn, err := dialControlTransportOnce(c)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func dialControlTransportOnce(c *config.ClientSpec) (net.Conn, error) {
	direct := config.IsDirectUpstream(c.UpstreamSOCKS)
	if direct {
		conn, err := net.Dial("tcp", c.Remote)
		if err != nil {
			return nil, fmt.Errorf("direct dial remote: %w", err)
		}
		return conn, nil
	}
	remoteHost, remotePort, err := SplitHostPort(c.Remote)
	if err != nil {
		return nil, err
	}
	conn, err := DialSOCKS5TCP(strings.TrimSpace(c.UpstreamSOCKS), remoteHost, remotePort)
	if err != nil {
		return nil, fmt.Errorf("upstream socks dial: %w", err)
	}
	return conn, nil
}
