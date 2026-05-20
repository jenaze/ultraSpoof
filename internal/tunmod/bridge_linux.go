//go:build linux

package tunmod

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ultraspoof/ultraspoof/internal/applog"
	"github.com/ultraspoof/ultraspoof/internal/config"
	"github.com/ultraspoof/ultraspoof/internal/protocol"
)

// tunConnWriter سریال‌سازی نوشتن روی TCP تا فریم‌ها قاطی نشوند.
type tunConnWriter struct {
	mu sync.Mutex
	c  net.Conn
}

func (w *tunConnWriter) writeTunData(packet []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return protocol.WriteTunData(w.c, packet)
}

func (w *tunConnWriter) writeKeepalive() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return protocol.WriteTunKeepalive(w.c)
}

func (w *tunConnWriter) writeReady() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return protocol.WriteTunReady(w.c)
}

func tuneTunSideTCP(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	const buf = 8 * 1024 * 1024
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)
	_ = tc.SetReadBuffer(buf)
	_ = tc.SetWriteBuffer(buf)
}

// pumpTunToConn از TUN می‌خواند و روی TCP می‌فرستد.
func pumpTunToConn(tun io.Reader, tw *tunConnWriter, mtu int, lg *applog.Logger) error {
	buf := make([]byte, mtu+64)
	for {
		n, err := tun.Read(buf)
		if n > 0 {
			if err := tw.writeTunData(buf[:n]); err != nil {
				return err
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// pumpConnToTun فریم‌های tun را از TCP می‌خواند و به TUN می‌نویسد.
func pumpConnToTun(conn net.Conn, tun io.Writer, lg *applog.Logger, keepaliveSec int) error {
	idle := time.Duration(keepaliveSec*3) * time.Second
	if idle < 90*time.Second {
		idle = 90 * time.Second
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		cmd, _, payload, err := protocol.ReadFrame(conn)
		if err != nil {
			return err
		}
		switch cmd {
		case protocol.CmdTunData:
			if len(payload) == 0 {
				continue
			}
			if _, werr := tun.Write(payload); werr != nil {
				return werr
			}
		case protocol.CmdTunKeepalive:
			// بدون echo تا حلقهٔ بی‌پایان keepalive بین دو طرف پیش نیاید؛ هر طرف با ticker خودش می‌فرستد.
		default:
			lg.Debugf("tunmod: unexpected tcp cmd=%d (ignored)", cmd)
		}
	}
}

func runKeepaliveTicker(tw *tunConnWriter, every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = tw.writeKeepalive()
		}
	}
}

// tunReconnectDelay فاصلهٔ sleep پس از قطع tun قبل از dial مجدد.
func tunReconnectDelay(t *config.TunModSpec) time.Duration {
	if t.ReconnectDelayMs > 0 {
		return time.Duration(t.ReconnectDelayMs) * time.Millisecond
	}
	return time.Duration(t.ReconnectDelaySec) * time.Second
}

// RunClient حلقهٔ اتصال مجدد: هر بار از dial() همان مسیر upstream استفاده می‌شود.
func RunClient(cfg *config.Root, lg *applog.Logger, dial func() (net.Conn, error)) error {
	t := cfg.TunMod
	if t == nil || !t.Enabled {
		return nil
	}
	delay := tunReconnectDelay(t)
	keepEvery := time.Duration(t.KeepaliveSec) * time.Second
	for {
		err := runClientOnce(cfg, lg, dial, keepEvery)
		if err != nil {
			lg.Infof("tunmod client: session ended: %v", err)
		}
		time.Sleep(delay)
	}
}

func runClientOnce(cfg *config.Root, lg *applog.Logger, dial func() (net.Conn, error), keepEvery time.Duration) error {
	t := cfg.TunMod
	conn, err := dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	tuneTunSideTCP(conn)

	if err := protocol.WriteTunRegister(conn); err != nil {
		return err
	}
	cmd, _, payload, err := protocol.ReadFrame(conn)
	if err != nil {
		return err
	}
	if cmd == protocol.CmdError {
		return fmt.Errorf("server error: %s", string(payload))
	}
	if cmd != protocol.CmdTunReady {
		return fmt.Errorf("unexpected first cmd %d (want TunReady)", cmd)
	}

	tunFile, err := openTUN(t.DeviceName)
	if err != nil {
		return err
	}
	defer tunFile.Close()

	if err := configureTUNLink(context.Background(), t.DeviceName, t.LocalCIDR, t.MTU); err != nil {
		lg.Infof("tunmod: ip configuration failed (need root/CAP_NET_ADMIN?): %v", err)
		return err
	}

	tw := &tunConnWriter{c: conn}
	stopKA := make(chan struct{})
	defer close(stopKA)
	go runKeepaliveTicker(tw, keepEvery, stopKA)

	errCh := make(chan error, 2)
	go func() {
		errCh <- pumpTunToConn(tunFile, tw, t.MTU, lg)
	}()
	go func() {
		errCh <- pumpConnToTun(conn, tunFile, lg, t.KeepaliveSec)
	}()
	return <-errCh
}

// ServeTunSession پس از CmdTunRegister؛ gate را caller آزاد می‌کند.
func ServeTunSession(cfg *config.Root, lg *applog.Logger, conn net.Conn, regPayload []byte) error {
	t := cfg.TunMod
	if len(regPayload) < 1 || regPayload[0] != 1 {
		return fmt.Errorf("unsupported tun register version")
	}
	tuneTunSideTCP(conn)
	tw := &tunConnWriter{c: conn}
	if err := tw.writeReady(); err != nil {
		return err
	}

	tunFile, err := openTUN(t.DeviceName)
	if err != nil {
		return err
	}
	defer tunFile.Close()

	if err := configureTUNLink(context.Background(), t.DeviceName, t.LocalCIDR, t.MTU); err != nil {
		lg.Infof("tunmod: ip configuration failed (need root/CAP_NET_ADMIN?): %v", err)
		return err
	}

	stopKA := make(chan struct{})
	defer close(stopKA)
	go runKeepaliveTicker(tw, time.Duration(t.KeepaliveSec)*time.Second, stopKA)

	errCh := make(chan error, 2)
	go func() {
		errCh <- pumpTunToConn(tunFile, tw, t.MTU, lg)
	}()
	go func() {
		errCh <- pumpConnToTun(conn, tunFile, lg, t.KeepaliveSec)
	}()
	return <-errCh
}
