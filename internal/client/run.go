package client

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"syscall"
	"sync/atomic"
	"time"

	"github.com/ultraspoof/ultraspoof/internal/applog"
	"github.com/ultraspoof/ultraspoof/internal/config"
	"github.com/ultraspoof/ultraspoof/internal/crypto"
	"github.com/ultraspoof/ultraspoof/internal/protocol"
	"github.com/ultraspoof/ultraspoof/internal/tunmod"
)

// isRecvTransient خطاهای موقت دریافت UDP (EAGAIN از poller Go).
func isRecvTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK) {
		return true
	}
	// بعضی نسخه‌ها پیام متنی برمی‌گردانند.
	msg := err.Error()
	return msg == "resource temporarily unavailable" || msg == "read: resource temporarily unavailable"
}

const (
	defaultRecvBufferBytes      = 32 * 1024 * 1024
	defaultSessionQueueSize     = 65536
	defaultUDPReadBufferBytes   = 2048 // اندازهٔ کافی برای MTU استاندارد + کمی جا
	defaultHubQueueSize         = 262144
	defaultClientTCPRecv        = 8 * 1024 * 1024
	defaultClientTCPSend        = 8 * 1024 * 1024
	defaultUserConnReadBufBytes = 64 * 1024
	defaultRecvBatchSize        = 64

	defaultNackTickMs       = 5
	defaultSkipCheckMs      = 25
	defaultStatsIntervalSec = 5
	defaultNackBudget       = 128 // حداکثر seq در یک فریم NACK در هر tick (<= MaxNackSeqsPerFrame)
	fastNackBudget          = 256 // با fast_recovery: حداکثر مجاز پروتکل
)

// Run اجرای حالت client: پروکسی محلی + کانال دانلود UDP.
func Run(cfg *config.Root) error {
	psk, err := cfg.PSKBytes()
	if err != nil {
		return err
	}
	c := cfg.Client
	lg := applog.New(cfg.LogLevel)
	if c.FastRecovery {
		lg.Infof("fast_recovery enabled: aggressive ARQ + shorter control TCP keepalive; override any download.* timer if needed")
	}

	plainMode := config.IsPlainEncryption(c.Download.Encryption)
	var aead cipher.AEAD
	if !plainMode {
		aead, err = crypto.NewUDPAEAD(psk)
		if err != nil {
			return fmt.Errorf("build aead: %w", err)
		}
	}

	hub, err := newUDPHub(aead, plainMode, c, lg)
	if err != nil {
		return err
	}
	lg.Debugf("UDP download listening on %s sockets=%d workers=%d batch=%d hub_queue=%d plain_mode=%v (filter source IP %s)",
		c.Download.ListenUDP, len(hub.conns), hub.workers, hub.recvBatchSize, cap(hub.pktCh), plainMode, c.Download.SpoofSourceIP)
	if plainMode {
		lg.Infof("UDP download running in AGGRESSIVE (plain) mode — no encryption, max throughput")
	}
	go func() {
		if err := hub.run(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("udp hub: %v", err)
		}
	}()

	if cfg.TunMod != nil && cfg.TunMod.Enabled {
		go func() {
			dialFn := func() (net.Conn, error) { return DialControlTransport(c) }
			if err := tunmod.RunClient(cfg, lg, dialFn); err != nil {
				lg.Infof("tunmod client stopped: %v", err)
			}
		}()
	}

	handler := func(userConn net.Conn, targetHost string, targetPort uint16) error {
		tuneClientTCP(userConn, defaultClientTCPRecv, defaultClientTCPSend, 0)
		err := runProxySession(cfg, hub, lg, userConn, targetHost, targetPort)
		peer := userConn.RemoteAddr().String()
		target := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))
		if err != nil && !errors.Is(err, io.EOF) {
			lg.Infof("session failed peer=%s target=%s err=%v", peer, target, err)
		} else {
			lg.Infof("session ok peer=%s target=%s", peer, target)
		}
		return err
	}

	errCh := make(chan error, 2)

	go func() {
		ln, err := net.Listen("tcp", c.Listen.SOCKS)
		if err != nil {
			errCh <- err
			return
		}
		lg.Debugf("SOCKS5 listening on %s", c.Listen.SOCKS)
		errCh <- serveSOCKS5(ln, lg, handler)
	}()

	if c.Listen.HTTP != "" {
		go func() {
			ln, err := net.Listen("tcp", c.Listen.HTTP)
			if err != nil {
				errCh <- err
				return
			}
			lg.Debugf("HTTP CONNECT listening on %s", c.Listen.HTTP)
			errCh <- serveHTTPConnect(ln, lg, handler)
		}()
	}

	return <-errCh
}

// udpEvt یک رویداد دیتا برای یک session (buf از payloadPool).
type udpEvt struct {
	seq  uint32
	buf  *[]byte
	data []byte
	fin  bool
}

// rawPacket یک بستهٔ خام که بین recv goroutine و worker goroutine رد می‌شود.
type rawPacket struct {
	buf  *[]byte
	size int
	src  net.UDPAddr
}

// sessionSub یک مشترک در hub برای یک session. شامل صف بسته‌ها و شمارندهٔ drop.
type sessionSub struct {
	ch         chan udpEvt
	queueDrops atomic.Uint64 // تعداد بستهٔ drop شده به دلیل پر بودن صف session
}

type sessionIDKey [16]byte

type udpHub struct {
	mu               sync.RWMutex
	subs             map[sessionIDKey]*sessionSub
	aead             cipher.AEAD
	plainMode        bool
	conns            []*net.UDPConn
	filterIP         net.IP
	bufPool          sync.Pool
	payloadPool      sync.Pool
	pktCh            chan rawPacket
	workers          int
	sessionQueueSize int
	recvBatchSize    int
	lg               *applog.Logger
}

func newUDPHub(aead cipher.AEAD, plainMode bool, c *config.ClientSpec, lg *applog.Logger) (*udpHub, error) {
	recvBuf := c.Download.SocketRecvBufferBytes
	if recvBuf <= 0 {
		recvBuf = defaultRecvBufferBytes
	}

	// پیش‌فرض ایمن: تنها یک سوکت UDP. بسیاری از کرنل‌ها/کانتینرها با SO_REUSEPORT
	// رفتار غیرمنتظره دارند. کاربر برای توزیع بار می‌تواند صریحاً recv_sockets>=2 بگذارد.
	numSockets := c.Download.RecvSockets
	if numSockets <= 0 {
		numSockets = 1
	}

	conns := make([]*net.UDPConn, 0, numSockets)
	for i := 0; i < numSockets; i++ {
		conn, err := listenUDPReusePort(c.Download.ListenUDP, recvBuf)
		if err != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			if i == 0 {
				return nil, err
			}
			lg.Debugf("could not open additional REUSEPORT socket #%d: %v (continuing with %d sockets)", i, err, len(conns))
			break
		}
		conns = append(conns, conn)
	}

	workers := c.Download.RecvWorkers
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers > 8 {
			workers = 8
		}
		if workers < 2 {
			workers = 2
		}
	}
	queueSize := c.Download.SessionQueueSize
	if queueSize <= 0 {
		queueSize = defaultSessionQueueSize
	}
	batchSize := c.Download.RecvBatchSize
	if batchSize <= 0 {
		batchSize = defaultRecvBatchSize
	}

	h := &udpHub{
		subs:             make(map[sessionIDKey]*sessionSub),
		aead:             aead,
		plainMode:        plainMode,
		conns:            conns,
		filterIP:         net.ParseIP(c.Download.SpoofSourceIP).To4(),
		pktCh:            make(chan rawPacket, defaultHubQueueSize),
		workers:          workers,
		sessionQueueSize: queueSize,
		recvBatchSize:    batchSize,
		lg:               lg,
	}
	h.bufPool.New = func() interface{} {
		b := make([]byte, defaultUDPReadBufferBytes)
		return &b
	}
	h.payloadPool.New = func() interface{} {
		b := make([]byte, 0, defaultUDPReadBufferBytes)
		return &b
	}
	return h, nil
}

// run حلقه‌های دریافت و worker های پردازش را راه‌اندازی می‌کند.
func (h *udpHub) run() error {
	var workerWg sync.WaitGroup
	for i := 0; i < h.workers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			h.workerLoop()
		}()
	}

	var recvWg sync.WaitGroup
	errCh := make(chan error, len(h.conns))
	for _, conn := range h.conns {
		recvWg.Add(1)
		go func(c *net.UDPConn) {
			defer recvWg.Done()
			errCh <- recvLoopBatched(c, h.recvBatchSize, defaultUDPReadBufferBytes, &h.bufPool, h.emit)
		}(conn)
	}

	firstErr := <-errCh
	for _, c := range h.conns {
		_ = c.Close()
	}
	go func() {
		for range errCh {
		}
	}()
	recvWg.Wait()
	close(errCh)
	close(h.pktCh)
	workerWg.Wait()
	return firstErr
}

// emit بستهٔ خام را روی کانال pktCh می‌گذارد (blocking send).
func (h *udpHub) emit(buf *[]byte, size int, src *net.UDPAddr) {
	h.pktCh <- rawPacket{buf: buf, size: size, src: *src}
}

// workerLoop یک worker است که از pktCh می‌خواند و هر بسته را پردازش می‌کند.
func (h *udpHub) workerLoop() {
	plainBuf := make([]byte, 0, defaultUDPReadBufferBytes)
	pbp := &plainBuf
	for raw := range h.pktCh {
		h.processPacket(raw.buf, raw.size, &raw.src, pbp)
		if raw.buf != nil {
			h.bufPool.Put(raw.buf)
		}
	}
}

// processPacket پردازش یک بستهٔ خام: filter، parse/decrypt، و dispatch به session.
func (h *udpHub) processPacket(buf *[]byte, size int, src *net.UDPAddr, plainBuf *[]byte) {
	if h.filterIP != nil {
		rip := src.IP.To4()
		if rip == nil || !rip.Equal(h.filterIP) {
			h.lg.Debugf("udp drop: filter mismatch src=%s (expected=%s)", src.IP.String(), h.filterIP.String())
			return
		}
	}
	pkt := (*buf)[:size]
	var (
		sid     []byte
		seq     uint32
		flags   byte
		payload []byte
		err     error
	)
	if h.plainMode {
		sid, seq, flags, payload, err = protocol.OpenUDPPacketPlain(pkt)
	} else {
		sid, seq, flags, payload, err = protocol.OpenUDPPacketWith(h.aead, pkt, plainBuf)
	}
	if err != nil {
		h.lg.Debugf("udp drop: decrypt/parse failed size=%d err=%v", size, err)
		return
	}
	fin := flags == protocol.FlagFIN
	var key sessionIDKey
	copy(key[:], sid)
	h.mu.RLock()
	sub, ok := h.subs[key]
	h.mu.RUnlock()
	if !ok {
		h.lg.Debugf("udp drop: unknown session=%x seq=%d flags=%d (no subscriber)", sid, seq, flags)
		return
	}
	pbp := h.payloadPool.Get().(*[]byte)
	pcopy := *pbp
	if cap(pcopy) < len(payload) {
		pcopy = make([]byte, len(payload))
	} else {
		pcopy = pcopy[:len(payload)]
	}
	copy(pcopy, payload)
	*pbp = pcopy
	select {
	case sub.ch <- udpEvt{seq: seq, buf: pbp, data: pcopy, fin: fin}:
	default:
		h.payloadPool.Put(pbp)
		sub.queueDrops.Add(1)
	}
}

func (h *udpHub) subscribe(sid []byte) *sessionSub {
	sub := &sessionSub{ch: make(chan udpEvt, h.sessionQueueSize)}
	var key sessionIDKey
	copy(key[:], sid)
	h.mu.Lock()
	h.subs[key] = sub
	h.mu.Unlock()
	return sub
}

func (h *udpHub) unsubscribe(sid []byte) {
	var key sessionIDKey
	copy(key[:], sid)
	h.mu.Lock()
	delete(h.subs, key)
	h.mu.Unlock()
}

// drainSessionUDPQueue رویدادهای مانده در صف session را دور می‌ریزد و buf را به pool برمی‌گرداند.
func drainSessionUDPQueue(ch <-chan udpEvt, payloadPool *sync.Pool) {
	for {
		select {
		case ev := <-ch:
			if ev.buf != nil && payloadPool != nil {
				payloadPool.Put(ev.buf)
			}
		default:
			return
		}
	}
}

// buildReassemblerConfig از کانفیگ کلاینت پارامترهای ARQ را استخراج می‌کند.
// مقادیر ۰ به پیش‌فرض‌های سالم برمی‌گردند؛ با fast_recovery پیش‌فرض‌های تهاجمی‌تر.
func buildReassemblerConfig(c *config.ClientSpec) reassemblerConfig {
	cfg := defaultReassemblerConfig()
	fr := c.FastRecovery
	if v := c.Download.NackIntervalMs; v > 0 {
		cfg.NackInterval = time.Duration(v) * time.Millisecond
	} else if fr {
		cfg.NackInterval = 15 * time.Millisecond
	}
	if v := c.Download.NackMaxTries; v > 0 {
		cfg.NackMaxTries = v
	} else if fr {
		cfg.NackMaxTries = 35
	}
	if v := c.Download.SkipTimeoutMs; v > 0 {
		cfg.SkipTimeout = time.Duration(v) * time.Millisecond
	} else if fr {
		// باید از NackInterval*NackMaxTries بزرگ‌تر باشد (۱۵×۳۵=۵۲۵ms).
		cfg.SkipTimeout = 700 * time.Millisecond
	}
	if v := c.Download.NackLookahead; v > 0 {
		cfg.NackLookahead = uint32(v)
	} else if fr {
		cfg.NackLookahead = 8192
	}
	if v := c.Download.MaxPendingPackets; v > 0 {
		cfg.MaxPending = v
	}
	return cfg
}

func runProxySession(cfg *config.Root, hub *udpHub, lg *applog.Logger, userConn net.Conn, targetHost string, targetPort uint16) error {
	c := cfg.Client
	peer := userConn.RemoteAddr().String()
	target := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))

	// در حالت direct، اتصال TCP کنترل مستقیم به remote زده می‌شود و هیچ SOCKS5
	// واسطی در مسیر نیست.
	direct := config.IsDirectUpstream(c.UpstreamSOCKS)

	var rawConn net.Conn
	var err error
	if direct {
		lg.Debugf("new session (direct) peer=%s target=%s remote=%s", peer, target, c.Remote)
	} else {
		lg.Debugf("new session peer=%s target=%s upstream=%s remote_tunnel=%s", peer, target, c.UpstreamSOCKS, c.Remote)
	}
	rawConn, err = DialControlTransport(c)
	if err != nil {
		return err
	}
	if direct {
		lg.Debugf("direct TCP connected local=%s remote=%s", rawConn.LocalAddr().String(), rawConn.RemoteAddr().String())
	} else {
		lg.Debugf("upstream SOCKS connected local=%s remote_chain=%s", rawConn.LocalAddr().String(), rawConn.RemoteAddr().String())
	}
	defer rawConn.Close()
	ctrlKeepAlive := 30 * time.Second
	if c.FastRecovery {
		ctrlKeepAlive = 8 * time.Second
	}
	tuneClientTCP(rawConn, defaultClientTCPRecv, defaultClientTCPSend, ctrlKeepAlive)
	ctrl := newControlConn(rawConn)

	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return err
	}

	// اشتراک در hub باید قبل از WriteOpen ثبت شود تا بسته‌های اولیهٔ UDP که
	// ممکن است بلافاصله پس از OpenOK سرور برسند، drop نشوند (race fix).
	sub := hub.subscribe(sessionID[:])
	defer func() {
		hub.unsubscribe(sessionID[:])
		// تخلیهٔ صف تا بافرهای payloadPool که دیگر مصرف‌کننده ندارند نشتی نکنند.
		drainSessionUDPQueue(sub.ch, &hub.payloadPool)
	}()

	// WriteOpen مستقیم (قبل از handshake هیچ goroutine دیگری روی rawConn نمی‌نویسد).
	if err := protocol.WriteOpen(rawConn, sessionID[:], targetHost, targetPort); err != nil {
		return err
	}
	cmd, _, payload, err := protocol.ReadFrame(rawConn)
	if err != nil {
		return err
	}
	switch cmd {
	case protocol.CmdOpenOK:
		lg.Debugf("remote open OK peer=%s target=%s session=%x", peer, target, sessionID)
	case protocol.CmdError:
		return fmt.Errorf("remote error: %s", string(payload))
	default:
		return fmt.Errorf("unexpected first frame cmd=%d", cmd)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reasmCfg := buildReassemblerConfig(c)
	reasm := newReassemblerWith(reasmCfg, &hub.payloadPool)
	errCh := make(chan error, 4)
	recvTimeout := c.ClientReceiveTimeout()

	nackTick := time.Duration(c.Download.NackTickMs) * time.Millisecond
	if nackTick <= 0 {
		if c.FastRecovery {
			nackTick = 2 * time.Millisecond
		} else {
			nackTick = defaultNackTickMs * time.Millisecond
		}
	}
	skipCheckInterval := time.Duration(c.Download.SkipCheckMs) * time.Millisecond
	if skipCheckInterval <= 0 {
		if c.FastRecovery {
			skipCheckInterval = 8 * time.Millisecond
		} else {
			skipCheckInterval = defaultSkipCheckMs * time.Millisecond
		}
	}
	nackBudget := defaultNackBudget
	if c.FastRecovery {
		nackBudget = fastNackBudget
	}
	statsInterval := time.Duration(c.Download.StatsIntervalSec) * time.Second
	if statsInterval <= 0 {
		statsInterval = defaultStatsIntervalSec * time.Second
	}

	go pumpUserToServer(ctx, userConn, ctrl, sessionID[:], errCh)
	go pumpServerControl(ctx, rawConn, errCh)
	go pumpUDPToUser(ctx, sub.ch, userConn, reasm, &hub.payloadPool, recvTimeout, skipCheckInterval, errCh)
	go pumpNackSender(ctx, ctrl, sessionID[:], reasm, nackTick, nackBudget, errCh)

	// stats logger (info level) — مصرف CPU و حافظه ناچیز دارد.
	if lg.Level() >= applog.LevelInfo && statsInterval > 0 {
		go sessionStatsLogger(ctx, lg, sessionID[:], reasm, sub, statsInterval)
	}

	err = <-errCh
	cancel()
	_ = rawConn.Close()
	_ = userConn.Close()

	// آخرین آمار session را log کن تا کاربر نتیجه‌ٔ نهایی را ببیند.
	if lg.Level() >= applog.LevelInfo {
		logSessionStatsFinal(lg, sessionID[:], reasm, sub)
	}

	// تخلیهٔ بافرهای معلق reassembler به pool (جلوگیری از leak هنگام پایان زودهنگام).
	reasm.releasePending(&hub.payloadPool)

	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func pumpUserToServer(ctx context.Context, user net.Conn, ctrl *controlConn, sessionID []byte, errCh chan<- error) {
	buf := make([]byte, defaultUserConnReadBufBytes)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := user.Read(buf)
		if n > 0 {
			if werr := ctrl.WriteData(sessionID, buf[:n]); werr != nil {
				errCh <- werr
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				_ = ctrl.WriteClose(sessionID)
				// با سیگنال EOF باعث خاتمهٔ سریع سایر pumpها می‌شویم.
				errCh <- io.EOF
				return
			}
			errCh <- err
			return
		}
	}
}

func pumpServerControl(ctx context.Context, remote net.Conn, errCh chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = remote.SetReadDeadline(time.Now().Add(90 * time.Second))
		cmd, _, payload, err := protocol.ReadFrame(remote)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if errors.Is(err, io.EOF) {
				errCh <- io.EOF
				return
			}
			errCh <- err
			return
		}
		if cmd == protocol.CmdError {
			errCh <- fmt.Errorf("remote error: %s", string(payload))
			return
		}
		// سایر cmdها در مسیر server→client روی TCP پشتیبانی نمی‌شوند؛ نادیده می‌گیریم.
	}
}

// pumpUDPToUser از صف session می‌خواند، از طریق reassembler ترتیب می‌دهد و روی
// userConn می‌نویسد. همچنین با یک ticker مستقل، MaybeSkip را صدا می‌زند تا حتی
// در نبود پکت تازه، اگر gap از skip_timeout گذشته باشد، stream stall نکند.
func pumpUDPToUser(ctx context.Context, ch <-chan udpEvt, user net.Conn, reasm *reassembler, payloadPool *sync.Pool, idle time.Duration, skipCheck time.Duration, errCh chan<- error) {
	firstWait := idle
	if firstWait < 5*time.Minute {
		firstWait = 10 * time.Minute
	}
	deadline := time.NewTimer(firstWait)
	defer deadline.Stop()

	skipTicker := time.NewTicker(skipCheck)
	defer skipTicker.Stop()

	first := true
	writeChunks := func(chunks []emit) error {
		for i, em := range chunks {
			if len(em.data) > 0 {
				if _, err := user.Write(em.data); err != nil {
					if em.buf != nil {
						payloadPool.Put(em.buf)
					}
					for j := i + 1; j < len(chunks); j++ {
						if chunks[j].buf != nil {
							payloadPool.Put(chunks[j].buf)
						}
					}
					return err
				}
			}
			if em.buf != nil {
				payloadPool.Put(em.buf)
			}
		}
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			first = false
			if !deadline.Stop() {
				select {
				case <-deadline.C:
				default:
				}
			}
			deadline.Reset(idle)
			chunks, done := reasm.Push(ev.seq, ev.buf, ev.data, ev.fin)
			if err := writeChunks(chunks); err != nil {
				errCh <- err
				return
			}
			if done {
				errCh <- io.EOF
				return
			}
		case <-skipTicker.C:
			// اگر gap طولانی شده، skip می‌کنیم تا stream stall نکند.
			chunks, done := reasm.MaybeSkip(time.Now())
			if len(chunks) > 0 {
				if err := writeChunks(chunks); err != nil {
					errCh <- err
					return
				}
				// پیشرفت داشتیم، deadline را هم refresh کن.
				if !deadline.Stop() {
					select {
					case <-deadline.C:
					default:
					}
				}
				deadline.Reset(idle)
			}
			if done {
				errCh <- io.EOF
				return
			}
		case <-deadline.C:
			if first {
				errCh <- errors.New("timeout waiting for first download UDP packet")
			} else {
				errCh <- errors.New("udp download idle timeout")
			}
			return
		}
	}
}

// pumpNackSender به‌صورت دوره‌ای از reassembler لیست seqهای گمشده را می‌گیرد
// و روی TCP کنترل به سرور می‌فرستد (CmdNack). بدون این goroutine، هر گم‌شدن
// UDP باعث stall دائمی تا skip_timeout می‌شود.
func pumpNackSender(ctx context.Context, ctrl *controlConn, sessionID []byte, reasm *reassembler, tick time.Duration, nackBudget int, errCh chan<- error) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			seqs := reasm.PickMissing(time.Now(), nackBudget)
			if len(seqs) == 0 {
				continue
			}
			if err := ctrl.WriteNack(sessionID, seqs); err != nil {
				// خطای نوشتن روی TCP کنترل = پایان session.
				errCh <- fmt.Errorf("nack write: %w", err)
				return
			}
		}
	}
}

// sessionStatsLogger هر statsInterval یک خط خلاصه از رفتار ARQ چاپ می‌کند.
// این برای عیب‌یابی سرعت حیاتی است: کاربر مستقیم می‌بیند nack_fill کار می‌کند یا نه.
func sessionStatsLogger(ctx context.Context, lg *applog.Logger, sessionID []byte, reasm *reassembler, sub *sessionSub, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	var prev reassemblerStatsSnapshot
	var prevQueueDrops uint64
	prevTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s := reasm.Stats()
			qd := sub.queueDrops.Load()
			dt := now.Sub(prevTime).Seconds()
			if dt <= 0 {
				dt = 1
			}
			bytesDelta := s.BytesEmitted - prev.BytesEmitted
			mbps := float64(bytesDelta) * 8 / 1e6 / dt
			lg.Infof("session=%x stats: mbps=%.2f recv=%d(+%d) ooo=%d(+%d) dup=%d(+%d) nack_sent=%d(+%d) nack_fill=%d(+%d) skipped=%d(+%d) pend_drop=%d(+%d) q_drop=%d(+%d) pending=%d",
				sessionID,
				mbps,
				s.RecvTotal, s.RecvTotal-prev.RecvTotal,
				s.RecvOOO, s.RecvOOO-prev.RecvOOO,
				s.RecvDup, s.RecvDup-prev.RecvDup,
				s.NackSent, s.NackSent-prev.NackSent,
				s.NackFilled, s.NackFilled-prev.NackFilled,
				s.Skipped, s.Skipped-prev.Skipped,
				s.PendingDrops, s.PendingDrops-prev.PendingDrops,
				qd, qd-prevQueueDrops,
				s.CurrentPending,
			)
			prev = s
			prevQueueDrops = qd
			prevTime = now
		}
	}
}

// logSessionStatsFinal آخرین خلاصه در پایان session.
func logSessionStatsFinal(lg *applog.Logger, sessionID []byte, reasm *reassembler, sub *sessionSub) {
	s := reasm.Stats()
	qd := sub.queueDrops.Load()
	lossPct := 0.0
	if s.RecvTotal > 0 {
		lossPct = float64(s.NackSent) * 100 / float64(s.RecvTotal+s.NackSent)
	}
	lg.Infof("session=%x final: recv=%d ooo=%d dup=%d nack_sent=%d nack_fill=%d skipped=%d pend_drop=%d q_drop=%d bytes=%d loss_est=%.2f%%",
		sessionID, s.RecvTotal, s.RecvOOO, s.RecvDup,
		s.NackSent, s.NackFilled, s.Skipped,
		s.PendingDrops, qd, s.BytesEmitted, lossPct)
}
