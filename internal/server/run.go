package server

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ultraspoof/ultraspoof/internal/applog"
	sockbridge "github.com/ultraspoof/ultraspoof/internal/client"
	"github.com/ultraspoof/ultraspoof/internal/config"
	"github.com/ultraspoof/ultraspoof/internal/connmanager"
	"github.com/ultraspoof/ultraspoof/internal/crypto"
	"github.com/ultraspoof/ultraspoof/internal/protocol"
	"github.com/ultraspoof/ultraspoof/internal/spoof"
	"github.com/ultraspoof/ultraspoof/internal/tunmod"
)

// udpDownloadSender انتزاع ارسال کانال دانلود: raw spoof یا UDP معمولی به رلهٔ میانی.
type udpDownloadSender interface {
	SendBatch(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payloads [][]byte) error
	SendUDP(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) error
	Close() error
}

// مقادیر پیش‌فرض برای throughput بسیار بالا (هدف: اشباع پهنای باند).
const (
	defaultTargetReadBufBytes = 128 * 1024
	defaultSendBatchSize      = 64
	defaultPipelineSlots      = 4
	defaultTCPRecvBuf         = 8 * 1024 * 1024
	defaultTCPSendBuf         = 8 * 1024 * 1024
	defaultTargetTCPBuf       = 8 * 1024 * 1024
	defaultSocketSendBuffer   = 16 * 1024 * 1024

	defaultRetxBufferPackets = 0 // 0 = غیرفعال تا کاربر در کانفیگ فعال کند
	defaultStatsIntervalSec  = 5

	defaultNackChDepth          = 256
	fastRecoveryNackChDepth     = 2048 // جلوگیری از drop شدن NACK وقتی کلاینت تهاجمی NACK می‌فرستد
	fastRecoveryTCPKeepalive    = 8 * time.Second
)

// Run اجرای حالت server روی ترکیه.
func Run(cfg *config.Root) error {
	psk, err := cfg.PSKBytes()
	if err != nil {
		return err
	}
	s := cfg.Server
	lg := applog.New(cfg.LogLevel)

	connMgr := connmanager.New(cfg.DeadConnIdleSec, lg)
	defer connMgr.Stop()

	plainMode := config.IsPlainEncryption(s.Download.Encryption)
	var aead cipher.AEAD
	if !plainMode {
		aead, err = crypto.NewUDPAEAD(psk)
		if err != nil {
			return fmt.Errorf("build aead: %w", err)
		}
	}

	var dlSender udpDownloadSender
	if relayStr := strings.TrimSpace(s.Download.UdpRelay); relayStr != "" {
		relayAddr, err := net.ResolveUDPAddr("udp", relayStr)
		if err != nil {
			return fmt.Errorf("resolve udp_relay: %w", err)
		}
		workers := s.Download.SendWorkers
		if workers <= 0 {
			workers = 1
		}
		sndBuf := s.Download.SocketSendBufferBytes
		if sndBuf <= 0 {
			sndBuf = defaultSocketSendBuffer
		}
		dlSender, err = newRelayUDPSender(relayAddr, workers, sndBuf, strings.TrimSpace(s.Download.Interface))
		if err != nil {
			return fmt.Errorf("init udp relay sender: %w", err)
		}
		lg.Infof("UDP download via relay %s (raw spoof disabled here; SNAT/DNAT required on relay hop)", relayAddr.String())
	} else {
		senderCfg := buildSenderConfig(s)
		spoofS, err := spoof.NewSenderWithConfig(senderCfg)
		if err != nil {
			return fmt.Errorf("init spoof sender: %w", err)
		}
		dlSender = spoofS
		lg.Debugf("spoof sender ready: workers=%d skip_udp_checksum=%v plain_mode=%v", senderCfg.Workers, senderCfg.SkipUDPChecksum, plainMode)
	}
	defer func() { _ = dlSender.Close() }()
	if plainMode {
		lg.Infof("UDP download running in AGGRESSIVE (plain) mode — no encryption, max throughput")
	}

	var totalLimiter *tokenBucket
	if s.Download.MaxTotalMbps > 0 {
		bps := int64(s.Download.MaxTotalMbps) * 1_000_000 / 8
		totalLimiter = newTokenBucket(bps, 0)
		lg.Infof("server-wide rate limit: %d Mbps (all sessions combined)", s.Download.MaxTotalMbps)
	} else {
		lg.Infof("WARNING: no server-wide rate limit set — may overrun Iran link and cause heavy UDP drops")
	}

	ln, err := net.Listen("tcp", s.Listen.TCP)
	if err != nil {
		return err
	}
	lg.Debugf("server TCP listening on %s", s.Listen.TCP)
	iranIP := net.ParseIP(s.Download.IranIP).To4()
	spoofIP := net.ParseIP(s.Download.SourceIP).To4()
	if iranIP == nil || spoofIP == nil {
		return errors.New("iran_ip and spoof_source_ip must be IPv4")
	}

	retxCap := s.Download.RetransmitBufferPackets
	if retxCap == 0 {
		retxCap = defaultRetxBufferPackets
	}
	if retxCap > 0 {
		lg.Infof("retransmit buffer enabled: %d packets per-session (NACK-based ARQ)", retxCap)
	} else {
		lg.Infof("WARNING: retransmit buffer disabled — any UDP loss stalls client reassembler until skip_timeout")
	}
	if s.FastRecovery {
		lg.Infof("server fast_recovery: deep NACK queue, shorter TCP keepalive on control/target dials")
		if retxCap == 0 {
			lg.Infof("hint: set server.download.retransmit_buffer_packets so NACKs can be answered (client fast_recovery needs retx on server)")
		}
	}

	if !config.IsDirectUpstream(s.UpstreamSOCKS) {
		lg.Infof("target TCP dial via upstream SOCKS5 %s", strings.TrimSpace(s.UpstreamSOCKS))
	}

	var tunSessionGate tunGate
	ctrlKeepAlive := time.Duration(0)
	if s.FastRecovery {
		ctrlKeepAlive = fastRecoveryTCPKeepalive
	}

	readBufSize := s.Download.TargetReadBufferBytes
	if readBufSize <= 0 {
		readBufSize = defaultTargetReadBufBytes
	}
	readBufPool := &sync.Pool{
		New: func() interface{} {
			b := make([]byte, readBufSize)
			return &b
		},
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		tuneServerTCP(c, defaultTCPRecvBuf, defaultTCPSendBuf, ctrlKeepAlive)
		c = connMgr.Track(c)
		go func(conn net.Conn) {
			defer conn.Close()
			peer := conn.RemoteAddr().String()
			lg.Debugf("server accept from %s", peer)
			err := handleConn(aead, plainMode, dlSender, cfg, lg, conn, iranIP, spoofIP, totalLimiter, retxCap, &tunSessionGate, readBufPool, connMgr)
			if err != nil && !errors.Is(err, io.EOF) {
				if lg.Level() >= applog.LevelInfo {
					lg.Infof("connection closed peer=%s err=%v", peer, err)
				} else {
					log.Printf("connection error: %v", err)
				}
			} else if lg.Level() >= applog.LevelInfo {
				lg.Infof("connection closed peer=%s", peer)
			}
		}(c)
	}
}

// buildSenderConfig defaults هوشمند برای Sender.
func buildSenderConfig(s *config.ServerSpec) spoof.SenderConfig {
	workers := s.Download.SendWorkers
	if workers <= 0 {
		workers = 1
	}
	skip := false
	if s.Download.SkipUDPChecksum != nil {
		skip = *s.Download.SkipUDPChecksum
	}
	sndBuf := s.Download.SocketSendBufferBytes
	if sndBuf <= 0 {
		sndBuf = defaultSocketSendBuffer
	}
	return spoof.SenderConfig{
		Iface:                 s.Download.Interface,
		Workers:               workers,
		SkipUDPChecksum:       skip,
		SocketSendBufferBytes: sndBuf,
	}
}

// sessionState نگهداری وضعیت هر session مسیر کنترل روی یک TCP مشترک.
// علاوه بر هدف TCP، retxRing برای پاسخ به NACK و نیز context برای خاتمهٔ
// goroutine هندلر NACK دارد.
type sessionState struct {
	sessionID []byte
	target    net.Conn
	seq       uint32 // فقط در pump یک گوروتین استفاده می‌شود
	closed    atomic.Bool

	// برای retransmit سرور→کلاینت روی UDP spoofed.
	retx     *retxRing
	iranIP   net.IP
	spoofIP  net.IP
	dstPort  uint16
	fallbackSrcPort uint16 // پورت منبع ثابت اگر در کانفیگ set شده باشد؛ ۰ یعنی dynamic

	// goroutine هندلر NACK: ورودی از nackCh، خاتمه با nackCtx.
	nackCh     chan []uint32
	nackCancel context.CancelFunc

	// آمار session (lock-free).
	nackFramesReceived atomic.Uint64 // تعداد فریم NACK دریافت‌شده از کلاینت
	nackSeqsRequested  atomic.Uint64 // مجموع seq های درخواست‌شده در NACK
	bytesSent          atomic.Uint64 // بایت‌های UDP payload ارسال‌شده (برای مبنای mbps)
}

func handleConn(aead cipher.AEAD, plainMode bool, sender udpDownloadSender, cfg *config.Root, lg *applog.Logger, client net.Conn, iranIP net.IP, spoofIP net.IP, totalLimiter *tokenBucket, retxCap int, tunGate *tunGate, readBufPool *sync.Pool, connMgr *connmanager.Manager) error {
	s := cfg.Server
	peer := client.RemoteAddr().String()

	firstCmd, firstSessionID, firstPayload, err := protocol.ReadFrame(client)
	if err != nil {
		return err
	}

	if firstCmd == protocol.CmdTunRegister {
		if cfg.TunMod == nil || !cfg.TunMod.Enabled {
			_ = protocol.WriteError(client, "tunmod is not enabled on this server")
			lg.Debugf("tun register rejected peer=%s (disabled)", peer)
			return nil
		}
		if !tunGate.tryEnter() {
			_ = protocol.WriteError(client, "tun session already active")
			lg.Debugf("tun register rejected peer=%s (busy)", peer)
			return nil
		}
		defer tunGate.exit()
		if len(firstPayload) < 1 || firstPayload[0] != 1 {
			_ = protocol.WriteError(client, "unsupported tun register protocol version")
			return fmt.Errorf("bad tun register version from %s", peer)
		}
		tunErr := tunmod.ServeTunSession(cfg, lg, client, firstPayload)
		if tunErr != nil && !errors.Is(tunErr, io.EOF) {
			lg.Debugf("tunmod session peer=%s err=%v", peer, tunErr)
		}
		return tunErr
	}

	sessions := make(map[string]*sessionState)
	var mu sync.Mutex

	closeSession := func(key string) {
		mu.Lock()
		sess, ok := sessions[key]
		if ok {
			delete(sessions, key)
		}
		mu.Unlock()
		if ok && sess.closed.CompareAndSwap(false, true) {
			if sess.nackCancel != nil {
				sess.nackCancel()
			}
			_ = sess.target.Close()
		}
	}

	defer func() {
		mu.Lock()
		snapshot := make([]*sessionState, 0, len(sessions))
		for k, sess := range sessions {
			snapshot = append(snapshot, sess)
			delete(sessions, k)
		}
		mu.Unlock()
		for _, sess := range snapshot {
			if sess.closed.CompareAndSwap(false, true) {
				if sess.nackCancel != nil {
					sess.nackCancel()
				}
				_ = sess.target.Close()
			}
		}
	}()

	primed := true
	for {
		var cmd byte
		var sessionID, payload []byte
		var err error
		if primed {
			cmd, sessionID, payload = firstCmd, firstSessionID, firstPayload
			primed = false
		} else {
			cmd, sessionID, payload, err = protocol.ReadFrame(client)
			if err != nil {
				return err
			}
		}

		key := string(sessionID)

		switch cmd {
		case protocol.CmdOpen:
			host, port, err := protocol.ParseOpenPayload(payload)
			if err != nil {
				lg.Debugf("bad open payload peer=%s err=%v", peer, err)
				_ = protocol.WriteError(client, err.Error())
				continue
			}
			targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
			lg.Debugf("open request peer=%s target=%s session=%x", peer, targetAddr, sessionID)

			mu.Lock()
			_, dup := sessions[key]
			mu.Unlock()
			if dup {
				lg.Debugf("duplicate open for session=%x peer=%s, dropping", sessionID, peer)
				continue
			}

			var dial net.Conn
			var dialErr error
			if config.IsDirectUpstream(s.UpstreamSOCKS) {
				dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
				dial, dialErr = dialer.Dial("tcp", targetAddr)
			} else {
				th, tp, serr := sockbridge.SplitHostPort(targetAddr)
				if serr != nil {
					lg.Debugf("split target addr peer=%s target=%s err=%v", peer, targetAddr, serr)
					_ = protocol.WriteError(client, serr.Error())
					continue
				}
				dial, dialErr = sockbridge.DialSOCKS5TCP(strings.TrimSpace(s.UpstreamSOCKS), th, tp)
			}
			if dialErr != nil {
				lg.Debugf("dial target failed peer=%s target=%s err=%v", peer, targetAddr, dialErr)
				_ = protocol.WriteError(client, dialErr.Error())
				continue
			}
			targetKeepAlive := time.Duration(0)
			if s.FastRecovery {
				targetKeepAlive = fastRecoveryTCPKeepalive
			}
			tuneServerTCP(dial, defaultTargetTCPBuf, defaultTargetTCPBuf, targetKeepAlive)
			dial = connMgr.Track(dial)
			lg.Debugf("dial target ok peer=%s target=%s local=%s session=%x", peer, targetAddr, dial.LocalAddr().String(), sessionID)

			nackCtx, nackCancel := context.WithCancel(context.Background())
			nackDepth := defaultNackChDepth
			if s.FastRecovery {
				nackDepth = fastRecoveryNackChDepth
			}
			sess := &sessionState{
				sessionID:       append([]byte(nil), sessionID...),
				target:          dial,
				retx:            newRetxRing(retxCap),
				iranIP:          iranIP,
				spoofIP:         spoofIP,
				dstPort:         uint16(s.Download.IranUDPPort),
				fallbackSrcPort: uint16(s.Download.SpoofUDPSourcePort),
				nackCh:          make(chan []uint32, nackDepth),
				nackCancel:      nackCancel,
			}
			mu.Lock()
			sessions[key] = sess
			mu.Unlock()

			// هندلر NACK: از nackCh می‌خواند و retransmit می‌کند.
			go handleSessionNacks(nackCtx, sess, sender, lg)

			// stats logger (در info) — رفتار retx و loss را منعکس می‌کند.
			statsInterval := time.Duration(defaultStatsIntervalSec) * time.Second
			if lg.Level() >= applog.LevelInfo && statsInterval > 0 {
				go sessionStatsLoggerServer(nackCtx, lg, sess, statsInterval)
			}

			if err := protocol.WriteOpenOK(client, sessionID); err != nil {
				closeSession(key)
				return err
			}

			var sessionLimiter *tokenBucket
			if s.Download.MaxSessionMbps > 0 {
				bps := int64(s.Download.MaxSessionMbps) * 1_000_000 / 8
				sessionLimiter = newTokenBucket(bps, 0)
			}

			go func(sess *sessionState) {
				err := pumpTargetToIranPipelined(aead, plainMode, sender, s, sess, totalLimiter, sessionLimiter, readBufPool)
				if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					lg.Debugf("target pump ended peer=%s session=%x err=%v", peer, sess.sessionID, err)
				}
				// خلاصهٔ نهایی session.
				if lg.Level() >= applog.LevelInfo {
					logSessionStatsFinalServer(lg, sess)
				}
				mu.Lock()
				if current, ok := sessions[string(sess.sessionID)]; ok && current == sess {
					delete(sessions, string(sess.sessionID))
				}
				mu.Unlock()
				if sess.closed.CompareAndSwap(false, true) {
					if sess.nackCancel != nil {
						sess.nackCancel()
					}
					_ = sess.target.Close()
				}
			}(sess)

		case protocol.CmdData:
			mu.Lock()
			sess, ok := sessions[key]
			mu.Unlock()
			if !ok {
				lg.Debugf("data for unknown session=%x peer=%s (dropped %d bytes)", sessionID, peer, len(payload))
				continue
			}
			if _, werr := sess.target.Write(payload); werr != nil {
				lg.Debugf("target write failed session=%x err=%v", sessionID, werr)
				closeSession(key)
			}

		case protocol.CmdClose:
			lg.Debugf("close request session=%x peer=%s", sessionID, peer)
			closeSession(key)

		case protocol.CmdNack:
			mu.Lock()
			sess, ok := sessions[key]
			mu.Unlock()
			if !ok {
				lg.Debugf("nack for unknown session=%x peer=%s", sessionID, peer)
				continue
			}
			seqs, perr := protocol.ParseNackPayload(payload)
			if perr != nil {
				lg.Debugf("bad nack payload session=%x err=%v", sessionID, perr)
				continue
			}
			sess.nackFramesReceived.Add(1)
			sess.nackSeqsRequested.Add(uint64(len(seqs)))
			// ارسال non-blocking به هندلر NACK؛ در فشار شدید NACK drop می‌شود.
			select {
			case sess.nackCh <- seqs:
			default:
				lg.Debugf("nack channel full session=%x, dropping %d seqs", sessionID, len(seqs))
			}

		default:
			lg.Debugf("ignoring unknown cmd=%d session=%x peer=%s", cmd, sessionID, peer)
		}
	}
}

// handleSessionNacks goroutine مخصوص پاسخ به NACKهای یک session. از nackCh
// لیست seq می‌خواند و برای هر seq از retxRing پکت را برمی‌دارد و دوباره
// با همان IP/پورت spoofed می‌فرستد.
func handleSessionNacks(ctx context.Context, sess *sessionState, sender udpDownloadSender, lg *applog.Logger) {
	if sess.retx == nil {
		// retransmit غیرفعال است؛ فقط تا پایان ctx NACKها را بلعیدنی می‌کنیم.
		for {
			select {
			case <-ctx.Done():
				return
			case <-sess.nackCh:
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case seqs := <-sess.nackCh:
			if len(seqs) == 0 {
				continue
			}
			pkts := make([][]byte, len(seqs))
			count, srcPort := sess.retx.LookupBatch(seqs, pkts)
			if count == 0 {
				continue
			}
			if srcPort == 0 {
				srcPort = 35000 + uint16(seqs[0]%30000)
			}
			if err := sender.SendBatch(sess.spoofIP, srcPort, sess.iranIP, sess.dstPort, pkts[:count]); err != nil {
				lg.Debugf("retx batch send failed session=%x n=%d: %v", sess.sessionID, count, err)
			}
		}
	}
}

// batchSlot نگهدارندهٔ چند بستهٔ آمادهٔ ارسال (سیل‌شده) برای یک batch.
type batchSlot struct {
	scratches []*[]byte // فضای کاری ازپیش‌تخصیص‌یافتهٔ هر بسته
	pkts      [][]byte  // slice های اشاره‌کننده داخل scratches (سیل‌شده)
	seqs      []uint32  // seq هر بسته (برای ذخیره در retxRing پس از ارسال)
	srcPort   uint16    // پورت منبع برای کل batch
	fin       bool      // اگر این batch شامل بستهٔ FIN است
}

// pumpTargetToIranPipelined: نسخهٔ pipelined با double-buffering و retx.
//
// پس از ارسال موفق هر batch، همهٔ پکت‌ها در retxRing session ذخیره می‌شوند تا
// در صورت رسیدن NACK، فوراً دوباره فرستاده شوند.
func pumpTargetToIranPipelined(aead cipher.AEAD, plainMode bool, sender udpDownloadSender, s *config.ServerSpec, sess *sessionState, totalLimiter, sessionLimiter *tokenBucket, readBufPool *sync.Pool) error {
	target := sess.target
	sessionID := sess.sessionID
	seq := &sess.seq

	var overhead int
	if plainMode {
		overhead = protocol.UDPPlainModeOverhead
	} else {
		overhead = protocol.UDPOverhead
	}
	maxPlain := s.Download.MaxChunkSize - overhead
	if maxPlain < 256 {
		maxPlain = s.Download.MaxChunkSize - 64
	}
	if maxPlain < 256 {
		maxPlain = 1300
	}

	readBufSize := s.Download.TargetReadBufferBytes
	if readBufSize <= 0 {
		readBufSize = defaultTargetReadBufBytes
	}
	batchSize := s.Download.SendBatchSize
	if batchSize <= 0 {
		batchSize = defaultSendBatchSize
	}
	slotsCount := s.Download.PipelineSlots
	if slotsCount <= 0 {
		slotsCount = defaultPipelineSlots
	}

	freeSlots := make(chan *batchSlot, slotsCount)
	filledSlots := make(chan *batchSlot, slotsCount)
	for i := 0; i < slotsCount; i++ {
		bs := &batchSlot{
			scratches: make([]*[]byte, batchSize),
			pkts:      make([][]byte, batchSize),
			seqs:      make([]uint32, batchSize),
		}
		for j := 0; j < batchSize; j++ {
			b := make([]byte, 0, s.Download.MaxChunkSize+protocol.UDPOverhead+udpPlainPaddingHint)
			bs.scratches[j] = &b
		}
		freeSlots <- bs
	}

	dstPort := uint16(s.Download.IranUDPPort)
	cfgSrcPort := uint16(s.Download.SpoofUDPSourcePort)

	senderErrCh := make(chan error, 1)
	var senderDone sync.WaitGroup
	senderDone.Add(1)

	// goroutine ارسال‌کننده.
	go func() {
		defer senderDone.Done()
		var firstErr error
		for slot := range filledSlots {
			if firstErr == nil && slot.pkts[0] != nil {
				count := slotPktCount(slot)
				batchBytes := 0
				for i := 0; i < count; i++ {
					batchBytes += len(slot.pkts[i]) + 28
				}
				if totalLimiter != nil {
					totalLimiter.Wait(batchBytes)
				}
				if sessionLimiter != nil {
					sessionLimiter.Wait(batchBytes)
				}
				err := sender.SendBatch(sess.spoofIP, slot.srcPort, sess.iranIP, dstPort, slot.pkts[:count])
				if err != nil {
					firstErr = err
				} else {
					// ذخیره در retxRing برای پاسخ به NACKهای آینده.
					// توجه: باید قبل از reset slot انجام شود چون slot.pkts بعداً
					// توسط slot جدید بازنویسی می‌شود.
					if sess.retx != nil {
						for i := 0; i < count; i++ {
							sess.retx.Store(slot.seqs[i], slot.srcPort, slot.pkts[i])
						}
					}
					// آمار بایت‌های ارسال‌شده برای mbps.
					for i := 0; i < count; i++ {
						sess.bytesSent.Add(uint64(len(slot.pkts[i])))
					}
				}
			}
			for k := range slot.pkts {
				slot.pkts[k] = nil
			}
			freeSlots <- slot
		}
		if firstErr != nil {
			senderErrCh <- firstErr
		}
		close(senderErrCh)
	}()

	readBufPtr := readBufPool.Get().(*[]byte)
	readBuf := *readBufPtr
	if cap(readBuf) < readBufSize {
		readBuf = make([]byte, readBufSize)
	} else {
		readBuf = readBuf[:readBufSize]
	}
	defer func() {
		*readBufPtr = readBuf
		readBufPool.Put(readBufPtr)
	}()

	var loopErr error

readLoop:
	for {
		_ = target.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, err := target.Read(readBuf)
		if n > 0 {
			data := readBuf[:n]
			for len(data) > 0 {
				slot := <-freeSlots
				k := 0
				for len(data) > 0 && k < batchSize {
					sz := maxPlain
					if sz > len(data) {
						sz = len(data)
					}
					chunk := data[:sz]
					seqVal := *seq
					*seq++
					var pkt []byte
					if plainMode {
						pkt = protocol.SealUDPPacketPlain(slot.scratches[k], sessionID, seqVal, protocol.FlagData, chunk)
					} else {
						pkt = protocol.SealUDPPacketWith(aead, slot.scratches[k], sessionID, seqVal, protocol.FlagData, chunk)
					}
					slot.pkts[k] = pkt
					slot.seqs[k] = seqVal
					k++
					data = data[sz:]
				}
				for j := k; j < batchSize; j++ {
					slot.pkts[j] = nil
					slot.seqs[j] = 0
				}
				srcPort := cfgSrcPort
				if srcPort == 0 {
					srcPort = 35000 + uint16(*seq%30000)
				}
				slot.srcPort = srcPort
				filledSlots <- slot
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				slot := <-freeSlots
				var pkt []byte
				finSeq := *seq
				if plainMode {
					pkt = protocol.SealUDPPacketPlain(slot.scratches[0], sessionID, finSeq, protocol.FlagFIN, nil)
				} else {
					pkt = protocol.SealUDPPacketWith(aead, slot.scratches[0], sessionID, finSeq, protocol.FlagFIN, nil)
				}
				*seq++
				slot.pkts[0] = pkt
				slot.seqs[0] = finSeq
				for j := 1; j < batchSize; j++ {
					slot.pkts[j] = nil
					slot.seqs[j] = 0
				}
				srcPort := cfgSrcPort
				if srcPort == 0 {
					srcPort = 35000 + uint16(*seq%30000)
				}
				slot.srcPort = srcPort
				filledSlots <- slot
				loopErr = io.EOF
				break readLoop
			}
			loopErr = err
			break readLoop
		}
	}

	close(filledSlots)
	senderDone.Wait()
	if serr, ok := <-senderErrCh; ok && serr != nil {
		return serr
	}
	return loopErr
}

// slotPktCount شمارش بسته‌های معتبر داخل یک slot.
func slotPktCount(slot *batchSlot) int {
	for i, p := range slot.pkts {
		if p == nil {
			return i
		}
	}
	return len(slot.pkts)
}

// udpPlainPaddingHint فضای اضافی scratch برای پوشش plaintext کنار ciphertext.
const udpPlainPaddingHint = 64

// sessionStatsLoggerServer آمار لحظه‌ای session سمت سرور را دوره‌ای چاپ می‌کند.
// روی info level فعال است و به کاربر نشان می‌دهد چند NACK رسیده، چند hit/miss در
// retxRing داشته و throughput واقعی چقدر بوده.
func sessionStatsLoggerServer(ctx context.Context, lg *applog.Logger, sess *sessionState, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	var prevStored, prevHits, prevMisses, prevBytes uint64
	var prevFrames, prevSeqs uint64
	prevTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			stored, hits, misses := sess.retx.Stats()
			bytes := sess.bytesSent.Load()
			frames := sess.nackFramesReceived.Load()
			seqs := sess.nackSeqsRequested.Load()
			dt := now.Sub(prevTime).Seconds()
			if dt <= 0 {
				dt = 1
			}
			mbps := float64(bytes-prevBytes) * 8 / 1e6 / dt
			lg.Infof("session=%x server stats: mbps=%.2f sent=%d(+%d) retx_hit=%d(+%d) retx_miss=%d(+%d) nack_frames=%d(+%d) nack_seqs=%d(+%d) retx_cap=%d",
				sess.sessionID, mbps,
				stored, stored-prevStored,
				hits, hits-prevHits,
				misses, misses-prevMisses,
				frames, frames-prevFrames,
				seqs, seqs-prevSeqs,
				sess.retx.Cap(),
			)
			prevStored, prevHits, prevMisses = stored, hits, misses
			prevBytes = bytes
			prevFrames, prevSeqs = frames, seqs
			prevTime = now
		}
	}
}

// logSessionStatsFinalServer خلاصه آخر session سمت سرور.
func logSessionStatsFinalServer(lg *applog.Logger, sess *sessionState) {
	stored, hits, misses := sess.retx.Stats()
	frames := sess.nackFramesReceived.Load()
	seqs := sess.nackSeqsRequested.Load()
	bytes := sess.bytesSent.Load()
	hitRate := 0.0
	if hits+misses > 0 {
		hitRate = float64(hits) * 100 / float64(hits+misses)
	}
	lg.Infof("session=%x server final: bytes=%d stored=%d retx_hit=%d retx_miss=%d hit_rate=%.1f%% nack_frames=%d nack_seqs=%d",
		sess.sessionID, bytes, stored, hits, misses, hitRate, frames, seqs)
}
