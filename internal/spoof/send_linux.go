//go:build linux

package spoof

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// SenderConfig تنظیمات راه‌اندازی Sender. مقادیر صفر/خالی به default های هوشمند برمی‌گردند.
type SenderConfig struct {
	// Iface اینترفیس شبکه برای SO_BINDTODEVICE (مثلاً "eth0"). خالی = انتخاب خودکار کرنل.
	Iface string
	// Workers تعداد raw socket fd که موازی نگه داشته می‌شوند تا قفل روی fd مشترک
	// از بین برود. توصیه: تعداد CPU. حداقل ۱.
	Workers int
	// SkipUDPChecksum اگر true باشد فیلد UDP checksum صفر گذاشته می‌شود (مجاز در IPv4)
	// و محاسبهٔ آن صرف‌نظر می‌شود. این یک برد بزرگ CPU است و چون AEAD صحت داده را
	// تضمین می‌کند، روی این تونل ایمن است.
	SkipUDPChecksum bool
	// SocketSendBufferBytes اندازهٔ SO_SNDBUF روی هر fd. صفر یعنی default داخلی (16MB).
	SocketSendBufferBytes int
}

// senderShard یک fd به همراه قفل خودش؛ هر shard مستقل از shardهای دیگر می‌فرستد.
type senderShard struct {
	fd int
	mu sync.Mutex
}

// Sender یک فرستندهٔ UDP/IPv4 با IP منبع جعلی و throughput بالا که از چندین raw fd
// به‌صورت موازی استفاده می‌کند تا contention روی یک fd واحد حذف شود.
type Sender struct {
	shards          []*senderShard
	iface           string
	skipUDPChecksum bool
	pktPool         sync.Pool
	rr              atomic.Uint64
	closeOnce       sync.Once
}

// NewSender با تنظیمات پیش‌فرض (یک fd، با محاسبهٔ checksum) Sender می‌سازد.
// برای حالت پرسرعت‌تر از NewSenderWithConfig استفاده کنید.
func NewSender(iface string) (*Sender, error) {
	return NewSenderWithConfig(SenderConfig{Iface: iface, Workers: 1, SkipUDPChecksum: false})
}

// NewSenderWithConfig یک Sender پیشرفته با تنظیمات کامل می‌سازد.
func NewSenderWithConfig(cfg SenderConfig) (*Sender, error) {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.SocketSendBufferBytes <= 0 {
		cfg.SocketSendBufferBytes = 16 * 1024 * 1024
	}

	shards := make([]*senderShard, 0, cfg.Workers)
	closeAll := func() {
		for _, sh := range shards {
			_ = unix.Close(sh.fd)
		}
	}
	for i := 0; i < cfg.Workers; i++ {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("raw socket: %w", err)
		}
		if cfg.Iface != "" {
			if err := unix.BindToDevice(fd, cfg.Iface); err != nil {
				_ = unix.Close(fd)
				closeAll()
				return nil, fmt.Errorf("bind to device %s: %w", cfg.Iface, err)
			}
		}
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, cfg.SocketSendBufferBytes)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, cfg.SocketSendBufferBytes)

		shards = append(shards, &senderShard{fd: fd})
	}

	s := &Sender{
		shards:          shards,
		iface:           cfg.Iface,
		skipUDPChecksum: cfg.SkipUDPChecksum,
	}
	s.pktPool.New = func() interface{} {
		b := make([]byte, 0, 2048)
		return &b
	}
	return s, nil
}

// Close بستن همهٔ fdها. ایمن برای فراخوانی چندباره.
func (s *Sender) Close() error {
	var firstErr error
	s.closeOnce.Do(func() {
		for _, sh := range s.shards {
			if err := unix.Close(sh.fd); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}

// pickShard انتخاب round-robin یک shard.
func (s *Sender) pickShard() *senderShard {
	if len(s.shards) == 1 {
		return s.shards[0]
	}
	idx := s.rr.Add(1) % uint64(len(s.shards))
	return s.shards[idx]
}

// SendUDP ساخت و ارسال یک بستهٔ UDP/IPv4 با IP منبع جعلی.
func (s *Sender) SendUDP(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) error {
	s4 := srcIP.To4()
	d4 := dstIP.To4()
	if s4 == nil || d4 == nil {
		return errors.New("only IPv4 supported")
	}
	bp := s.pktPool.Get().(*[]byte)
	pkt := buildIPv4UDPPacket((*bp)[:0], s4, d4, srcPort, dstPort, payload, s.skipUDPChecksum)
	defer func() {
		*bp = pkt[:0]
		s.pktPool.Put(bp)
	}()

	sa := &unix.SockaddrInet4{Addr: [4]byte{d4[0], d4[1], d4[2], d4[3]}}
	sh := s.pickShard()
	sh.mu.Lock()
	err := unix.Sendto(sh.fd, pkt, 0, sa)
	sh.mu.Unlock()
	if err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	return nil
}

// SendBatch ارسال چند بسته به همان مقصد در یک syscall sendmmsg (در صورت پشتیبانی).
// در یک shard ارسال می‌شود تا ترتیب درون batch حفظ شود.
func (s *Sender) SendBatch(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payloads [][]byte) error {
	if len(payloads) == 0 {
		return nil
	}
	s4 := srcIP.To4()
	d4 := dstIP.To4()
	if s4 == nil || d4 == nil {
		return errors.New("only IPv4 supported")
	}
	if len(payloads) == 1 {
		return s.SendUDP(srcIP, srcPort, dstIP, dstPort, payloads[0])
	}

	bps := make([]*[]byte, len(payloads))
	pkts := make([][]byte, len(payloads))
	for i, p := range payloads {
		bp := s.pktPool.Get().(*[]byte)
		bps[i] = bp
		pkts[i] = buildIPv4UDPPacket((*bp)[:0], s4, d4, srcPort, dstPort, p, s.skipUDPChecksum)
	}
	defer func() {
		for i := range bps {
			*bps[i] = pkts[i][:0]
			s.pktPool.Put(bps[i])
		}
	}()

	sh := s.pickShard()
	sh.mu.Lock()
	err := sendmmsgIPv4(sh.fd, d4, pkts)
	sh.mu.Unlock()
	return err
}

// buildIPv4UDPPacket سرآیند IPv4 + UDP را روی buf می‌سازد و slice پر شده را برمی‌گرداند.
func buildIPv4UDPPacket(buf []byte, s4, d4 net.IP, srcPort, dstPort uint16, payload []byte, skipUDPChecksum bool) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	if cap(buf) < totalLen {
		buf = make([]byte, totalLen)
	} else {
		buf = buf[:totalLen]
	}
	pkt := buf

	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0)
	pkt[8] = 64
	pkt[9] = unix.IPPROTO_UDP
	pkt[10] = 0
	pkt[11] = 0
	copy(pkt[12:16], s4)
	copy(pkt[16:20], d4)
	ipChecksum := ipHeaderChecksum(pkt[0:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum)

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	pkt[26] = 0
	pkt[27] = 0
	copy(pkt[28:], payload)

	if !skipUDPChecksum {
		udpChecksum := udpChecksumIPv4(s4, d4, pkt[20:totalLen])
		binary.BigEndian.PutUint16(pkt[26:28], udpChecksum)
	}
	// در IPv4 مقدار صفر در فیلد UDP checksum یعنی «بدون checksum» (مجاز توسط RFC 768).
	return pkt
}

func ipHeaderChecksum(header []byte) uint16 {
	var sum uint32
	n := len(header)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	if n%2 == 1 {
		sum += uint32(header[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksumIPv4(src, dst net.IP, udpPacket []byte) uint16 {
	var sum uint32
	s := src.To4()
	d := dst.To4()
	for i := 0; i < 4; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(s[i : i+2]))
	}
	for i := 0; i < 4; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(d[i : i+2]))
	}
	sum += uint32(unix.IPPROTO_UDP)
	sum += uint32(len(udpPacket))
	n := len(udpPacket)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpPacket[i : i+2]))
	}
	if n%2 == 1 {
		sum += uint32(udpPacket[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
