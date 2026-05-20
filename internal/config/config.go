package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// Mode مشخص می‌کند برنامه به‌عنوان client یا server اجرا شود.
type Mode string

const (
	ModeClient Mode = "client"
	ModeServer Mode = "server"
)

// Root تنظیمات ریشه برای هر دو حالت (فرمت فایل: JSON؛ پسوند می‌تواند .yaml باشد اگر محتوا JSON معتبر باشد).
type Root struct {
	Mode Mode   `json:"mode"`
	PSK  string `json:"psk"`
	// LogLevel: خالی یا off = بدون لاگ اتصال؛ info = موفق/ناموفل بودن؛ debug = جزئیات کامل اتصال‌ها.
	LogLevel string `json:"log_level,omitempty"`

	Client *ClientSpec `json:"client,omitempty"`
	Server *ServerSpec `json:"server,omitempty"`
	// TunMod لینک TUN نقطه‌به‌نقطه روی همان TCP کنترل (کلاینت از مسیر upstream_socks به remote وصل می‌شود).
	TunMod *TunModSpec `json:"tunmod,omitempty"`
}

// TunModSpec تنظیمات رابط TUN overlay بین دو طرف ultraSpoof.
type TunModSpec struct {
	Enabled           bool   `json:"enabled"`
	DeviceName        string `json:"device_name"`
	LocalCIDR         string `json:"local_cidr"`
	PeerCIDR          string `json:"peer_cidr"`
	MTU               int    `json:"mtu,omitempty"`
	KeepaliveSec      int    `json:"keepalive_sec,omitempty"`
	ReconnectDelaySec int    `json:"reconnect_delay_sec,omitempty"`
	// ReconnectDelayMs اگر بزرگ‌تر از صفر باشد، به‌جای reconnect_delay_sec برای فاصلهٔ
	// بین تلاش‌های اتصال مجدد tun استفاده می‌شود (مثلاً 50 برای reconnect تقریباً فوری).
	ReconnectDelayMs int `json:"reconnect_delay_ms,omitempty"`
}

type ClientSpec struct {
	Listen struct {
		SOCKS string `json:"socks"`
		HTTP  string `json:"http,omitempty"`
	} `json:"listen"`
	UpstreamSOCKS string `json:"upstream_socks"`
	Remote        string `json:"remote"`
	// FastRecovery اگر true باشد، برای فیلدهای download.* که صفر/خالی مانده‌اند
	// پارامترهای ARQ تهاجمی‌تری اعمال می‌شود (NACK سریع‌تر، keepalive کوتاه‌تر روی TCP کنترل).
	// برای استریم/دانلود روی لینک پر از loss مفید است؛ CPU و ترافیک NACK کمی بیشتر می‌شود.
	FastRecovery bool `json:"fast_recovery,omitempty"`
	// ControlDialRetries پس از خطای dial اولیه، این تعداد بار دیگر TCP کنترل زده می‌شود (۰ = همان یک تلاش).
	ControlDialRetries int `json:"control_dial_retries,omitempty"`
	// ControlDialRetryIntervalMs فاصله بین هر تلاش dial (میلی‌ثانیه). ۰ با retries>0 یعنی ۲۰۰ms.
	ControlDialRetryIntervalMs int `json:"control_dial_retry_interval_ms,omitempty"`
	Download      struct {
		ListenUDP      string `json:"listen_udp"`
		SpoofSourceIP  string `json:"spoof_source_ip"`
		ReceiveTimeout string `json:"receive_timeout,omitempty"`
		// SocketRecvBufferBytes اندازهٔ بافر دریافت سوکت UDP (SO_RCVBUF). برای throughput بالا
		// مقدار بزرگ (مثلاً 32MB) توصیه می‌شود تا burst ها در سمت ایران drop نشوند.
		SocketRecvBufferBytes int `json:"socket_recv_buffer_bytes,omitempty"`
		// RecvWorkers تعداد goroutine موازی برای رمزگشایی بسته‌های UDP. پیش‌فرض = NumCPU.
		RecvWorkers int `json:"recv_workers,omitempty"`
		// SessionQueueSize ظرفیت صف هر session قبل از drop شدن بسته‌ها.
		SessionQueueSize int `json:"session_queue_size,omitempty"`
		// RecvSockets تعداد سوکت UDP موازی که با SO_REUSEPORT روی همان پورت bind می‌شوند.
		// کرنل بسته‌ها را بر اساس hash توزیع می‌کند تا softirq روی چند CPU پخش شود.
		// پیش‌فرض = ۱ (ایمن). برای throughput بالاتر روی کرنل‌های مدرن می‌توانید
		// به 2-4 برسانید؛ ولی روی بعضی کانتینرها رفتار SO_REUSEPORT نامتعارف است.
		RecvSockets int `json:"recv_sockets,omitempty"`
		// RecvBatchSize حداکثر تعداد بستهٔ UDP که در یک فراخوانی recvmmsg دریافت می‌شوند
		// (در صورت دسترسی). پیش‌فرض ۶۴.
		RecvBatchSize int `json:"recv_batch_size,omitempty"`
		// Encryption نوع محافظت روی کانال UDP دانلود. مقادیر مجاز:
		//   "aead" (پیش‌فرض): AES-GCM، محرمانگی + صحت.
		//   "none":           بدون رمزنگاری، حداکثر سرعت (aggressive mode). سربار هر بسته
		//                     حدود 23 بایت به‌جای ~50 بایت AEAD، و CPU رمزگذاری حذف می‌شود.
		// این فیلد باید در هر دو سمت client/server یکسان باشد.
		Encryption string `json:"encryption,omitempty"`

		// ===== پارامترهای ARQ (NACK-based retransmit) =====
		// این پارامترها رفتار کلاینت هنگام گم شدن بستهٔ UDP را کنترل می‌کنند.
		// اگر سرور RetransmitBufferPackets>0 داشته باشد، این مکانیزم loss زیر ~10٪ را
		// به‌طور کامل پنهان می‌کند و هیچ stall در مسیر دانلود رخ نمی‌دهد.

		// NackIntervalMs حداقل فاصلهٔ زمانی (میلی‌ثانیه) بین NACKهای متوالی برای یک seq.
		// مقدار توصیه‌شده: کمی بزرگ‌تر از RTT (Iran-Turkey معمولاً 30-60ms → مقدار 30-40).
		// پیش‌فرض: 30.
		NackIntervalMs int `json:"nack_interval_ms,omitempty"`
		// NackMaxTries حداکثر تعداد NACK برای یک seq مشخص. پس از این، تنها راه بازیابی
		// رد شدن skip-timeout است. مقدار بالا = پایداری بیشتر در loss سنگین؛
		// مقدار پایین = کاهش ترافیک NACK در loss ماندگار (سرور بافر ندارد).
		// پیش‌فرض: 20 (یعنی ~600ms تلاش با interval=30).
		NackMaxTries int `json:"nack_max_tries,omitempty"`
		// SkipTimeoutMs پس از این مدت (میلی‌ثانیه) از اولین مشاهدهٔ gap، seq گمشده
		// کنار گذاشته می‌شود تا stream stall نکند. باید از NackIntervalMs*NackMaxTries
		// کمی بزرگ‌تر باشد.
		// پیش‌فرض: 1200 (یعنی 1.2 ثانیه).
		SkipTimeoutMs int `json:"skip_timeout_ms,omitempty"`
		// NackLookahead حداکثر فاصلهٔ seq نسبت به seq منتظر که در هر tick NACK بررسی
		// می‌شود. بزرگ بودن = تشخیص گم‌شدگی‌های دور ولی CPU بیشتر در tick.
		// پیش‌فرض: 4096.
		NackLookahead int `json:"nack_lookahead,omitempty"`
		// MaxPendingPackets سقف تعداد بستهٔ خارج از ترتیب نگه‌داشته در حافظه.
		// برای جلوگیری از blowup هنگام loss شدید و پیاپی.
		// پیش‌فرض: 32768 (حدود 40MB در MaxChunkSize=1400).
		MaxPendingPackets int `json:"max_pending_packets,omitempty"`
		// NackTickMs فاصلهٔ زمانی goroutine فرستندهٔ NACK. کوچک‌تر = واکنش سریع‌تر
		// به gap ولی syscall بیشتر. پیش‌فرض: 5.
		NackTickMs int `json:"nack_tick_ms,omitempty"`
		// SkipCheckMs فاصلهٔ زمانی بررسی skip-timeout در pumpUDPToUser. مقدار کوچک =
		// واکنش سریع به skip ولی overhead کمی بیشتر. پیش‌فرض: 25.
		SkipCheckMs int `json:"skip_check_ms,omitempty"`
		// StatsIntervalSec فاصلهٔ لاگ آمار ARQ هر session (۰ = غیرفعال).
		// روی log_level=info فعال است. پیش‌فرض: 5.
		StatsIntervalSec int `json:"stats_interval_sec,omitempty"`
	} `json:"download"`
	ProtocolVersion int `json:"protocol_version,omitempty"`
}

type ServerSpec struct {
	Listen struct {
		TCP string `json:"tcp"`
	} `json:"listen"`
	// UpstreamSOCKS اگر غیرخالی باشد، اتصال TCP سرور به مقصد هر session (پس از CmdOpen)
	// از طریق این پروکسی SOCKS5 برقرار می‌شود. "", "direct", "none" = dial مستقیم.
	UpstreamSOCKS string `json:"upstream_socks,omitempty"`
	// FastRecovery صف عمیق‌تر برای NACKهای پشت‌سرهم از کلاینت و keepalive کوتاه‌تر روی TCP
	// (کنترل و اتصال به مقصد) تا پاسخ retransmit کمتر گیر کند. همراه با retransmit_buffer_packets
	// روی دانلود و fast_recovery کلاینت استفاده شود.
	FastRecovery bool `json:"fast_recovery,omitempty"`
	Download struct {
		IranIP             string `json:"iran_ip"`
		IranUDPPort        int    `json:"iran_udp_port"`
		// UdpRelay اگر غیرخالی باشد، سرور دیگر raw spoof نمی‌زند؛ همان payload دانلود را با UDP عادی
		// به این آدرس (مثلاً IP_ترکیه:پورت_رله) می‌فرستد. روی سرور واسط باید DNAT به iran_ip:iran_udp_port
		// و SNAT به spoof_source_ip تنظیم شود تا کلاینت ایران همان فیلتر قبلی را ببیند.
		UdpRelay string `json:"udp_relay,omitempty"`
		SourceIP           string `json:"spoof_source_ip"`
		SpoofUDPSourcePort int    `json:"spoof_udp_source_port,omitempty"`
		Interface          string `json:"interface,omitempty"`
		MaxChunkSize       int    `json:"max_chunk_size,omitempty"`
		// TargetReadBufferBytes اندازهٔ بافر خواندن از مقصد TCP. مقادیر بزرگ (256KB-1MB)
		// تعداد syscall read را کاهش داده و throughput را به‌شدت افزایش می‌دهد.
		TargetReadBufferBytes int `json:"target_read_buffer_bytes,omitempty"`
		// SendBatchSize حداکثر تعداد بستهٔ UDP که در یک فراخوانی sendmmsg ارسال می‌شوند.
		SendBatchSize int `json:"send_batch_size,omitempty"`
		// SendWorkers تعداد raw socket fd موازی برای حذف contention روی یک fd مشترک.
		// پیش‌فرض = ۱ (ایمن). برای افزایش throughput می‌توانید تا NumCPU زیاد کنید.
		SendWorkers int `json:"send_workers,omitempty"`
		// SkipUDPChecksum اگر true باشد، UDP checksum صفر ارسال می‌شود (پیش‌فرض false).
		// true سرعت را حدود ۱۵-۲۰٪ بالا می‌برد ولی بعضی middleboxها/فایروال‌ها بسته را drop می‌کنند.
		// اگر کاملاً مطمئن هستید که مسیر UDP بدون checksum را قبول می‌کند، true بگذارید.
		SkipUDPChecksum *bool `json:"skip_udp_checksum,omitempty"`
		// SocketSendBufferBytes اندازهٔ SO_SNDBUF روی هر raw fd. پیش‌فرض ۱۶MB.
		SocketSendBufferBytes int `json:"socket_send_buffer_bytes,omitempty"`
		// PipelineSlots تعداد بافر در حلقهٔ double-buffer بین reader و sender در هر session.
		// پیش‌فرض ۴.
		PipelineSlots int `json:"pipeline_slots,omitempty"`
		// Encryption نوع محافظت روی کانال UDP دانلود. "aead" (پیش‌فرض) یا "none".
		// باید با مقدار سمت client یکسان باشد.
		Encryption string `json:"encryption,omitempty"`
		// MaxTotalMbps سقف کل نرخ ارسال UDP (Mbps) برای کل سرور، مشترک بین همهٔ session ها.
		// این مقدار باید کمی کمتر از ظرفیت واقعی لینک ایران تنظیم شود تا کرنل/ISP
		// سمت ایران دچار drop نشود. ۰ = نامحدود (فقط وقتی مطمئن هستید لینک ایران
		// ظرفیت کافی دارد). مثال: اگر لینک ایران 100Mbps است، مقدار 80 را بگذارید.
		MaxTotalMbps int `json:"max_total_mbps,omitempty"`
		// MaxSessionMbps سقف نرخ ارسال UDP هر session به‌تنهایی (Mbps). پیش‌فرض ۰ = نامحدود.
		// برای فرستادن عادلانه بین چند session همزمان مفید است.
		MaxSessionMbps int `json:"max_session_mbps,omitempty"`
		// RetransmitBufferPackets تعداد بسته‌ی اخیر هر session که برای پاسخ به
		// درخواست retransmit (CmdNack) از کلاینت نگه داشته می‌شود. ۰ یعنی
		// retransmit غیرفعال است (رفتار قدیمی بدون ARQ). مقدار توصیه‌شده 2048
		// تا 8192. هر slot حدود اندازهٔ یک بستهٔ UDP حافظه می‌گیرد؛ مثلاً 4096
		// به‌ازای هر session ≈ 5MB. برای مقابله با UDP loss در مسیرهای با نرخ
		// از دست رفتن قابل‌توجه، فعال کردن این گزینه بسیار توصیه می‌شود.
		RetransmitBufferPackets int `json:"retransmit_buffer_packets,omitempty"`
	} `json:"download"`
	ProtocolVersion int `json:"protocol_version,omitempty"`
}

// Load خواندن و اعتبارسنجی فایل کانفیگ (JSON).
func Load(path string) (*Root, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var root Root
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse config json: %w", err)
	}
	if err := root.Validate(); err != nil {
		return nil, err
	}
	normalizeLogLevel(&root)
	return &root, nil
}

func normalizeLogLevel(r *Root) {
	s := strings.ToLower(strings.TrimSpace(r.LogLevel))
	switch s {
	case "", "off", "none", "false":
		r.LogLevel = ""
	default:
		r.LogLevel = s
	}
}

// Validate اعتبارسنجی فیلدها.
func (r *Root) Validate() error {
	if r.Mode != ModeClient && r.Mode != ModeServer {
		return fmt.Errorf("mode must be %q or %q", ModeClient, ModeServer)
	}
	if err := validateLogLevel(r.LogLevel); err != nil {
		return err
	}
	if r.TunMod != nil && r.TunMod.Enabled {
		if runtime.GOOS != "linux" {
			return fmt.Errorf("tunmod.enabled requires Linux (current GOOS=%s)", runtime.GOOS)
		}
		if err := validateTunMod(r.TunMod); err != nil {
			return err
		}
	}
	psk, err := r.PSKBytes()
	if err != nil {
		return err
	}
	if len(psk) < 16 {
		return errors.New("psk must decode to at least 16 bytes (use base64 or longer raw secret)")
	}
	switch r.Mode {
	case ModeClient:
		if r.Client == nil {
			return errors.New("client section is required when mode=client")
		}
		return validateClient(r.Client)
	case ModeServer:
		if r.Server == nil {
			return errors.New("server section is required when mode=server")
		}
		return validateServer(r.Server)
	default:
		return nil
	}
}

func validateTunMod(t *TunModSpec) error {
	if strings.TrimSpace(t.DeviceName) == "" {
		return errors.New("tunmod.device_name is required when tunmod.enabled")
	}
	if len(t.DeviceName) >= 16 {
		return errors.New("tunmod.device_name must be shorter than 16 characters (Linux IFNAMSIZ)")
	}
	if _, localNet, err := net.ParseCIDR(strings.TrimSpace(t.LocalCIDR)); err != nil {
		return fmt.Errorf("tunmod.local_cidr: %w", err)
	} else if localNet.IP.To4() == nil {
		return errors.New("tunmod.local_cidr must be IPv4")
	}
	if _, peerNet, err := net.ParseCIDR(strings.TrimSpace(t.PeerCIDR)); err != nil {
		return fmt.Errorf("tunmod.peer_cidr: %w", err)
	} else if peerNet.IP.To4() == nil {
		return errors.New("tunmod.peer_cidr must be IPv4 for this build")
	}
	if t.MTU == 0 {
		t.MTU = 1400
	}
	if t.MTU < 576 || t.MTU > 65535 {
		return errors.New("tunmod.mtu must be between 576 and 65535")
	}
	if t.KeepaliveSec == 0 {
		t.KeepaliveSec = 20
	}
	if t.KeepaliveSec < 1 || t.KeepaliveSec > 86400 {
		return errors.New("tunmod.keepalive_sec must be 1-86400")
	}
	if t.ReconnectDelaySec < 0 || t.ReconnectDelaySec > 3600 {
		return errors.New("tunmod.reconnect_delay_sec must be 0-3600")
	}
	if t.ReconnectDelayMs < 0 || t.ReconnectDelayMs > 3_600_000 {
		return errors.New("tunmod.reconnect_delay_ms must be 0-3600000")
	}
	if t.ReconnectDelayMs == 0 && t.ReconnectDelaySec == 0 {
		t.ReconnectDelaySec = 3
	}
	return nil
}

func validateLogLevel(s string) error {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "off", "none", "false", "info", "debug":
		return nil
	default:
		return fmt.Errorf("log_level must be empty/off or %q or %q", "info", "debug")
	}
}

func validateClient(c *ClientSpec) error {
	if strings.TrimSpace(c.Listen.SOCKS) == "" {
		return errors.New("client.listen.socks is required")
	}
	if _, err := net.ResolveTCPAddr("tcp", c.Listen.SOCKS); err != nil {
		return fmt.Errorf("client.listen.socks: %w", err)
	}
	if c.Listen.HTTP != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.Listen.HTTP); err != nil {
			return fmt.Errorf("client.listen.http: %w", err)
		}
	}
	// upstream_socks اختیاری است. مقادیر "", "direct" یا "none" یعنی
	// اتصال TCP کنترل مستقیماً به remote بدون عبور از هیچ SOCKS5 واسط برقرار شود.
	// این حالت برای وقتی مفید است که سرور ایران مستقیم به IP عمومی ترکیه دسترسی دارد
	// و نیازی به تونل رمز (Xray/VLESS) نیست؛ در این حالت احتمال interleaving frameها
	// به‌دلیل mux در لایه‌های واسط صفر است.
	if !IsDirectUpstream(c.UpstreamSOCKS) {
		if _, err := net.ResolveTCPAddr("tcp", c.UpstreamSOCKS); err != nil {
			return fmt.Errorf("client.upstream_socks: %w", err)
		}
	}
	if strings.TrimSpace(c.Remote) == "" {
		return errors.New("client.remote is required")
	}
	if _, err := net.ResolveTCPAddr("tcp", c.Remote); err != nil {
		return fmt.Errorf("client.remote: %w", err)
	}
	if strings.TrimSpace(c.Download.ListenUDP) == "" {
		return errors.New("client.download.listen_udp is required")
	}
	if _, err := net.ResolveUDPAddr("udp", c.Download.ListenUDP); err != nil {
		return fmt.Errorf("client.download.listen_udp: %w", err)
	}
	if strings.TrimSpace(c.Download.SpoofSourceIP) == "" {
		return errors.New("client.download.spoof_source_ip is required (for packet filter)")
	}
	if net.ParseIP(c.Download.SpoofSourceIP) == nil {
		return errors.New("client.download.spoof_source_ip must be a valid IP")
	}
	if c.Download.SocketRecvBufferBytes < 0 {
		return errors.New("client.download.socket_recv_buffer_bytes must be >= 0")
	}
	if c.Download.RecvWorkers < 0 {
		return errors.New("client.download.recv_workers must be >= 0")
	}
	if c.Download.SessionQueueSize < 0 {
		return errors.New("client.download.session_queue_size must be >= 0")
	}
	if c.Download.RecvSockets < 0 {
		return errors.New("client.download.recv_sockets must be >= 0")
	}
	if c.Download.RecvSockets > 64 {
		return errors.New("client.download.recv_sockets must be <= 64")
	}
	if c.Download.RecvBatchSize < 0 {
		return errors.New("client.download.recv_batch_size must be >= 0")
	}
	if c.Download.RecvBatchSize > 1024 {
		return errors.New("client.download.recv_batch_size must be <= 1024")
	}
	if err := validateEncryption(c.Download.Encryption); err != nil {
		return fmt.Errorf("client.download.encryption: %w", err)
	}
	if c.Download.NackIntervalMs < 0 {
		return errors.New("client.download.nack_interval_ms must be >= 0")
	}
	if c.Download.NackIntervalMs > 10000 {
		return errors.New("client.download.nack_interval_ms must be <= 10000")
	}
	if c.Download.NackMaxTries < 0 {
		return errors.New("client.download.nack_max_tries must be >= 0")
	}
	if c.Download.NackMaxTries > 1000 {
		return errors.New("client.download.nack_max_tries must be <= 1000")
	}
	if c.Download.SkipTimeoutMs < 0 {
		return errors.New("client.download.skip_timeout_ms must be >= 0")
	}
	if c.Download.NackLookahead < 0 {
		return errors.New("client.download.nack_lookahead must be >= 0")
	}
	if c.Download.NackLookahead > 1_000_000 {
		return errors.New("client.download.nack_lookahead must be <= 1000000")
	}
	if c.Download.MaxPendingPackets < 0 {
		return errors.New("client.download.max_pending_packets must be >= 0")
	}
	if c.Download.NackTickMs < 0 {
		return errors.New("client.download.nack_tick_ms must be >= 0")
	}
	if c.Download.SkipCheckMs < 0 {
		return errors.New("client.download.skip_check_ms must be >= 0")
	}
	if c.Download.StatsIntervalSec < 0 {
		return errors.New("client.download.stats_interval_sec must be >= 0")
	}
	if c.ControlDialRetries < 0 || c.ControlDialRetries > 30 {
		return errors.New("client.control_dial_retries must be 0-30")
	}
	if c.ControlDialRetryIntervalMs < 0 || c.ControlDialRetryIntervalMs > 120_000 {
		return errors.New("client.control_dial_retry_interval_ms must be 0-120000")
	}
	if c.ProtocolVersion == 0 {
		c.ProtocolVersion = 1
	}
	return nil
}

// validateEncryption مقادیر مجاز فیلد encryption را چک می‌کند.
func validateEncryption(s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "aead", "none":
		return nil
	default:
		return fmt.Errorf("encryption must be \"aead\" or \"none\", got %q", s)
	}
}

// IsPlainEncryption برمی‌گرداند آیا پیکربندی حالت بدون رمزنگاری (plain) است.
func IsPlainEncryption(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "none")
}

// IsDirectUpstream نشان می‌دهد آیا upstream_socks به معنای اتصال مستقیم بدون SOCKS5
// است. مقادیر معتبر برای این حالت: رشتهٔ خالی، "direct"، "none".
func IsDirectUpstream(s string) bool {
	v := strings.ToLower(strings.TrimSpace(s))
	return v == "" || v == "direct" || v == "none"
}

func validateServer(s *ServerSpec) error {
	if strings.TrimSpace(s.Listen.TCP) == "" {
		return errors.New("server.listen.tcp is required")
	}
	if _, err := net.ResolveTCPAddr("tcp", s.Listen.TCP); err != nil {
		return fmt.Errorf("server.listen.tcp: %w", err)
	}
	if !IsDirectUpstream(s.UpstreamSOCKS) {
		if _, err := net.ResolveTCPAddr("tcp", s.UpstreamSOCKS); err != nil {
			return fmt.Errorf("server.upstream_socks: %w", err)
		}
	}
	if strings.TrimSpace(s.Download.IranIP) == "" {
		return errors.New("server.download.iran_ip is required")
	}
	if net.ParseIP(s.Download.IranIP) == nil {
		return errors.New("server.download.iran_ip must be a valid IP")
	}
	if s.Download.IranUDPPort <= 0 || s.Download.IranUDPPort > 65535 {
		return errors.New("server.download.iran_udp_port must be 1-65535")
	}
	if strings.TrimSpace(s.Download.SourceIP) == "" {
		return errors.New("server.download.spoof_source_ip is required")
	}
	if net.ParseIP(s.Download.SourceIP) == nil {
		return errors.New("server.download.spoof_source_ip must be a valid IP")
	}
	if s.Download.MaxChunkSize == 0 {
		// مقدار محافظه‌کارانه برای جلوگیری از fragmentation روی مسیرهایی که MTU<1500 دارند.
		// برای سرعت بیشتر، در کانفیگ می‌توانید 1400 بگذارید.
		s.Download.MaxChunkSize = 1200
	}
	if s.Download.MaxChunkSize < 256 || s.Download.MaxChunkSize > 60000 {
		return errors.New("server.download.max_chunk_size should be between 256 and 60000")
	}
	if s.Download.TargetReadBufferBytes < 0 {
		return errors.New("server.download.target_read_buffer_bytes must be >= 0")
	}
	if s.Download.SendBatchSize < 0 {
		return errors.New("server.download.send_batch_size must be >= 0")
	}
	if s.Download.SendBatchSize > 1024 {
		return errors.New("server.download.send_batch_size must be <= 1024")
	}
	if s.Download.SendWorkers < 0 {
		return errors.New("server.download.send_workers must be >= 0")
	}
	if s.Download.SendWorkers > 64 {
		return errors.New("server.download.send_workers must be <= 64")
	}
	if s.Download.SocketSendBufferBytes < 0 {
		return errors.New("server.download.socket_send_buffer_bytes must be >= 0")
	}
	if s.Download.PipelineSlots < 0 {
		return errors.New("server.download.pipeline_slots must be >= 0")
	}
	if s.Download.MaxTotalMbps < 0 {
		return errors.New("server.download.max_total_mbps must be >= 0")
	}
	if s.Download.MaxSessionMbps < 0 {
		return errors.New("server.download.max_session_mbps must be >= 0")
	}
	if err := validateEncryption(s.Download.Encryption); err != nil {
		return fmt.Errorf("server.download.encryption: %w", err)
	}
	if s.Download.RetransmitBufferPackets < 0 {
		return errors.New("server.download.retransmit_buffer_packets must be >= 0")
	}
	if s.Download.RetransmitBufferPackets > 1_048_576 {
		return errors.New("server.download.retransmit_buffer_packets must be <= 1048576")
	}
	if s.ProtocolVersion == 0 {
		s.ProtocolVersion = 1
	}
	if strings.TrimSpace(s.Download.UdpRelay) != "" {
		if _, err := net.ResolveUDPAddr("udp", strings.TrimSpace(s.Download.UdpRelay)); err != nil {
			return fmt.Errorf("server.download.udp_relay: %w", err)
		}
	}
	return nil
}

// PSKBytes کلید خام PSK را برمی‌گرداند (base64 یا رشتهٔ UTF-8).
func (r *Root) PSKBytes() ([]byte, error) {
	s := strings.TrimSpace(r.PSK)
	if s == "" {
		return nil, errors.New("psk is required")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	return []byte(s), nil
}

// ClientReceiveTimeout مدت انتظار برای دریافت قطعات UDP.
func (c *ClientSpec) ClientReceiveTimeout() time.Duration {
	if c.Download.ReceiveTimeout == "" {
		return 120 * time.Second
	}
	d, err := time.ParseDuration(c.Download.ReceiveTimeout)
	if err != nil {
		return 120 * time.Second
	}
	return d
}
