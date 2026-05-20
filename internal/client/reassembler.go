package client

import (
	"sync"
	"sync/atomic"
	"time"
)

// pendingChunk یک قطعهٔ خارج از ترتیب در انتظار seq گمشده.
// buf اشاره به pool slot است و data یک slice از *buf با طول دقیق payload.
type pendingChunk struct {
	buf  *[]byte
	data []byte
	fin  bool
}

// emit یک chunk آمادهٔ نوشتن به userConn است.
// مصرف‌کننده پس از Write باید buf را به pool مناسب برگرداند تا allocation
// در hot path حذف شود. اگر buf nil باشد، هیچ pool return ای لازم نیست.
type emit struct {
	buf  *[]byte
	data []byte
}

// reassemblerConfig رفتار ARQ را پیکربندی می‌کند. همهٔ مقادیر مثبت باید باشند.
type reassemblerConfig struct {
	// MaxPending سقف تعداد chunk در صف خارج‌از‌ترتیب. وقتی رد شود، جدیدترین seq
	// (دورترین از next) قربانی می‌شود تا پذیرش بسته‌های نزدیک به next (که مهم‌ترند
	// برای drain سریع) مختل نشود.
	MaxPending int
	// NackInterval حداقل فاصلهٔ زمانی بین NACKهای متوالی برای یک seq مشخص.
	// معمولاً کمی بزرگ‌تر از RTT (مثلاً 40ms برای Iran-Turkey).
	NackInterval time.Duration
	// NackMaxTries حداکثر تعداد NACK برای یک seq. پس از این، seq فقط با
	// skip-timeout پاک می‌شود (جلوگیری از NACK طوفان روی بسته‌ای که سرور بافر
	// ندارد).
	NackMaxTries int
	// SkipTimeout بعد از این مدت از اولین مشاهدهٔ gap، اگر seq=next هنوز نرسیده
	// باشد، از آن صرف‌نظر می‌شود تا stream stall نکند. حتماً باید از
	// NackInterval*NackMaxTries بیشتر باشد.
	SkipTimeout time.Duration
	// NackLookahead حداکثر فاصلهٔ seq نسبت به next که PickMissing در آن به
	// دنبال seqهای گمشده می‌گردد. بزرگ بودن این مقدار = هزینهٔ CPU بیشتر در
	// هر tick ولی تشخیص زودتر گم‌شدگی‌های دور.
	NackLookahead uint32
}

func defaultReassemblerConfig() reassemblerConfig {
	return reassemblerConfig{
		MaxPending:    32768,
		NackInterval:  30 * time.Millisecond,
		NackMaxTries:  20,
		SkipTimeout:   1200 * time.Millisecond,
		NackLookahead: 4096,
	}
}

// reassemblerStats شمارنده‌های lock-free برای مشاهدهٔ رفتار زنده.
type reassemblerStats struct {
	recvTotal     atomic.Uint64 // کل پکت‌های دریافتی (in-order + out-of-order + dup)
	recvOOO       atomic.Uint64 // پکت‌هایی که جلوتر از next بودند (gap ایجاد کردند)
	recvDup       atomic.Uint64 // پکت‌های تکراری یا قدیمی‌تر از next
	nackSent      atomic.Uint64 // مجموع seqهای NACK شده (هر تکرار جدا شمرده می‌شود)
	nackFilled    atomic.Uint64 // seqهایی که پس از NACK رسیدند (گم‌شدهٔ بازیابی‌شده)
	skipped       atomic.Uint64 // seqهایی که با skip-timeout کنار گذاشته شدند
	pendingDrops  atomic.Uint64 // حذف از pending به دلیل رد شدن از MaxPending
	bytesEmitted  atomic.Uint64 // بایت‌های نوشته‌شده به userConn (برای mbps)
	currentPending int64        // اندازهٔ فعلی pending (تقریبی، فقط گزارش)
}

// reassembler بازسازی ترتیب seq برای استریم دانلود با پشتیبانی از ARQ.
//
// payloadPool برای بازگرداندن بافرهای قربانی هنگام overflow sacrifice استفاده
// می‌شود؛ بدون آن، MaxPending overflow باعث leak بافر می‌شود.
type reassembler struct {
	mu sync.Mutex

	next         uint32                  // اولین seq که هنوز emit نشده
	pending      map[uint32]pendingChunk // seq → chunk معطل
	highestSeen  uint32                  // بالاترین seq دریافت‌شده تاکنون
	haveHigh     bool                    // آیا highestSeen معتبر است
	gapNoticedAt time.Time               // زمان اولین مشاهدهٔ gap فعلی (zero = بدون gap)
	nackLastAt   map[uint32]time.Time    // آخرین زمان NACK برای هر seq
	nackCount    map[uint32]int          // تعداد NACK ارسال‌شده برای هر seq

	cfg         reassemblerConfig
	payloadPool *sync.Pool

	stats *reassemblerStats
}

func newReassembler(pool *sync.Pool) *reassembler {
	return newReassemblerWith(defaultReassemblerConfig(), pool)
}

func newReassemblerWith(cfg reassemblerConfig, pool *sync.Pool) *reassembler {
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 32768
	}
	if cfg.NackInterval <= 0 {
		cfg.NackInterval = 30 * time.Millisecond
	}
	if cfg.NackMaxTries <= 0 {
		cfg.NackMaxTries = 20
	}
	if cfg.SkipTimeout <= 0 {
		cfg.SkipTimeout = 1200 * time.Millisecond
	}
	if cfg.NackLookahead == 0 {
		cfg.NackLookahead = 4096
	}
	return &reassembler{
		pending:     make(map[uint32]pendingChunk),
		nackLastAt:  make(map[uint32]time.Time),
		nackCount:   make(map[uint32]int),
		cfg:         cfg,
		payloadPool: pool,
		stats:       &reassemblerStats{},
	}
}

// Push یک بستهٔ دریافتی را به reassembler می‌دهد.
//
// برمی‌گرداند لیست chunk های آمادهٔ نوشتن (به ترتیب)، و done=true اگر FIN
// مشاهده و تخلیه شد. هر emit.buf (در صورت غیر nil) پس از مصرف باید توسط
// caller به payloadPool برگردانده شود.
func (r *reassembler) Push(seq uint32, buf *[]byte, data []byte, fin bool) ([]emit, bool) {
	r.stats.recvTotal.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()

	// seq قدیمی یا تکراری (شامل حالت اول که هنوز highest set نشده هم اگر seq < next).
	if r.haveHigh && seq < r.next {
		r.stats.recvDup.Add(1)
		// اگر seq در nackCount بود، یعنی NACK ما کار کرد ولی با تاخیر رسید
		// (در این زمان آن را skip کرده‌ایم یا قبل‌تر drain شد). همچنان NACK-fill
		// شمرده می‌شود چون دادهٔ واقعی گم نشد (فقط از دستمان دیر در آمد).
		if _, hadNack := r.nackCount[seq]; hadNack {
			r.stats.nackFilled.Add(1)
			delete(r.nackCount, seq)
			delete(r.nackLastAt, seq)
		}
		return []emit{{buf: buf, data: nil}}, false
	}

	// به‌روزرسانی highestSeen
	if !r.haveHigh || seq > r.highestSeen {
		r.highestSeen = seq
		r.haveHigh = true
	}

	// اگر این seq قبلاً NACK شده بود، الان پر شد.
	if _, hadNack := r.nackCount[seq]; hadNack {
		r.stats.nackFilled.Add(1)
		delete(r.nackCount, seq)
		delete(r.nackLastAt, seq)
	}

	if seq > r.next {
		// بستهٔ خارج از ترتیب
		r.stats.recvOOO.Add(1)
		if _, exists := r.pending[seq]; exists {
			// تکراری (نسخهٔ دیگری از این seq قبلاً آمده). بازگشت به pool.
			r.stats.recvDup.Add(1)
			return []emit{{buf: buf, data: nil}}, false
		}
		// اعمال سقف حافظهٔ pending: اگر رد شد، دورترین seq را بیرون می‌اندازیم
		// (چون احتمال اینکه به آن برسیم کم‌تر است).
		if len(r.pending) >= r.cfg.MaxPending {
			r.evictFarthestLocked()
		}
		r.pending[seq] = pendingChunk{buf: buf, data: data, fin: fin}
		atomic.StoreInt64(&r.stats.currentPending, int64(len(r.pending)))
		if r.gapNoticedAt.IsZero() {
			r.gapNoticedAt = time.Now()
		}
		return nil, false
	}

	// seq == next: drain متوالی
	out, done := r.drainLocked(buf, data, fin)
	r.refreshGapClockLocked()
	atomic.StoreInt64(&r.stats.currentPending, int64(len(r.pending)))
	return out, done
}

// evictFarthestLocked هنگام overflow، دورترین seq از next را از pending بیرون می‌کشد
// و بافر آن را به payloadPool برمی‌گرداند (جلوگیری از leak).
func (r *reassembler) evictFarthestLocked() {
	var victim uint32
	first := true
	for seq := range r.pending {
		if first || seq > victim {
			victim = seq
			first = false
		}
	}
	if !first {
		if ch, ok := r.pending[victim]; ok {
			if ch.buf != nil && r.payloadPool != nil {
				r.payloadPool.Put(ch.buf)
			}
			delete(r.pending, victim)
			delete(r.nackCount, victim)
			delete(r.nackLastAt, victim)
			r.stats.pendingDrops.Add(1)
		}
	}
}

// drainLocked باید با mu گرفته‌شده صدا زده شود. firstBuf/firstData مربوط به
// seq=next است که همین الان رسیده.
func (r *reassembler) drainLocked(firstBuf *[]byte, firstData []byte, fin bool) ([]emit, bool) {
	out := make([]emit, 0, 4)
	out = append(out, emit{buf: firstBuf, data: firstData})
	r.stats.bytesEmitted.Add(uint64(len(firstData)))
	r.next++
	delete(r.nackCount, r.next-1)
	delete(r.nackLastAt, r.next-1)
	if fin {
		return out, true
	}
	for {
		ch, ok := r.pending[r.next]
		if !ok {
			break
		}
		delete(r.pending, r.next)
		delete(r.nackCount, r.next)
		delete(r.nackLastAt, r.next)
		out = append(out, emit{buf: ch.buf, data: ch.data})
		r.stats.bytesEmitted.Add(uint64(len(ch.data)))
		r.next++
		if ch.fin {
			return out, true
		}
	}
	return out, false
}

// refreshGapClockLocked تشخیص می‌دهد آیا هنوز gap باز است و ساعت gap را به‌روز
// می‌کند. اگر next به highestSeen+1 رسیده → بدون gap → reset.
// در غیر اینصورت gap هنوز هست؛ اگر قبلاً zero بود الان set می‌شود (gap جدید).
func (r *reassembler) refreshGapClockLocked() {
	if !r.haveHigh || r.next > r.highestSeen {
		r.gapNoticedAt = time.Time{}
		return
	}
	if r.gapNoticedAt.IsZero() {
		r.gapNoticedAt = time.Now()
	}
}

// MaybeSkip بررسی می‌کند اگر gap جاری از SkipTimeout گذشته، seq=next را skip
// می‌کند و تا حد امکان drain می‌کند. این تابع باید دوره‌ای (مثلاً هر 50ms)
// از طرف pumpUDPToUser فراخوانی شود تا حتی در نبود بستهٔ جدید، stream جلو برود.
func (r *reassembler) MaybeSkip(now time.Time) ([]emit, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.gapNoticedAt.IsZero() {
		return nil, false
	}
	if now.Sub(r.gapNoticedAt) < r.cfg.SkipTimeout {
		return nil, false
	}
	// seq=next را skip می‌کنیم (دادهٔ آن گم شد).
	out := make([]emit, 0, 4)
	delete(r.nackCount, r.next)
	delete(r.nackLastAt, r.next)
	r.next++
	r.stats.skipped.Add(1)
	// drain متوالی از pending
	for {
		ch, ok := r.pending[r.next]
		if !ok {
			break
		}
		delete(r.pending, r.next)
		delete(r.nackCount, r.next)
		delete(r.nackLastAt, r.next)
		out = append(out, emit{buf: ch.buf, data: ch.data})
		r.stats.bytesEmitted.Add(uint64(len(ch.data)))
		r.next++
		if ch.fin {
			atomic.StoreInt64(&r.stats.currentPending, int64(len(r.pending)))
			return out, true
		}
	}
	r.refreshGapClockLocked()
	atomic.StoreInt64(&r.stats.currentPending, int64(len(r.pending)))
	return out, false
}

// PickMissing لیست seqهای گمشده را (تا سقف budget و lookahead) برمی‌گرداند
// و زمان NACK را در داخل ثبت می‌کند. قبل از برگرداندن، NackInterval رعایت
// می‌شود تا از طوفان NACK جلوگیری شود. اگر ignoreInterval true باشد، NACK
// بلافاصله (مناسب برای اولین تشخیص gap) برگردانده می‌شود.
func (r *reassembler) PickMissing(now time.Time, budget int) []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.haveHigh || r.highestSeen < r.next {
		return nil
	}
	lookEnd := r.next + r.cfg.NackLookahead
	if lookEnd > r.highestSeen {
		lookEnd = r.highestSeen
	}
	out := make([]uint32, 0, budget)
	for s := r.next; s <= lookEnd && len(out) < budget; s++ {
		if _, ok := r.pending[s]; ok {
			continue
		}
		cnt := r.nackCount[s]
		if cnt >= r.cfg.NackMaxTries {
			continue
		}
		if last, ok := r.nackLastAt[s]; ok {
			if now.Sub(last) < r.cfg.NackInterval {
				continue
			}
		}
		out = append(out, s)
		r.nackLastAt[s] = now
		r.nackCount[s] = cnt + 1
	}
	if n := len(out); n > 0 {
		r.stats.nackSent.Add(uint64(n))
	}
	return out
}

// Next seq فعلی که منتظرش هستیم (برای log debug).
func (r *reassembler) Next() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.next
}

// HighestSeen بالاترین seq دیده‌شده (برای log debug).
func (r *reassembler) HighestSeen() (uint32, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.highestSeen, r.haveHigh
}

// Stats یک snapshot از شمارنده‌ها را برمی‌گرداند (lock-free برای خواندن).
func (r *reassembler) Stats() reassemblerStatsSnapshot {
	return reassemblerStatsSnapshot{
		RecvTotal:      r.stats.recvTotal.Load(),
		RecvOOO:        r.stats.recvOOO.Load(),
		RecvDup:        r.stats.recvDup.Load(),
		NackSent:       r.stats.nackSent.Load(),
		NackFilled:     r.stats.nackFilled.Load(),
		Skipped:        r.stats.skipped.Load(),
		PendingDrops:   r.stats.pendingDrops.Load(),
		BytesEmitted:   r.stats.bytesEmitted.Load(),
		CurrentPending: atomic.LoadInt64(&r.stats.currentPending),
	}
}

// reassemblerStatsSnapshot یک copy ثابت از آمار برای لاگ.
type reassemblerStatsSnapshot struct {
	RecvTotal      uint64
	RecvOOO        uint64
	RecvDup        uint64
	NackSent       uint64
	NackFilled     uint64
	Skipped        uint64
	PendingDrops   uint64
	BytesEmitted   uint64
	CurrentPending int64
}

// releasePending تمام بافرهای معلق را به pool بازمی‌گرداند.
// هنگام پایان session باید صدا زده شود تا بافرها leak نشوند.
func (r *reassembler) releasePending(pool *sync.Pool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for seq, ch := range r.pending {
		if ch.buf != nil {
			pool.Put(ch.buf)
		}
		delete(r.pending, seq)
	}
	r.nackCount = make(map[uint32]int)
	r.nackLastAt = make(map[uint32]time.Time)
	atomic.StoreInt64(&r.stats.currentPending, 0)
}
