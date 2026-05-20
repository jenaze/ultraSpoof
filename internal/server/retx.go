package server

import (
	"sync"
	"sync/atomic"
)

// retxEntry یک slot ذخیرهٔ بستهٔ ارسالی در ring buffer سمت سرور.
type retxEntry struct {
	seq     uint32
	srcPort uint16
	data    []byte // بدنهٔ کامل پکت UDP (sealed/plain) که به کلاینت فرستاده شد
	valid   bool
}

// retxRing یک ring buffer ساده و thread-safe برای نگه‌داری آخرین N پکت ارسالی
// هر session. وقتی کلاینت با CmdNack درخواست retransmit می‌دهد، از اینجا
// پکت را برمی‌داریم و دوباره می‌فرستیم.
//
// اندیس = seq & capMask (capacity همیشه توان ۲). وقتی seq جدیدی با همان اندیس
// می‌آید، slot قدیمی بازنویسی می‌شود. این یعنی retransmit فقط برای پکت‌هایی
// کار می‌کند که در ~cap بستهٔ اخیر بوده‌اند. capacity باید متناسب با
// bandwidth × skip_timeout انتخاب شود:
//
//	cap >= (Mbps × 1e6 / 8) × skip_timeout_sec / chunk_size
//
// مثال: 100 Mbps × 1.2s / 1400B ≈ 10700 → cap = 16384 ایمن است.
type retxRing struct {
	mu      sync.RWMutex
	entries []retxEntry
	capMask uint32 // cap - 1

	// شمارنده‌های آمار (lock-free).
	stored atomic.Uint64 // تعداد Store موفق
	hits   atomic.Uint64 // تعداد Lookup موفق (پکت ارسال‌شده مجدد)
	misses atomic.Uint64 // تعداد Lookup ناموفق (seq تاریخی/نرسیده)
}

// newRetxRing یک ring با capacity به توان ۲ می‌سازد. اگر capRequest صفر یا منفی
// باشد، nil برمی‌گرداند (retransmit غیرفعال).
func newRetxRing(capRequest int) *retxRing {
	if capRequest <= 0 {
		return nil
	}
	// گرد به توان ۲ بالا.
	c := 1
	for c < capRequest {
		c <<= 1
	}
	if c < 64 {
		c = 64
	}
	return &retxRing{
		entries: make([]retxEntry, c),
		capMask: uint32(c - 1),
	}
}

// Store یک پکت با seq مشخص و srcPort را در ring ذخیره می‌کند.
// pkt کپی می‌شود چون caller احتمالاً bufferهای اشتراکی (scratch) دارد.
func (r *retxRing) Store(seq uint32, srcPort uint16, pkt []byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	idx := seq & r.capMask
	e := &r.entries[idx]
	if cap(e.data) < len(pkt) {
		e.data = make([]byte, len(pkt))
	} else {
		e.data = e.data[:len(pkt)]
	}
	copy(e.data, pkt)
	e.seq = seq
	e.srcPort = srcPort
	e.valid = true
	r.stored.Add(1)
	r.mu.Unlock()
}

// Lookup بستهٔ مربوط به seq را اگر هنوز در ring باشد برمی‌گرداند.
// خروجی data کپی جدید است (جلوگیری از مسابقه با Store هنگام ارسال).
func (r *retxRing) Lookup(seq uint32) (data []byte, srcPort uint16, ok bool) {
	if r == nil {
		return nil, 0, false
	}
	r.mu.RLock()
	idx := seq & r.capMask
	e := r.entries[idx]
	if !e.valid || e.seq != seq {
		r.mu.RUnlock()
		r.misses.Add(1)
		return nil, 0, false
	}
	out := make([]byte, len(e.data))
	copy(out, e.data)
	sp := e.srcPort
	r.mu.RUnlock()
	r.hits.Add(1)
	return out, sp, true
}

// LookupBatch چند seq را با یک قفل خواندن پیدا می‌کند و برای ارسال مجدد batch آماده می‌کند.
// pkts باید ظرفیت کافی داشته باشد (معمولاً len(seqs)).
func (r *retxRing) LookupBatch(seqs []uint32, pkts [][]byte) (count int, srcPort uint16) {
	if r == nil || len(seqs) == 0 {
		return 0, 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, seq := range seqs {
		idx := seq & r.capMask
		e := r.entries[idx]
		if !e.valid || e.seq != seq {
			r.misses.Add(1)
			continue
		}
		out := make([]byte, len(e.data))
		copy(out, e.data)
		pkts[count] = out
		count++
		if srcPort == 0 {
			srcPort = e.srcPort
		}
		r.hits.Add(1)
	}
	return count, srcPort
}

// Stats یک snapshot از شمارنده‌ها برمی‌گرداند.
func (r *retxRing) Stats() (stored, hits, misses uint64) {
	if r == nil {
		return 0, 0, 0
	}
	return r.stored.Load(), r.hits.Load(), r.misses.Load()
}

// Cap اندازهٔ capacity ring.
func (r *retxRing) Cap() int {
	if r == nil {
		return 0
	}
	return int(r.capMask) + 1
}
