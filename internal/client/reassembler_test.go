package client

import (
	"sync"
	"testing"
	"time"
)

// کمک‌کنندهٔ ساخت chunk آزمون با data یک بایتی.
func mkChunk(b byte) (*[]byte, []byte) {
	s := []byte{b}
	bp := &s
	return bp, s
}

// TestReassemblerInOrder تأیید می‌کند که پکت‌های متوالی بلافاصله emit می‌شوند
// و هیچ gap ای ثبت نمی‌شود.
func TestReassemblerInOrder(t *testing.T) {
	pool := &sync.Pool{New: func() interface{} { b := make([]byte, 0, 64); return &b }}
	r := newReassembler(pool)
	for i := uint32(0); i < 10; i++ {
		bp, d := mkChunk(byte(i))
		chunks, done := r.Push(i, bp, d, false)
		if done {
			t.Fatalf("unexpected done at %d", i)
		}
		if len(chunks) != 1 {
			t.Fatalf("expected 1 chunk at %d, got %d", i, len(chunks))
		}
	}
	if len(r.PickMissing(time.Now(), 8)) != 0 {
		t.Fatalf("no gap expected")
	}
}

// TestReassemblerGapFilledByRetransmit: ابتدا seq=1 و 2 می‌آیند (gap)، سپس
// seq=0 با تاخیر می‌رسد و باید هر سه را به‌ترتیب drain کند.
func TestReassemblerGapFilledByRetransmit(t *testing.T) {
	pool := &sync.Pool{New: func() interface{} { b := make([]byte, 0, 64); return &b }}
	r := newReassembler(pool)

	b1, d1 := mkChunk(1)
	b2, d2 := mkChunk(2)
	if chunks, _ := r.Push(1, b1, d1, false); len(chunks) != 0 {
		t.Fatalf("expected 0 chunks for seq=1 with next=0, got %d", len(chunks))
	}
	if chunks, _ := r.Push(2, b2, d2, false); len(chunks) != 0 {
		t.Fatalf("expected 0 chunks for seq=2 with next=0, got %d", len(chunks))
	}
	if len(r.PickMissing(time.Now(), 8)) == 0 {
		t.Fatalf("expected gap")
	}

	// اکنون seq=0 می‌رسد (مثلاً در پاسخ به NACK).
	b0, d0 := mkChunk(0)
	chunks, _ := r.Push(0, b0, d0, false)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks after fill, got %d", len(chunks))
	}
	if chunks[0].data[0] != 0 || chunks[1].data[0] != 1 || chunks[2].data[0] != 2 {
		t.Fatalf("wrong order: %v %v %v", chunks[0].data, chunks[1].data, chunks[2].data)
	}
}

// TestReassemblerPickMissing: gap ایجاد می‌کنیم و PickMissing لیست درست را
// برمی‌گرداند، و در tick بعدی قبل از NackInterval، آن seqها را تکرار نمی‌کند.
func TestReassemblerPickMissing(t *testing.T) {
	pool := &sync.Pool{New: func() interface{} { b := make([]byte, 0, 64); return &b }}
	cfg := defaultReassemblerConfig()
	cfg.NackInterval = 50 * time.Millisecond
	r := newReassemblerWith(cfg, pool)

	// seq=0 و seq=5 می‌آیند؛ seqهای 1..4 گمشده‌اند.
	b0, d0 := mkChunk(10)
	_, _ = r.Push(0, b0, d0, false)
	b5, d5 := mkChunk(15)
	_, _ = r.Push(5, b5, d5, false)

	now := time.Now()
	seqs := r.PickMissing(now, 128)
	if len(seqs) != 4 {
		t.Fatalf("expected 4 missing seqs, got %d: %v", len(seqs), seqs)
	}
	for i, s := range seqs {
		if s != uint32(i+1) {
			t.Fatalf("seqs[%d]=%d, want %d", i, s, i+1)
		}
	}

	// tick بلافاصلهٔ دوم: interval رعایت می‌شود → خالی.
	seqs2 := r.PickMissing(now.Add(10*time.Millisecond), 128)
	if len(seqs2) != 0 {
		t.Fatalf("expected empty within interval, got %v", seqs2)
	}

	// پس از گذشت interval: دوباره برمی‌گردد.
	seqs3 := r.PickMissing(now.Add(60*time.Millisecond), 128)
	if len(seqs3) != 4 {
		t.Fatalf("expected 4 after interval, got %d", len(seqs3))
	}
}

// TestReassemblerNackMaxTries پس از NackMaxTries، آن seqها در PickMissing
// دیگر ظاهر نمی‌شوند (تا skip-timeout آن‌ها را بردارد).
func TestReassemblerNackMaxTries(t *testing.T) {
	pool := &sync.Pool{New: func() interface{} { b := make([]byte, 0, 64); return &b }}
	cfg := defaultReassemblerConfig()
	cfg.NackInterval = 1 * time.Millisecond
	cfg.NackMaxTries = 3
	r := newReassemblerWith(cfg, pool)

	// gap روی seq=0
	b1, d1 := mkChunk(1)
	_, _ = r.Push(1, b1, d1, false)

	now := time.Now()
	for i := 0; i < 3; i++ {
		seqs := r.PickMissing(now, 128)
		if len(seqs) != 1 || seqs[0] != 0 {
			t.Fatalf("try %d: expected [0], got %v", i, seqs)
		}
		now = now.Add(2 * time.Millisecond)
	}
	// تلاش چهارم: باید خالی باشد چون به MaxTries رسیدیم.
	seqs := r.PickMissing(now, 128)
	if len(seqs) != 0 {
		t.Fatalf("expected empty after max tries, got %v", seqs)
	}
}

// TestReassemblerSkip: اگر gap بیش از SkipTimeout باز بماند، MaybeSkip آن seq
// را کنار می‌گذارد و next را جلو می‌برد.
func TestReassemblerSkip(t *testing.T) {
	pool := &sync.Pool{New: func() interface{} { b := make([]byte, 0, 64); return &b }}
	cfg := defaultReassemblerConfig()
	cfg.SkipTimeout = 20 * time.Millisecond
	r := newReassemblerWith(cfg, pool)

	// seq=0 گمشده، seq=1 و 2 داریم.
	b1, d1 := mkChunk(1)
	b2, d2 := mkChunk(2)
	_, _ = r.Push(1, b1, d1, false)
	_, _ = r.Push(2, b2, d2, false)

	// قبل از skip_timeout: هیچ skip.
	if chunks, _ := r.MaybeSkip(time.Now()); chunks != nil {
		t.Fatalf("unexpected skip before timeout")
	}

	// بعد از skip_timeout: seq=0 skip شود و 1 و 2 drain شوند.
	time.Sleep(25 * time.Millisecond)
	chunks, _ := r.MaybeSkip(time.Now())
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks after skip, got %d", len(chunks))
	}
	if r.Next() != 3 {
		t.Fatalf("next=%d, want 3", r.Next())
	}
	if s := r.Stats(); s.Skipped != 1 {
		t.Fatalf("skipped=%d, want 1", s.Skipped)
	}
}

// TestReassemblerNackFillStats: پر شدن NACK در آمار nack_fill ثبت می‌شود.
func TestReassemblerNackFillStats(t *testing.T) {
	pool := &sync.Pool{New: func() interface{} { b := make([]byte, 0, 64); return &b }}
	r := newReassembler(pool)

	b1, d1 := mkChunk(1)
	_, _ = r.Push(1, b1, d1, false)

	// NACK می‌شود
	seqs := r.PickMissing(time.Now(), 10)
	if len(seqs) != 1 || seqs[0] != 0 {
		t.Fatalf("expected NACK for seq=0, got %v", seqs)
	}
	if s := r.Stats(); s.NackSent != 1 {
		t.Fatalf("nack_sent=%d", s.NackSent)
	}

	// پر می‌شود
	b0, d0 := mkChunk(0)
	_, _ = r.Push(0, b0, d0, false)
	if s := r.Stats(); s.NackFilled != 1 {
		t.Fatalf("nack_filled=%d, want 1", s.NackFilled)
	}
}
