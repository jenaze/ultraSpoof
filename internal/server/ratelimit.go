package server

import (
	"sync"
	"time"
)

// tokenBucket یک rate limiter سادهٔ thread-safe برای بایت بر ثانیه.
//
// هدف: جلوگیری از ارسال بسته‌های UDP با سرعتی فراتر از ظرفیت واقعی لینک
// مقصد. بدون این مکانیزم، sender با سرعت NIC (معمولاً 1-10 Gbps) می‌فرستد
// و در کرنل/ISP سمت گیرنده drop زیاد رخ می‌دهد.
//
// الگو: Wait(n) منتظر می‌ماند تا n بایت token فراهم شود، سپس آن‌ها را
// مصرف می‌کند. اگر limit صفر باشد، هیچ‌وقت مسدود نمی‌شود (نامحدود).
type tokenBucket struct {
	mu        sync.Mutex
	tokens    float64
	maxTokens float64
	// نرخ بر حسب token/ns (بایت بر نانوثانیه). اگر ۰ باشد، unlimited.
	ratePerNs float64
	last      time.Time
}

// newTokenBucket سازندهٔ bucket با سرعت مشخص (بایت بر ثانیه) و ظرفیت burst.
// اگر bytesPerSec == 0 => unlimited (nil برگرداند ولی اینجا هر تابع Wait نهایتاً
// noop می‌شود اگر نرخ صفر باشد).
func newTokenBucket(bytesPerSec int64, burstBytes int64) *tokenBucket {
	if bytesPerSec <= 0 {
		return nil
	}
	if burstBytes <= 0 {
		// پیش‌فرض: burst برابر با 100ms ترافیک. مقدار معقول برای smoothing بدون
		// ایجاد micro-bursts بزرگ که بافر مسیر را پر کند.
		burstBytes = bytesPerSec / 10
		if burstBytes < 64*1024 {
			burstBytes = 64 * 1024
		}
	}
	return &tokenBucket{
		tokens:    float64(burstBytes),
		maxTokens: float64(burstBytes),
		ratePerNs: float64(bytesPerSec) / 1e9,
		last:      time.Now(),
	}
}

// Wait منتظر می‌ماند تا n token فراهم شود و آن‌ها را مصرف می‌کند.
// در صورت nil بودن bucket (unlimited) بلافاصله برمی‌گردد.
func (tb *tokenBucket) Wait(n int) {
	if tb == nil || n <= 0 {
		return
	}
	// اگر n بزرگ‌تر از maxTokens باشد، این را در یک انتظار طولانی انجام می‌دهیم
	// تا رفتار منصفانه باشد. ولی در عمل n معمولاً اندازهٔ یک batch است (<256KB).
	for {
		tb.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(tb.last)
		if elapsed > 0 {
			tb.tokens += float64(elapsed.Nanoseconds()) * tb.ratePerNs
			if tb.tokens > tb.maxTokens {
				tb.tokens = tb.maxTokens
			}
			tb.last = now
		}
		need := float64(n) - tb.tokens
		if need <= 0 {
			tb.tokens -= float64(n)
			tb.mu.Unlock()
			return
		}
		// ns ای که باید صبر کنیم تا need توکن تولید شود.
		waitNs := need / tb.ratePerNs
		tb.mu.Unlock()
		sleep := time.Duration(waitNs)
		if sleep < time.Millisecond {
			// Avoid busy-looping and too many wake-ups. Give the CPU a break.
			sleep = time.Millisecond
		}
		time.Sleep(sleep)
	}
}
