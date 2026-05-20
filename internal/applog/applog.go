// Package applog سطح لاگ قابل تنظیم برای اتصال‌ها (info / debug).
package applog

import (
	"log"
	"strings"
)

// Level سطح لاگ.
type Level int

const (
	LevelOff Level = iota
	LevelInfo
	LevelDebug
)

// Logger با توجه به سطح، پیام‌ها را چاپ می‌کند.
type Logger struct {
	level Level
}

// ParseLevel رشته کانفیگ را به Level تبدیل می‌کند (off، info، debug).
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return LevelInfo
	case "debug":
		return LevelDebug
	default:
		return LevelOff
	}
}

// New از رشته کانفیگ یک Logger می‌سازد.
func New(logLevel string) *Logger {
	return &Logger{level: ParseLevel(logLevel)}
}

// Level برمی‌گرداند.
func (l *Logger) Level() Level {
	if l == nil {
		return LevelOff
	}
	return l.level
}

// Infof فقط در info یا بالاتر.
func (l *Logger) Infof(format string, args ...interface{}) {
	if l == nil || l.level < LevelInfo {
		return
	}
	log.Printf("[INFO] "+format, args...)
}

// Debugf فقط در debug.
func (l *Logger) Debugf(format string, args ...interface{}) {
	if l == nil || l.level < LevelDebug {
		return
	}
	log.Printf("[DEBUG] "+format, args...)
}
