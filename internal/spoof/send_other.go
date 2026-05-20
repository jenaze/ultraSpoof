//go:build !linux

package spoof

import (
	"errors"
	"net"
)

// SenderConfig stub برای پلتفرم‌های غیر لینوکسی (برای حفظ سازگاری امضا).
type SenderConfig struct {
	Iface                 string
	Workers               int
	SkipUDPChecksum       bool
	SocketSendBufferBytes int
}

// Sender پیاده‌سازی stub برای پلتفرم‌های غیر لینوکسی.
type Sender struct{}

// NewSender روی پلتفرم‌های غیر لینوکسی با خطا برمی‌گردد.
func NewSender(_ string) (*Sender, error) {
	return nil, errors.New("spoof UDP send is only implemented on linux")
}

// NewSenderWithConfig روی پلتفرم‌های غیر لینوکسی با خطا برمی‌گردد.
func NewSenderWithConfig(_ SenderConfig) (*Sender, error) {
	return nil, errors.New("spoof UDP send is only implemented on linux")
}

// Close فقط برای تطابق با interface.
func (s *Sender) Close() error { return nil }

// SendUDP پیاده‌سازی stub.
func (s *Sender) SendUDP(_ net.IP, _ uint16, _ net.IP, _ uint16, _ []byte) error {
	return errors.New("spoof UDP send is only implemented on linux")
}

// SendBatch پیاده‌سازی stub.
func (s *Sender) SendBatch(_ net.IP, _ uint16, _ net.IP, _ uint16, _ [][]byte) error {
	return errors.New("spoof UDP send is only implemented on linux")
}
