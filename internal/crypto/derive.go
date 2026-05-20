package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
)

const infoUDP = "ultraSpoof-udp-v1"

// UDPKey از PSK کلید ۳۲ بایتی برای AEAD روی کانال دانلود می‌سازد.
func UDPKey(psk []byte) []byte {
	mac := hmac.New(sha256.New, []byte(infoUDP))
	mac.Write(psk)
	return mac.Sum(nil)
}

// NewUDPAEAD سازندهٔ AES-GCM برای فریم‌های UDP.
func NewUDPAEAD(psk []byte) (cipher.AEAD, error) {
	key := UDPKey(psk)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
