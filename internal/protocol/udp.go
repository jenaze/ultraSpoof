package protocol

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/ultraspoof/ultraspoof/internal/crypto"
)

// فریم UDP پس از رمزگشایی AEAD (plaintext داخلی).
const (
	UDPPayloadVersion = 1
	FlagData          = 0
	FlagFIN           = 1
)

// udpPlainHeaderLen طول سرآیند plaintext قبل از chunk: version + session + seq + flags.
const udpPlainHeaderLen = 1 + 16 + 4 + 1

// UDPNonceLength اندازهٔ nonce برای AES-GCM.
const UDPNonceLength = 12

// UDPAEADTagLen اندازهٔ tag در AEAD مورد استفاده (AES-GCM).
const UDPAEADTagLen = 16

// UDPOverhead سربار کل هر بستهٔ UDP بعد از Seal نسبت به chunk: nonce + tag + plain header.
const UDPOverhead = UDPNonceLength + UDPAEADTagLen + udpPlainHeaderLen

// EncodeUDPPlain ساخت بدنهٔ plaintext قبل از AEAD (مسیر بدون پول).
func EncodeUDPPlain(sessionID []byte, seq uint32, flags byte, chunk []byte) []byte {
	if len(sessionID) != 16 {
		panic("session id len")
	}
	out := make([]byte, udpPlainHeaderLen+len(chunk))
	encodePlainInto(out, sessionID, seq, flags, chunk)
	return out
}

// encodePlainInto نوشتن plaintext در یک buffer از پیش آماده‌شده.
func encodePlainInto(dst []byte, sessionID []byte, seq uint32, flags byte, chunk []byte) {
	dst[0] = UDPPayloadVersion
	copy(dst[1:17], sessionID)
	binary.BigEndian.PutUint32(dst[17:21], seq)
	dst[21] = flags
	copy(dst[udpPlainHeaderLen:], chunk)
}

// DecodeUDPPlain تجزیهٔ plaintext بعد از رمزگشایی (نسخهٔ کپی‌کنندهٔ سازگار).
func DecodeUDPPlain(plain []byte) (sessionID []byte, seq uint32, flags byte, payload []byte, err error) {
	if len(plain) < udpPlainHeaderLen {
		return nil, 0, 0, nil, errors.New("udp plain too short")
	}
	if plain[0] != UDPPayloadVersion {
		return nil, 0, 0, nil, errors.New("unsupported udp payload version")
	}
	sessionID = append([]byte(nil), plain[1:17]...)
	seq = binary.BigEndian.Uint32(plain[17:21])
	flags = plain[21]
	payload = append([]byte(nil), plain[udpPlainHeaderLen:]...)
	return sessionID, seq, flags, payload, nil
}

// BuildUDPNonce ساخت nonce از session و seq (نسخهٔ allocator).
func BuildUDPNonce(sessionID []byte, seq uint32) []byte {
	n := make([]byte, UDPNonceLength)
	writeNonceInto(n, sessionID, seq)
	return n
}

func writeNonceInto(dst []byte, sessionID []byte, seq uint32) {
	copy(dst[0:4], sessionID[0:4])
	binary.BigEndian.PutUint32(dst[4:8], seq)
	copy(dst[8:12], sessionID[4:8])
}

// SealUDPPacket بستهٔ کامل UDP: [nonce 12][ciphertext+tag] (نسخهٔ سازگار).
func SealUDPPacket(psk []byte, sessionID []byte, seq uint32, flags byte, chunk []byte) ([]byte, error) {
	aead, err := crypto.NewUDPAEAD(psk)
	if err != nil {
		return nil, err
	}
	plain := EncodeUDPPlain(sessionID, seq, flags, chunk)
	nonce := BuildUDPNonce(sessionID, seq)
	sealed := aead.Seal(nil, nonce, plain, nil)
	out := make([]byte, UDPNonceLength+len(sealed))
	copy(out, nonce)
	copy(out[UDPNonceLength:], sealed)
	return out, nil
}

// SealUDPPacketWith نسخهٔ بهینه: AEAD از پیش ساخته‌شده می‌گیرد و scratch قابل
// reuse برای جلوگیری از allocation در hot path.
//
// scratch یک اشاره‌گر به slice است که فضای کاری را نگه می‌دارد. تابع در صورت نیاز
// آن را گسترش می‌دهد. بستهٔ تولیدشده روی همان فضا قرار می‌گیرد و slice برگشتی تا
// زمان ارسال معتبر است (بعد از فراخوانی بعدی این تابع روی همان scratch بازنویسی می‌شود).
func SealUDPPacketWith(aead cipher.AEAD, scratch *[]byte, sessionID []byte, seq uint32, flags byte, chunk []byte) []byte {
	plainLen := udpPlainHeaderLen + len(chunk)
	sealedLen := plainLen + UDPAEADTagLen
	totalLen := UDPNonceLength + sealedLen
	// نیاز به فضای اضافه برای plaintext (Seal ممکن است با src/dst همپوش کار نکند).
	required := totalLen + plainLen

	buf := *scratch
	if cap(buf) < required {
		buf = make([]byte, required)
	} else {
		buf = buf[:required]
	}
	*scratch = buf

	nonce := buf[:UDPNonceLength]
	writeNonceInto(nonce, sessionID, seq)

	plain := buf[totalLen : totalLen+plainLen]
	encodePlainInto(plain, sessionID, seq, flags, chunk)

	sealed := aead.Seal(buf[UDPNonceLength:UDPNonceLength], nonce, plain, nil)
	return buf[:UDPNonceLength+len(sealed)]
}

// OpenUDPPacket باز کردن بستهٔ کامل UDP (نسخهٔ سازگار، با کپی).
func OpenUDPPacket(psk []byte, packet []byte) (sessionID []byte, seq uint32, flags byte, payload []byte, err error) {
	if len(packet) < UDPNonceLength+UDPAEADTagLen {
		return nil, 0, 0, nil, errors.New("packet too short")
	}
	nonce := packet[:UDPNonceLength]
	aead, err := crypto.NewUDPAEAD(psk)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	plain, err := aead.Open(nil, nonce, packet[UDPNonceLength:], nil)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	return DecodeUDPPlain(plain)
}

// OpenUDPPacketWith نسخهٔ بهینه: AEAD از پیش ساخته‌شده + plain buffer قابل reuse.
//
// مقادیر برگشتی sessionID و payload به داخل plainBuf اشاره می‌کنند، پس caller
// قبل از فراخوانی بعدی این تابع روی همان plainBuf باید کپی بگیرد.
func OpenUDPPacketWith(aead cipher.AEAD, packet []byte, plainBuf *[]byte) (sessionID []byte, seq uint32, flags byte, payload []byte, err error) {
	if len(packet) < UDPNonceLength+UDPAEADTagLen {
		return nil, 0, 0, nil, errors.New("packet too short")
	}
	nonce := packet[:UDPNonceLength]
	plain, err := aead.Open((*plainBuf)[:0], nonce, packet[UDPNonceLength:], nil)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	*plainBuf = plain
	if len(plain) < udpPlainHeaderLen {
		return nil, 0, 0, nil, errors.New("udp plain too short")
	}
	if plain[0] != UDPPayloadVersion {
		return nil, 0, 0, nil, errors.New("unsupported udp payload version")
	}
	sessionID = plain[1:17]
	seq = binary.BigEndian.Uint32(plain[17:21])
	flags = plain[21]
	payload = plain[udpPlainHeaderLen:]
	return sessionID, seq, flags, payload, nil
}

// ============================================================================
// Aggressive/Plain Mode (بدون AEAD): حداکثر سرعت به‌قیمت حذف encryption.
// ============================================================================
//
// فرمت بسته (هیچ nonce و tag نداریم):
//
//     magic(1)=0xFE | version(1)=2 | session_id(16) | seq(4) | flags(1) | chunk
//
// magic=0xFE عمداً غیرتصادفی انتخاب شده تا در سناریوهایی که receive اتفاقی
// به fd دیگری می‌افتد (مثلاً مسیرهای مشترک)، سریع reject شود. امنیت/محرمانگی
// وجود ندارد؛ فقط identification session و reassembly.

const udpPlainModeMagic byte = 0xFE
const udpPlainModeVersion byte = 2

// UDPPlainModeOverhead سربار در حالت plain mode: magic+version+sid+seq+flags.
const UDPPlainModeOverhead = 1 + 1 + 16 + 4 + 1 // = 23 بایت

// SealUDPPacketPlain ساخت بستهٔ UDP بدون رمزنگاری. scratch برای کاهش allocation
// استفاده می‌شود. خروجی اشاره به داخل scratch است.
func SealUDPPacketPlain(scratch *[]byte, sessionID []byte, seq uint32, flags byte, chunk []byte) []byte {
	if len(sessionID) != 16 {
		panic("session id len")
	}
	total := UDPPlainModeOverhead + len(chunk)
	buf := *scratch
	if cap(buf) < total {
		buf = make([]byte, total)
	} else {
		buf = buf[:total]
	}
	*scratch = buf
	buf[0] = udpPlainModeMagic
	buf[1] = udpPlainModeVersion
	copy(buf[2:18], sessionID)
	binary.BigEndian.PutUint32(buf[18:22], seq)
	buf[22] = flags
	copy(buf[23:], chunk)
	return buf
}

// OpenUDPPacketPlain تجزیهٔ بستهٔ plain بدون رمزگشایی. نتایج به داخل packet
// اشاره می‌کنند؛ caller باید قبل از استفادهٔ مجدد packet کپی بگیرد.
func OpenUDPPacketPlain(packet []byte) (sessionID []byte, seq uint32, flags byte, payload []byte, err error) {
	if len(packet) < UDPPlainModeOverhead {
		return nil, 0, 0, nil, errors.New("plain packet too short")
	}
	if packet[0] != udpPlainModeMagic {
		return nil, 0, 0, nil, errors.New("plain bad magic")
	}
	if packet[1] != udpPlainModeVersion {
		return nil, 0, 0, nil, errors.New("plain unsupported version")
	}
	sessionID = packet[2:18]
	seq = binary.BigEndian.Uint32(packet[18:22])
	flags = packet[22]
	payload = packet[23:]
	return sessionID, seq, flags, payload, nil
}
