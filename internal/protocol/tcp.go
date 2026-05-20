package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// ثابت‌های پروتکل کنترل روی TCP (مسیر آپلود از ایران به ترکیه).
const (
	Magic0 = 'U'
	Magic1 = 'S'
	Magic2 = 'p'
	Magic3 = 0x01
)

const (
	CmdOpen   = 0x01
	CmdData   = 0x02
	CmdClose  = 0x03
	CmdNack   = 0x04
	CmdOpenOK = 0x80
	CmdError  = 0x81

	// کانال TUN نقطه‌به‌نقطه روی همان اتصال TCP کنترل (بدون dial مستقیم به IP عمومی).
	CmdTunRegister  = 0x10
	CmdTunReady     = 0x11
	CmdTunData      = 0x12
	CmdTunKeepalive = 0x13
)

// MaxNackSeqsPerFrame حداکثر تعداد seq در یک فریم NACK تا از اندازهٔ فریم جلوگیری شود.
const MaxNackSeqsPerFrame = 256

var (
	ErrBadMagic = errors.New("invalid tcp frame magic")
)

// WriteOpen ارسال باز کردن نشست و اتصال به مقصد نهایی.
func WriteOpen(w io.Writer, sessionID []byte, host string, port uint16) error {
	if len(sessionID) != 16 {
		return errors.New("session id must be 16 bytes")
	}
	hostBytes := []byte(host)
	if len(hostBytes) > 65535 {
		return errors.New("host too long")
	}
	bodyLen := 16 + 2 + len(hostBytes) + 2
	buf := make([]byte, 4+1+4+bodyLen)
	buf[0], buf[1], buf[2], buf[3] = Magic0, Magic1, Magic2, Magic3
	buf[4] = CmdOpen
	binary.BigEndian.PutUint32(buf[5:9], uint32(bodyLen))
	copy(buf[9:25], sessionID)
	binary.BigEndian.PutUint16(buf[25:27], uint16(len(hostBytes)))
	copy(buf[27:], hostBytes)
	binary.BigEndian.PutUint16(buf[27+len(hostBytes):29+len(hostBytes)], port)
	_, err := w.Write(buf)
	return err
}

// WriteData ارسال دادهٔ آپلود روی TCP.
func WriteData(w io.Writer, sessionID []byte, payload []byte) error {
	if len(sessionID) != 16 {
		return errors.New("session id must be 16 bytes")
	}
	bodyLen := 16 + 4 + len(payload)
	buf := make([]byte, 4+1+4+bodyLen)
	buf[0], buf[1], buf[2], buf[3] = Magic0, Magic1, Magic2, Magic3
	buf[4] = CmdData
	binary.BigEndian.PutUint32(buf[5:9], uint32(bodyLen))
	copy(buf[9:25], sessionID)
	binary.BigEndian.PutUint32(buf[25:29], uint32(len(payload)))
	copy(buf[29:], payload)
	_, err := w.Write(buf)
	return err
}

// WriteNack ارسال درخواست retransmit از کلاینت به سرور.
// body = [16]sessionID + [4]count + count × [4]seq
func WriteNack(w io.Writer, sessionID []byte, seqs []uint32) error {
	if len(sessionID) != 16 {
		return errors.New("session id must be 16 bytes")
	}
	if len(seqs) == 0 {
		return nil
	}
	if len(seqs) > MaxNackSeqsPerFrame {
		seqs = seqs[:MaxNackSeqsPerFrame]
	}
	bodyLen := 16 + 4 + 4*len(seqs)
	buf := make([]byte, 4+1+4+bodyLen)
	buf[0], buf[1], buf[2], buf[3] = Magic0, Magic1, Magic2, Magic3
	buf[4] = CmdNack
	binary.BigEndian.PutUint32(buf[5:9], uint32(bodyLen))
	copy(buf[9:25], sessionID)
	binary.BigEndian.PutUint32(buf[25:29], uint32(len(seqs)))
	off := 29
	for _, s := range seqs {
		binary.BigEndian.PutUint32(buf[off:off+4], s)
		off += 4
	}
	_, err := w.Write(buf)
	return err
}

// ParseNackPayload استخراج لیست seq از payload فریم CmdNack.
// ورودی همان payload برگشتی ReadFrame برای CmdNack است (بدون sessionID).
func ParseNackPayload(payload []byte) ([]uint32, error) {
	if len(payload) < 4 {
		return nil, errors.New("nack payload too short")
	}
	count := binary.BigEndian.Uint32(payload[0:4])
	if count > MaxNackSeqsPerFrame {
		return nil, fmt.Errorf("nack count too large: %d", count)
	}
	if int(4+4*count) > len(payload) {
		return nil, errors.New("nack payload truncated")
	}
	seqs := make([]uint32, count)
	off := 4
	for i := uint32(0); i < count; i++ {
		seqs[i] = binary.BigEndian.Uint32(payload[off : off+4])
		off += 4
	}
	return seqs, nil
}

// WriteTunRegister شروع نشست TUN-only روی این TCP (بدون CmdOpen).
func WriteTunRegister(w io.Writer) error {
	const bodyLen = 1
	buf := make([]byte, 4+1+4+bodyLen)
	buf[0], buf[1], buf[2], buf[3] = Magic0, Magic1, Magic2, Magic3
	buf[4] = CmdTunRegister
	binary.BigEndian.PutUint32(buf[5:9], bodyLen)
	buf[9] = 1 // نسخهٔ پروتکل فرعی tunmod
	_, err := w.Write(buf)
	return err
}

// WriteTunReady پاسخ سرور پس از پذیرش نشست TUN.
func WriteTunReady(w io.Writer) error {
	const bodyLen = 0
	buf := make([]byte, 4+1+4+bodyLen)
	buf[0], buf[1], buf[2], buf[3] = Magic0, Magic1, Magic2, Magic3
	buf[4] = CmdTunReady
	binary.BigEndian.PutUint32(buf[5:9], bodyLen)
	_, err := w.Write(buf)
	return err
}

// WriteTunData یک فریم L3 (معمولاً IPv4 کامل) از سمت peer دیگر.
func WriteTunData(w io.Writer, packet []byte) error {
	if len(packet) == 0 {
		return errors.New("tun data empty")
	}
	bodyLen := len(packet)
	buf := make([]byte, 4+1+4+bodyLen)
	buf[0], buf[1], buf[2], buf[3] = Magic0, Magic1, Magic2, Magic3
	buf[4] = CmdTunData
	binary.BigEndian.PutUint32(buf[5:9], uint32(bodyLen))
	copy(buf[9:], packet)
	_, err := w.Write(buf)
	return err
}

// WriteTunKeepalive زنده‌نگهدارندهٔ یکطرفه (طرف مقابل می‌تواند echo کند).
func WriteTunKeepalive(w io.Writer) error {
	const bodyLen = 0
	buf := make([]byte, 4+1+4+bodyLen)
	buf[0], buf[1], buf[2], buf[3] = Magic0, Magic1, Magic2, Magic3
	buf[4] = CmdTunKeepalive
	binary.BigEndian.PutUint32(buf[5:9], bodyLen)
	_, err := w.Write(buf)
	return err
}

// WriteClose بستن نشست از سمت کلاینت.
func WriteClose(w io.Writer, sessionID []byte) error {
	if len(sessionID) != 16 {
		return errors.New("session id must be 16 bytes")
	}
	bodyLen := 16
	buf := make([]byte, 4+1+4+bodyLen)
	buf[0], buf[1], buf[2], buf[3] = Magic0, Magic1, Magic2, Magic3
	buf[4] = CmdClose
	binary.BigEndian.PutUint32(buf[5:9], uint32(bodyLen))
	copy(buf[9:25], sessionID)
	_, err := w.Write(buf)
	return err
}

// ReadFrame خواندن یک فریم TCP کامل.
func ReadFrame(r io.Reader) (cmd byte, sessionID []byte, payload []byte, err error) {
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, nil, err
	}
	if hdr[0] != Magic0 || hdr[1] != Magic1 || hdr[2] != Magic2 || hdr[3] != Magic3 {
		return 0, nil, nil, ErrBadMagic
	}
	cmd = hdr[4]
	bodyLen := binary.BigEndian.Uint32(hdr[5:9])
	if bodyLen > 16*1024*1024 {
		return 0, nil, nil, fmt.Errorf("frame too large: %d", bodyLen)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, nil, err
	}
	switch cmd {
	case CmdOpen:
		if len(body) < 18 {
			return cmd, nil, nil, errors.New("open frame too short")
		}
		sessionID = append([]byte(nil), body[0:16]...)
		payload = append([]byte(nil), body[16:]...)
		return cmd, sessionID, payload, nil
	case CmdOpenOK:
		if len(body) < 17 {
			return cmd, nil, nil, errors.New("open_ok too short")
		}
		sessionID = append([]byte(nil), body[0:16]...)
		payload = append([]byte(nil), body[16:]...)
		return cmd, sessionID, payload, nil
	case CmdError:
		if len(body) < 3 {
			return cmd, nil, nil, errors.New("error frame too short")
		}
		msgLen := binary.BigEndian.Uint16(body[1:3])
		if int(msgLen)+3 > len(body) {
			return cmd, nil, nil, errors.New("error frame corrupt")
		}
		return cmd, nil, body[3 : 3+msgLen], nil
	case CmdData:
		if len(body) < 20 {
			return cmd, nil, nil, errors.New("data frame too short")
		}
		sessionID = append([]byte(nil), body[0:16]...)
		ln := binary.BigEndian.Uint32(body[16:20])
		if int(ln)+20 > len(body) {
			return cmd, nil, nil, errors.New("data length mismatch")
		}
		return cmd, sessionID, append([]byte(nil), body[20:20+ln]...), nil
	case CmdClose:
		if len(body) < 16 {
			return cmd, nil, nil, errors.New("close frame too short")
		}
		sessionID = append([]byte(nil), body[0:16]...)
		return cmd, sessionID, nil, nil
	case CmdNack:
		if len(body) < 20 {
			return cmd, nil, nil, errors.New("nack frame too short")
		}
		sessionID = append([]byte(nil), body[0:16]...)
		payload = append([]byte(nil), body[16:]...)
		return cmd, sessionID, payload, nil
	case CmdTunRegister:
		payload = append([]byte(nil), body...)
		return cmd, nil, payload, nil
	case CmdTunReady:
		return cmd, nil, nil, nil
	case CmdTunData:
		if len(body) < 1 {
			return cmd, nil, nil, errors.New("tun data frame empty")
		}
		return cmd, nil, append([]byte(nil), body...), nil
	case CmdTunKeepalive:
		return cmd, nil, nil, nil
	default:
		return cmd, nil, body, nil
	}
}

// WriteOpenOK تأیید باز شدن نشست (سمت سرور به کلاینت).
func WriteOpenOK(w io.Writer, sessionID []byte) error {
	bodyLen := 16 + 1
	buf := make([]byte, 4+1+4+bodyLen)
	buf[0], buf[1], buf[2], buf[3] = Magic0, Magic1, Magic2, Magic3
	buf[4] = CmdOpenOK
	binary.BigEndian.PutUint32(buf[5:9], uint32(bodyLen))
	copy(buf[9:25], sessionID)
	buf[25] = 1
	_, err := w.Write(buf)
	return err
}

// WriteError ارسال خطا به کلاینت روی TCP.
func WriteError(w io.Writer, msg string) error {
	msgBytes := []byte(msg)
	if len(msgBytes) > 0xffff {
		msgBytes = msgBytes[:0xffff]
	}
	bodyLen := 1 + 2 + len(msgBytes)
	buf := make([]byte, 4+1+4+bodyLen)
	buf[0], buf[1], buf[2], buf[3] = Magic0, Magic1, Magic2, Magic3
	buf[4] = CmdError
	binary.BigEndian.PutUint32(buf[5:9], uint32(bodyLen))
	buf[9] = 1
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(msgBytes)))
	copy(buf[12:], msgBytes)
	_, err := w.Write(buf)
	return err
}

// ParseOpenPayload بدنهٔ فریم Open پس از session_id (payload برگشتی ReadFrame برای CmdOpen).
func ParseOpenPayload(payload []byte) (host string, port uint16, err error) {
	if len(payload) < 2+2 {
		return "", 0, errors.New("open payload too short")
	}
	hl := binary.BigEndian.Uint16(payload[0:2])
	if int(2+hl)+2 > len(payload) {
		return "", 0, errors.New("open host len corrupt")
	}
	host = string(payload[2 : 2+hl])
	port = binary.BigEndian.Uint16(payload[2+hl : 4+hl])
	return host, port, nil
}

// MustParseHostPort برای تست و ابزارهای داخلی.
func MustParseHostPort(addr string) (string, uint16, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	portNum, err := net.LookupPort("tcp", p)
	if err != nil {
		return "", 0, err
	}
	if portNum < 1 || portNum > 65535 {
		return "", 0, errors.New("invalid port")
	}
	return h, uint16(portNum), nil
}
