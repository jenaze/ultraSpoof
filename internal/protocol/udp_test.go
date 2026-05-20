package protocol

import (
	"bytes"
	"testing"

	"github.com/ultraspoof/ultraspoof/internal/crypto"
)

// TestSealCompat تأیید می‌کند نسخهٔ بهینهٔ SealUDPPacketWith دقیقاً همان بایت‌های
// نسخهٔ سازگار SealUDPPacket را تولید کند، تا کلاینت‌های قدیمی هم بتوانند
// رمزگشایی کنند.
func TestSealCompat(t *testing.T) {
	psk := []byte("a-pretty-strong-psk-32-bytes-long!")
	aead, err := crypto.NewUDPAEAD(psk)
	if err != nil {
		t.Fatal(err)
	}
	sid := []byte("0123456789ABCDEF")

	cases := []struct {
		name  string
		seq   uint32
		flags byte
		chunk []byte
	}{
		{"empty data", 0, FlagData, nil},
		{"small data", 7, FlagData, []byte("hello")},
		{"fin", 99, FlagFIN, nil},
		{"large data", 1234, FlagData, bytes.Repeat([]byte{0xAB}, 1400)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old, err := SealUDPPacket(psk, sid, tc.seq, tc.flags, tc.chunk)
			if err != nil {
				t.Fatal(err)
			}
			var scratch []byte
			newp := SealUDPPacketWith(aead, &scratch, sid, tc.seq, tc.flags, tc.chunk)
			if !bytes.Equal(old, newp) {
				t.Fatalf("seal mismatch:\n old(%d)=%x\n new(%d)=%x", len(old), old, len(newp), newp)
			}

			// رمزگشایی متقابل با هر دو API.
			gotSid1, gotSeq1, gotFlags1, gotPayload1, err := OpenUDPPacket(psk, newp)
			if err != nil {
				t.Fatalf("open(old api) on new packet: %v", err)
			}
			if !bytes.Equal(gotSid1, sid) || gotSeq1 != tc.seq || gotFlags1 != tc.flags || !bytes.Equal(gotPayload1, tc.chunk) {
				t.Fatalf("old api decode mismatch")
			}

			plainBuf := make([]byte, 0, 64)
			gotSid2, gotSeq2, gotFlags2, gotPayload2, err := OpenUDPPacketWith(aead, old, &plainBuf)
			if err != nil {
				t.Fatalf("open(new api) on old packet: %v", err)
			}
			if !bytes.Equal(gotSid2, sid) || gotSeq2 != tc.seq || gotFlags2 != tc.flags || !bytes.Equal(gotPayload2, tc.chunk) {
				t.Fatalf("new api decode mismatch")
			}
		})
	}
}

// TestPlainRoundtrip تأیید می‌کند نسخهٔ plain (بدون AEAD) بسته‌ها را درست تولید
// و بازیابی می‌کند.
func TestPlainRoundtrip(t *testing.T) {
	sid := []byte("0123456789ABCDEF")

	cases := []struct {
		name  string
		seq   uint32
		flags byte
		chunk []byte
	}{
		{"empty data", 0, FlagData, nil},
		{"small data", 7, FlagData, []byte("hello")},
		{"fin", 99, FlagFIN, nil},
		{"large data", 1234, FlagData, bytes.Repeat([]byte{0xAB}, 1377)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var scratch []byte
			pkt := SealUDPPacketPlain(&scratch, sid, tc.seq, tc.flags, tc.chunk)
			if len(pkt) != UDPPlainModeOverhead+len(tc.chunk) {
				t.Fatalf("plain len: got %d want %d", len(pkt), UDPPlainModeOverhead+len(tc.chunk))
			}
			pktCopy := make([]byte, len(pkt))
			copy(pktCopy, pkt)
			gotSid, gotSeq, gotFlags, gotPayload, err := OpenUDPPacketPlain(pktCopy)
			if err != nil {
				t.Fatalf("open plain: %v", err)
			}
			if !bytes.Equal(gotSid, sid) || gotSeq != tc.seq || gotFlags != tc.flags || !bytes.Equal(gotPayload, tc.chunk) {
				t.Fatalf("plain decode mismatch: sid=%x seq=%d flags=%d payload=%x", gotSid, gotSeq, gotFlags, gotPayload)
			}
		})
	}
}

// TestPlainRejectsAEAD تأیید می‌کند parser plain بستهٔ AEAD را رد می‌کند
// (جلوگیری از confusion بین دو حالت).
func TestPlainRejectsAEAD(t *testing.T) {
	psk := []byte("a-pretty-strong-psk-32-bytes-long!")
	sid := []byte("0123456789ABCDEF")
	aead, _ := crypto.NewUDPAEAD(psk)
	var scratch []byte
	aeadPkt := SealUDPPacketWith(aead, &scratch, sid, 1, FlagData, []byte("abc"))
	if _, _, _, _, err := OpenUDPPacketPlain(aeadPkt); err == nil {
		t.Fatalf("expected error parsing AEAD packet as plain")
	}
}

// TestSealReusesScratch تأیید می‌کند فراخوانی‌های متوالی روی همان scratch
// بدون تخصیص جدید کار می‌کنند و خروجی صحیح است.
func TestSealReusesScratch(t *testing.T) {
	psk := []byte("a-pretty-strong-psk-32-bytes-long!")
	aead, err := crypto.NewUDPAEAD(psk)
	if err != nil {
		t.Fatal(err)
	}
	sid := []byte("0123456789ABCDEF")
	var scratch []byte

	for seq := uint32(0); seq < 50; seq++ {
		chunk := bytes.Repeat([]byte{byte(seq)}, 1000+int(seq))
		newp := SealUDPPacketWith(aead, &scratch, sid, seq, FlagData, chunk)
		// کپی بسته (چون scratch در فراخوانی بعدی بازنویسی می‌شود)
		pkt := make([]byte, len(newp))
		copy(pkt, newp)

		gotSid, gotSeq, gotFlags, gotPayload, err := OpenUDPPacket(psk, pkt)
		if err != nil {
			t.Fatalf("seq %d open: %v", seq, err)
		}
		if !bytes.Equal(gotSid, sid) || gotSeq != seq || gotFlags != FlagData || !bytes.Equal(gotPayload, chunk) {
			t.Fatalf("seq %d mismatch", seq)
		}
	}
}
