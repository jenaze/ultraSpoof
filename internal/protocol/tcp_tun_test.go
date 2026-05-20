package protocol

import (
	"bytes"
	"testing"
)

func TestTunFramesRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTunRegister(&buf); err != nil {
		t.Fatal(err)
	}
	cmd, _, pay, err := ReadFrame(&buf)
	if err != nil || cmd != CmdTunRegister || len(pay) != 1 || pay[0] != 1 {
		t.Fatalf("register: cmd=%d pay=%v err=%v", cmd, pay, err)
	}

	buf.Reset()
	if err := WriteTunReady(&buf); err != nil {
		t.Fatal(err)
	}
	cmd, _, pay, err = ReadFrame(&buf)
	if err != nil || cmd != CmdTunReady || pay != nil {
		t.Fatalf("ready: cmd=%d pay=%v err=%v", cmd, pay, err)
	}

	pkt := []byte{0x45, 0x00, 0x00, 0x14} // minimal IPv4-like header fragment
	buf.Reset()
	if err := WriteTunData(&buf, pkt); err != nil {
		t.Fatal(err)
	}
	cmd, _, pay, err = ReadFrame(&buf)
	if err != nil || cmd != CmdTunData || string(pay) != string(pkt) {
		t.Fatalf("data: cmd=%d pay=%v err=%v", cmd, pay, err)
	}
}
