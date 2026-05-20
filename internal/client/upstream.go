package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// DialSOCKS5TCP اتصال TCP به مقصد از طریق پروکسی SOCKS5.
func DialSOCKS5TCP(proxyAddr, destHost string, destPort uint16) (net.Conn, error) {
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	if err := socksHandshake(c); err != nil {
		c.Close()
		return nil, err
	}
	if err := socksRequestConnect(c, destHost, destPort); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func socksHandshake(rw io.ReadWriter) error {
	if _, err := rw.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(rw, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return fmt.Errorf("socks handshake failed: %v %v", buf[0], buf[1])
	}
	return nil
}

func socksRequestConnect(rw io.ReadWriter, host string, port uint16) error {
	hostBytes := []byte(host)
	if len(hostBytes) > 255 {
		return fmt.Errorf("host too long")
	}
	req := make([]byte, 0, 6+len(hostBytes))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(hostBytes)))
	req = append(req, hostBytes...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	req = append(req, pb...)
	if _, err := rw.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(rw, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks connect rejected: code %d", resp[1])
	}
	atyp := resp[3]
	switch atyp {
	case 0x01:
		if _, err := io.ReadFull(rw, make([]byte, 4+2)); err != nil {
			return err
		}
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(rw, l); err != nil {
			return err
		}
		if _, err := io.ReadFull(rw, make([]byte, int(l[0])+2)); err != nil {
			return err
		}
	case 0x04:
		if _, err := io.ReadFull(rw, make([]byte, 16+2)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown atyp %d", atyp)
	}
	return nil
}

// SplitHostPort همان net.SplitHostPort با پورت عددی.
func SplitHostPort(addr string) (host string, port uint16, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	pn, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return "", 0, err
	}
	return h, uint16(pn), nil
}
