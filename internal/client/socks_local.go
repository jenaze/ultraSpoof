package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/ultraspoof/ultraspoof/internal/applog"
)

// serveSOCKS5 یک سرور SOCKS5 مینیمال (بدون احراز هویت).
func serveSOCKS5(ln net.Listener, lg *applog.Logger, handler func(conn net.Conn, host string, port uint16) error) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			remote := c.RemoteAddr().String()
			lg.Debugf("SOCKS accept from %s", remote)
			if err := handleSOCKSConn(c, handler); err != nil {
				lg.Infof("SOCKS handshake failed peer=%s err=%v", remote, err)
				return
			}
		}()
	}
}

func handleSOCKSConn(c net.Conn, handler func(net.Conn, string, uint16) error) error {
	buf := make([]byte, 257)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("bad socks version")
	}
	nm := int(buf[1])
	if _, err := io.ReadFull(c, buf[:nm]); err != nil {
		return err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		return fmt.Errorf("unsupported socks cmd %d", buf[1])
	}
	atyp := buf[3]
	var host string
	switch atyp {
	case 0x01:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return err
		}
		host = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return err
		}
		l := int(buf[0])
		if _, err := io.ReadFull(c, buf[:l]); err != nil {
			return err
		}
		host = string(buf[:l])
	case 0x04:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return err
		}
		host = net.IP(buf[:16]).String()
	default:
		return fmt.Errorf("bad atyp %d", atyp)
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(buf[:2])

	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	return handler(c, host, port)
}
