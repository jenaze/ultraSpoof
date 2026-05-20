package client

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/ultraspoof/ultraspoof/internal/applog"
)

// serveHTTPConnect سرور HTTP CONNECT ساده.
func serveHTTPConnect(ln net.Listener, lg *applog.Logger, handler func(conn net.Conn, host string, port uint16) error) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			remote := c.RemoteAddr().String()
			lg.Debugf("HTTP accept from %s", remote)
			br := bufio.NewReader(c)
			req, err := http.ReadRequest(br)
			if err != nil {
				lg.Infof("HTTP read request failed peer=%s err=%v", remote, err)
				return
			}
			if strings.ToUpper(req.Method) != http.MethodConnect {
				fmt.Fprintf(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
				lg.Infof("HTTP method not CONNECT peer=%s method=%s", remote, req.Method)
				return
			}
			host := req.Host
			port := uint16(443)
			if h, p, err := net.SplitHostPort(req.Host); err == nil {
				host = h
				if v, err := strconv.ParseUint(p, 10, 16); err == nil {
					port = uint16(v)
				}
			}
			fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = handler(c, host, port)
		}()
	}
}
