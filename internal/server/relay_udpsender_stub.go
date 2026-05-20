//go:build !linux

package server

import (
	"errors"
	"net"
)

func newRelayUDPSender(_ *net.UDPAddr, _ int, _ int, _ string) (udpDownloadSender, error) {
	return nil, errors.New("server.download.udp_relay is only supported on linux")
}
