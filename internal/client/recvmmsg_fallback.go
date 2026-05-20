//go:build !(linux && amd64)

package client

import (
	"net"
	"sync"
)

func recvLoopBatched(conn *net.UDPConn, _ int, _ int, pool *sync.Pool, emit func(buf *[]byte, size int, src *net.UDPAddr)) error {
	return recvLoopReadFromUDP(conn, pool, emit)
}
