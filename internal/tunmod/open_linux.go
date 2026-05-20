//go:build linux

package tunmod

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ifReqLinux اندازهٔ ۴۰ بایتی struct ifreq روی linux/amd64 برای TUNSETIFF.
type ifReqLinux struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

// openTUN یک اینترفیس TUN بدون PI باز می‌کند (فریم‌ها خام L3 هستند).
func openTUN(deviceName string) (*os.File, error) {
	if len(deviceName) == 0 {
		return nil, errors.New("empty tun device name")
	}
	if len(deviceName) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("device name too long (max %d)", unix.IFNAMSIZ-1)
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var ifr ifReqLinux
	copy(ifr.Name[:], deviceName)
	ifr.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %v", errno)
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}
