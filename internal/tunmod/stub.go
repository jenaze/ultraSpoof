//go:build !linux

package tunmod

import (
	"fmt"
	"net"

	"github.com/ultraspoof/ultraspoof/internal/applog"
	"github.com/ultraspoof/ultraspoof/internal/config"
)

// RunClient روی غیر لینوکس خالی است (فعال‌سازی tunmod در validate رد می‌شود).
func RunClient(_ *config.Root, _ *applog.Logger, _ func() (net.Conn, error)) error {
	return nil
}

// ServeTunSession روی غیر لینوکس نباید فراخوانی شود.
func ServeTunSession(_ *config.Root, _ *applog.Logger, _ net.Conn, _ []byte) error {
	return fmt.Errorf("tunmod: Linux required")
}
