//go:build linux

package tunmod

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// configureTUNLink آدرس، MTU و up را با iproute2 اعمال می‌کند (نیازمند قابلیت CAP_NET_ADMIN معمولاً با root).
func configureTUNLink(ctx context.Context, dev, localCIDR string, mtu int) error {
	if mtu <= 0 {
		mtu = 1400
	}
	run := func(args ...string) error {
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cctx, "ip", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("ip %v: %w: %s", args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run("link", "set", "dev", dev, "mtu", fmt.Sprintf("%d", mtu)); err != nil {
		return err
	}
	if err := run("addr", "replace", localCIDR, "dev", dev); err != nil {
		return err
	}
	if err := run("link", "set", "dev", dev, "up"); err != nil {
		return err
	}
	return nil
}
