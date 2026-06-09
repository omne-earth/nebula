//go:build !sshd

package nebula

import (
	"context"
	"log/slog"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/control"
)

// Default-build seam: the embedded ssh control server is compiled out (no sshd/ package,
// no golang.org/x/crypto/ssh). The control commands themselves are transport-neutral and
// live in control_commands.go (built in BOTH configs); only the ssh transport that would
// serve them is stubbed here. Build with `-tags sshd` to restore the embedded sshd.
// sshControl is an opaque no-op handle. See .notes/NEBULA-CONTROL-PLANE.md.
type sshControl = *struct{}

func newSSHControl(_ context.Context, _ *slog.Logger, _ *control.Registry) (sshControl, error) {
	return nil, nil
}

func wireSSHReload(_ *slog.Logger, _ sshControl, _ *config.C) {}

func configSSH(_ *slog.Logger, _ sshControl, _ *config.C) (func(), error) { return nil, nil }
