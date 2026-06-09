package nebula

// Local control socket wiring: reads the control.* config and runs a unix-domain
// SocketServer that serves the shared control.Registry (the same commands the embedded sshd
// exposes under -tags sshd). This is the DEFAULT control transport - no x/crypto/ssh, no
// host keys - and replaces the embedded sshd for local admin. Remote control is qp-ssh
// forwarding the socket. See .notes/NEBULA-CONTROL-PLANE.md.

import (
	"context"
	"log/slog"
	"os"
	"os/user"
	"strconv"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/control"
)

// configControlSocket reads control.* and, if control.socket is set, returns a start func that
// runs the socket server. The server is ctx-scoped: it tears down (and removes the socket
// file) when ctx is cancelled, i.e. on Control.Stop. Returns (nil, nil) when disabled.
//
//	control.socket: /run/nebula.sock   # path; unset/empty disables the socket
//	control.mode:   0660               # socket file mode (local authz gate)
//	control.group:  nebula             # group owner; admins in this group can talk to it
func configControlSocket(ctx context.Context, l *slog.Logger, reg *control.Registry, c *config.C) (func(), error) {
	path := c.GetString("control.socket", "")
	if path == "" {
		return nil, nil
	}

	sl := l.With("subsystem", "control-socket")
	mode := os.FileMode(c.GetInt("control.mode", 0o660))
	gid := lookupControlGid(sl, c.GetString("control.group", "nebula"))

	srv := control.NewSocketServer(sl, reg, path, mode, gid)

	// Reload re-applies the perms (mode/group) to the live socket so they can be tightened
	// without a restart. A path change needs a restart (one socket per run); we log and skip.
	c.RegisterReloadCallback(func(nc *config.C) {
		if np := nc.GetString("control.socket", ""); np != path {
			sl.Warn("control.socket path change requires a restart to take effect", "old", path, "new", np)
			return
		}
		nmode := os.FileMode(nc.GetInt("control.mode", 0o660))
		ngid := lookupControlGid(sl, nc.GetString("control.group", "nebula"))
		srv.SetPerms(nmode, ngid)
	})

	return func() {
		if err := srv.Run(ctx); err != nil {
			sl.Warn("control socket exited", "error", err)
		}
	}, nil
}

// lookupControlGid resolves a group name to a gid for chowning the socket. An empty group or a
// lookup miss (common in dev/CI where the group does not exist) yields -1, meaning "leave the
// socket's group as-is" - the mode alone still gates access.
func lookupControlGid(l *slog.Logger, group string) int {
	if group == "" {
		return -1
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		l.Debug("control socket: group not found, leaving socket group as-is", "group", group, "error", err)
		return -1
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return gid
}
