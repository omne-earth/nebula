package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	shlex "github.com/anmitsu/go-shlex"
)

// StatusEOT prefixes the trailing status frame a command response ends with: after the
// command's text output the server writes "\x04<exitcode>\n". EOT (0x04) is chosen so a raw
// `nc -U`/`socat` session still shows readable output (the terminal swallows the control
// byte) while `nebula ctl` can split on it to recover the exit code. One command per
// connection: the client writes one request line, reads until EOF, the last frame is status.
const StatusEOT = 0x04

// SocketServer serves a control.Registry over a local unix-domain socket - the transport that
// replaces the embedded sshd for local admin. It is transport-only: it frames requests/
// responses and enforces the socket's filesystem perms; the commands themselves are the
// shared Registry. See .notes/NEBULA-CONTROL-PLANE.md.
type SocketServer struct {
	l    *slog.Logger
	reg  *Registry
	path string
	mode os.FileMode
	gid  int // -1: leave group ownership as-is (e.g. group not found / not privileged)

	mu sync.Mutex
	ln net.Listener
}

// NewSocketServer builds a server that will listen on path with the given mode, and (if gid
// >= 0) chown the socket to that group. It does not listen until Run is called.
func NewSocketServer(l *slog.Logger, reg *Registry, path string, mode os.FileMode, gid int) *SocketServer {
	return &SocketServer{l: l, reg: reg, path: path, mode: mode, gid: gid}
}

// Run removes any stale socket, listens, applies mode+group, and serves connections until ctx
// is cancelled or Stop is called. The socket file is removed on teardown (remove-on-stop). Run
// blocks; callers typically `go server.Run(ctx)`.
func (s *SocketServer) Run(ctx context.Context) error {
	// A leftover socket from an unclean shutdown would make Listen fail with EADDRINUSE.
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("control socket: removing stale %s: %w", s.path, err)
	}

	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("control socket: listen %s: %w", s.path, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	// Perms are the local authz gate: 0660 + a group the admins share. Apply before serving.
	s.applyPerms()

	// Tear down (close listener -> Accept returns -> remove file) when the daemon stops.
	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	// Snapshot mode under the lock: a concurrent reload (SetPerms) may write it.
	s.mu.Lock()
	mode := s.mode
	s.mu.Unlock()
	s.l.Info("control socket listening", "path", s.path, "mode", fmt.Sprintf("%#o", mode))

	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.l.Warn("control socket accept error, shutting down", "error", err)
			}
			break
		}
		go s.handle(conn)
	}

	// Best-effort cleanup; Listen above also removes a stale file on next start.
	_ = os.Remove(s.path)
	s.l.Info("control socket stopped listening", "path", s.path)
	return nil
}

// applyPerms sets the socket file mode and (if configured) its group owner, snapshotting the
// desired values under the lock so a concurrent reload (SetPerms) cannot tear them.
func (s *SocketServer) applyPerms() {
	s.mu.Lock()
	mode, gid := s.mode, s.gid
	s.mu.Unlock()

	if err := os.Chmod(s.path, mode); err != nil {
		s.l.Warn("control socket: failed to set mode", "path", s.path, "error", err)
	}
	if gid >= 0 {
		if err := os.Chown(s.path, -1, gid); err != nil {
			s.l.Warn("control socket: failed to set group", "path", s.path, "gid", gid, "error", err)
		}
	}
}

// SetPerms updates the desired mode/group and, if the socket is live, re-applies them. Used by
// config reload so an operator can tighten perms without restarting the daemon.
func (s *SocketServer) SetPerms(mode os.FileMode, gid int) {
	s.mu.Lock()
	s.mode = mode
	s.gid = gid
	live := s.ln != nil
	s.mu.Unlock()
	if live {
		s.applyPerms()
	}
}

// Stop closes the listener, which unblocks Accept and triggers file removal in Run.
func (s *SocketServer) Stop() {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.l.Warn("control socket: failed to close listener", "error", err)
		}
	}
}

// handle services one connection: read a single request line, dispatch it through the
// registry (output streamed to the client), then write the trailing status frame.
func (s *SocketServer) handle(conn net.Conn) {
	defer conn.Close()

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		// Client connected and closed without sending a request.
		return
	}

	w := NewStringWriter(conn)

	args, serr := shlex.Split(strings.TrimRight(line, "\r\n"), true)
	if serr != nil {
		_ = w.WriteLine("could not parse request: " + serr.Error())
		s.writeStatus(conn, 1)
		return
	}

	code := 0
	if derr := s.reg.Dispatch(args, w); derr != nil {
		// Dispatch only errors on a transport-level problem (commands report their own user
		// errors to w); surface it and exit non-zero so `nebula ctl` propagates it.
		_ = w.WriteLine("error: " + derr.Error())
		code = 1
	}
	s.writeStatus(conn, code)
}

func (s *SocketServer) writeStatus(conn net.Conn, code int) {
	if _, err := fmt.Fprintf(conn, "%c%d\n", StatusEOT, code); err != nil {
		s.l.Debug("control socket: failed to write status frame", "error", err)
	}
}
