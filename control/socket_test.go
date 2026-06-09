package control

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// runReq opens a fresh connection (one command per connection), writes a request line, reads
// the full response, and splits the trailing "\x04<code>\n" status frame off the body.
func runReq(t *testing.T, path, line string) (body string, code int) {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	out := string(data)
	idx := strings.LastIndexByte(out, StatusEOT)
	if idx < 0 {
		t.Fatalf("no status frame in response %q", out)
	}
	code, _ = strconv.Atoi(strings.TrimSpace(out[idx+1:]))
	return out[:idx], code
}

func waitFor(t *testing.T, want bool, path string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		_, err := os.Stat(path)
		if (err == nil) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for socket present=%v at %s", want, path)
}

// TestSocketServerDispatch is the Phase B acceptance at unit scope: a request line over the
// unix socket is dispatched through the registry, the command's output streams back, and the
// connection ends with a status frame the client can parse. Also covers help/-h, graceful
// unknown-command handling, the socket file mode (the local authz gate), and remove-on-stop.
func TestSocketServerDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctl.sock")

	reg := NewRegistry()
	reg.Register(&Command{
		Name:             "version",
		ShortDescription: "prints version",
		Callback: func(_ any, _ []string, w StringWriter) error {
			return w.WriteLine("v1.2.3")
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	srv := NewSocketServer(slog.New(slog.NewTextHandler(io.Discard, nil)), reg, path, 0o660, -1)
	go func() { _ = srv.Run(ctx) }()
	waitFor(t, true, path)

	// Registered command: output streamed, status 0.
	if body, code := runReq(t, path, "version"); !strings.Contains(body, "v1.2.3") || code != 0 {
		t.Fatalf("version: body=%q code=%d", body, code)
	}

	// Args reach the command's help (-h routes to help text).
	if body, _ := runReq(t, path, "version -h"); !strings.Contains(body, "prints version") {
		t.Fatalf("help: body=%q", body)
	}

	// Unknown command: graceful listing, not a transport error.
	if body, _ := runReq(t, path, "bogus"); !strings.Contains(body, "did not understand") {
		t.Fatalf("unknown: body=%q", body)
	}

	// Local authz gate: the socket file is mode 0660.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o660 {
		t.Fatalf("socket mode = %v, want 0660", perm)
	}

	// Remove-on-stop: cancelling the ctx tears down the listener and removes the file.
	cancel()
	waitFor(t, false, path)
}

// TestSocketCommandError covers the non-zero status path: a command callback that returns an
// error makes the server surface it and end the connection with exit code 1.
func TestSocketCommandError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctl.sock")

	reg := NewRegistry()
	reg.Register(&Command{
		Name:     "boom",
		Callback: func(_ any, _ []string, _ StringWriter) error { return io.ErrUnexpectedEOF },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewSocketServer(slog.New(slog.NewTextHandler(io.Discard, nil)), reg, path, 0o660, -1)
	go func() { _ = srv.Run(ctx) }()
	waitFor(t, true, path)

	body, code := runReq(t, path, "boom")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(body, "error:") {
		t.Fatalf("body = %q, want an error: line", body)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestSocketListenError covers Run's error return when the socket cannot be created.
func TestSocketListenError(t *testing.T) {
	srv := NewSocketServer(discardLogger(), NewRegistry(), "/nonexistent-dir-xyz/ctl.sock", 0o660, -1)
	if err := srv.Run(context.Background()); err == nil {
		t.Fatal("expected a listen error for an un-listenable path")
	}
}

// TestSocketEdgeCases covers handle's empty-connection and unparseable-request branches, and
// that the server keeps serving afterward.
func TestSocketEdgeCases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctl.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewSocketServer(discardLogger(), NewRegistry(), path, 0o660, -1)
	go func() { _ = srv.Run(ctx) }()
	waitFor(t, true, path)

	// Connect and close without sending a request: handled gracefully (no hang/panic).
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	// Unparseable request (unbalanced quote) -> parse error message + exit 1.
	if body, code := runReq(t, path, "\"unterminated"); code != 1 || !strings.Contains(body, "could not parse request") {
		t.Fatalf("parse-error: body=%q code=%d", body, code)
	}

	// Still serving after the edge cases.
	if body, code := runReq(t, path, "help"); code != 0 || !strings.Contains(body, "Available commands") {
		t.Fatalf("after edge cases: body=%q code=%d", body, code)
	}
}

// TestSocketSetPerms covers the reload path: SetPerms re-applies the mode to the live socket.
func TestSocketSetPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctl.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewSocketServer(slog.New(slog.NewTextHandler(io.Discard, nil)), NewRegistry(), path, 0o660, -1)
	go func() { _ = srv.Run(ctx) }()
	waitFor(t, true, path)

	// Re-apply with our own gid so the chown branch runs (chowning to a group we belong to is
	// allowed without privilege); mode 0600 confirms SetPerms took effect.
	srv.SetPerms(0o600, os.Getgid())
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("after SetPerms, mode = %v, want 0600", perm)
	}
}
