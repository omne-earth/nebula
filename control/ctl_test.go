package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// fakeConn is an io.ReadWriter that discards writes and replays a canned response, with
// optional injected Write/Read errors - to reach exchange's I/O error branches without a
// real socket.
type fakeConn struct {
	resp []byte
	rpos int
	wErr error
	rErr error
}

func (f *fakeConn) Write(p []byte) (int, error) {
	if f.wErr != nil {
		return 0, f.wErr
	}
	return len(p), nil
}

func (f *fakeConn) Read(p []byte) (int, error) {
	if f.rErr != nil {
		return 0, f.rErr
	}
	if f.rpos >= len(f.resp) {
		return 0, io.EOF
	}
	n := copy(p, f.resp[f.rpos:])
	f.rpos += n
	return n, nil
}

// TestExchange covers exchange's four outcomes: write error, read error, a response with a
// status frame (body + exit code), and a non-conforming response with no frame.
func TestExchange(t *testing.T) {
	boom := errors.New("boom")

	if code := exchange(&fakeConn{wErr: boom}, []string{"x"}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("write error: code = %d, want 1", code)
	}
	if code := exchange(&fakeConn{rErr: boom}, []string{"x"}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("read error: code = %d, want 1", code)
	}

	// Body + "\x041\n" status frame -> body to stdout, exit 1.
	var out bytes.Buffer
	if code := exchange(&fakeConn{resp: []byte("oops\n\x041\n")}, []string{"x"}, &out, io.Discard); code != 1 {
		t.Fatalf("framed: code = %d, want 1", code)
	}
	if out.String() != "oops\n" {
		t.Fatalf("framed body = %q, want %q", out.String(), "oops\n")
	}

	// No status frame -> emit everything, success.
	out.Reset()
	if code := exchange(&fakeConn{resp: []byte("raw output")}, []string{"x"}, &out, io.Discard); code != 0 {
		t.Fatalf("unframed: code = %d, want 0", code)
	}
	if out.String() != "raw output" {
		t.Fatalf("unframed body = %q", out.String())
	}
}

// TestRunCtl covers RunCtl's arg handling and connection paths: flag error, no command, dial
// failure, and a full success round-trip against a real SocketServer.
func TestRunCtl(t *testing.T) {
	// Flag parse error -> exit 2.
	if code := RunCtl([]string{"-nope"}, "/x.sock", io.Discard, io.Discard); code != 2 {
		t.Fatalf("bad flag: code = %d, want 2", code)
	}
	// Flags but no command -> usage, exit 2.
	if code := RunCtl([]string{"-socket", "/x.sock"}, "/default.sock", io.Discard, io.Discard); code != 2 {
		t.Fatalf("no command: code = %d, want 2", code)
	}
	// Unreachable socket -> exit 1.
	if code := RunCtl([]string{"-socket", "/nonexistent-dir/x.sock", "version"}, "/d.sock", io.Discard, io.Discard); code != 1 {
		t.Fatalf("dial fail: code = %d, want 1", code)
	}

	// Success: real socket server, command dispatched, output streamed, exit 0.
	path := filepath.Join(t.TempDir(), "ctl.sock")
	reg := NewRegistry()
	reg.Register(&Command{
		Name:     "version",
		Callback: func(_ any, _ []string, w StringWriter) error { return w.WriteLine("v9.9.9") },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewSocketServer(discardLogger(), reg, path, 0o660, -1).Run(ctx) }()
	waitFor(t, true, path)

	var out bytes.Buffer
	if code := RunCtl([]string{"-socket", path, "version"}, "/d.sock", &out, io.Discard); code != 0 {
		t.Fatalf("success: code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "v9.9.9") {
		t.Fatalf("success: stdout = %q, want v9.9.9", out.String())
	}

	// A command whose callback errors -> exit 1, error surfaced (covers the framed non-zero
	// path end-to-end through the socket too).
	reg.Register(&Command{Name: "boom", Callback: func(_ any, _ []string, _ StringWriter) error { return errors.New("nope") }})
	out.Reset()
	if code := RunCtl([]string{"-socket", path, "boom"}, "/d.sock", &out, io.Discard); code != 1 {
		t.Fatalf("boom: code = %d, want 1", code)
	}
}
