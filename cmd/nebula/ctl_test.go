package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/control"
)

func waitForFile(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("control socket never appeared: %s", path)
}

// TestRunCtlIfRequested unit-covers the subcommand gate: a non-ctl argv falls through to the
// daemon; a `ctl` argv is handled (and here fails to connect, exit 1).
func TestRunCtlIfRequested(t *testing.T) {
	if handled, code := runCtlIfRequested([]string{"nebula", "-version"}, io.Discard, io.Discard); handled || code != 0 {
		t.Fatalf("non-ctl: handled=%v code=%d, want false 0", handled, code)
	}
	if handled, code := runCtlIfRequested([]string{"nebula", "ctl", "-socket", "/nonexistent-dir/x.sock", "version"}, io.Discard, io.Discard); !handled || code != 1 {
		t.Fatalf("ctl: handled=%v code=%d, want true 1", handled, code)
	}
}

// TestCtlCLI is the smoke-cli integration: it builds the real nebula binary, starts an
// in-process control socket with a couple of test commands, and exercises EVERY `nebula ctl`
// path through the actual binary - success, args, help, unknown, command error, unreachable
// socket, missing command, bad flag.
func TestCtlCLI(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "nebula")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build nebula: %v\n%s", err, out)
	}

	sock := filepath.Join(dir, "ctl.sock")
	reg := control.NewRegistry()
	reg.Register(&control.Command{
		Name:             "version",
		ShortDescription: "prints version",
		Callback:         func(_ any, _ []string, w control.StringWriter) error { return w.WriteLine("v9.9.9") },
	})
	reg.Register(&control.Command{
		Name:     "boom",
		Callback: func(_ any, _ []string, _ control.StringWriter) error { return errors.New("nope") },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := control.NewSocketServer(slog.New(slog.NewTextHandler(io.Discard, nil)), reg, sock, 0o660, -1)
	go func() { _ = srv.Run(ctx) }()
	waitForFile(t, sock)

	run := func(args ...string) (string, int) {
		cmd := exec.Command(bin, args...)
		var so bytes.Buffer
		cmd.Stdout = &so
		cmd.Stderr = io.Discard
		_ = cmd.Run()
		return so.String(), cmd.ProcessState.ExitCode()
	}

	cases := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string // substring expected on stdout ("" = no check)
	}{
		{"command", []string{"ctl", "-socket", sock, "version"}, 0, "v9.9.9"},
		{"help", []string{"ctl", "-socket", sock, "help"}, 0, "version"},
		{"unknown", []string{"ctl", "-socket", sock, "bogus"}, 0, "did not understand"},
		{"command-error", []string{"ctl", "-socket", sock, "boom"}, 1, ""},
		{"unreachable", []string{"ctl", "-socket", filepath.Join(dir, "nope.sock"), "version"}, 1, ""},
		{"no-command", []string{"ctl", "-socket", sock}, 2, ""},
		{"bad-flag", []string{"ctl", "-nope"}, 2, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := run(tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit = %d, want %d (out=%q)", code, tc.wantCode, out)
			}
			if tc.wantOut != "" && !strings.Contains(out, tc.wantOut) {
				t.Fatalf("stdout = %q, want substring %q", out, tc.wantOut)
			}
		})
	}
}
