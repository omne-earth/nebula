package control

import (
	"bytes"
	"flag"
	"io"
	"strings"
	"testing"
)

// errWriter fails every write, to exercise the WriteLine/Write error branches.
type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }

// TestRegistryDispatchByName is the Phase A acceptance: a command registered by name is
// dispatched by name, its callback runs, args after the name reach it, and its output lands
// on the supplied writer - all with no transport involved.
func TestRegistryDispatchByName(t *testing.T) {
	r := NewRegistry()

	ran := false
	var gotArgs []string
	r.Register(&Command{
		Name:             "ping",
		ShortDescription: "test ping",
		Callback: func(fs any, a []string, w StringWriter) error {
			ran = true
			gotArgs = a
			return w.WriteLine("pong")
		},
	})

	buf := &bytes.Buffer{}
	if err := r.Dispatch([]string{"ping", "a", "b"}, NewStringWriter(buf)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !ran {
		t.Fatal("callback did not run")
	}
	if got := strings.TrimSpace(buf.String()); got != "pong" {
		t.Fatalf("output = %q, want pong", got)
	}
	if len(gotArgs) != 2 || gotArgs[0] != "a" || gotArgs[1] != "b" {
		t.Fatalf("args = %v, want [a b]", gotArgs)
	}
}

// TestRegistryFlagsParsed confirms the structured flag mechanism survives the move: the
// registry parses a command's FlagSet out of argv before the callback runs.
func TestRegistryFlagsParsed(t *testing.T) {
	r := NewRegistry()

	type flags struct{ Pretty bool }
	gotPretty := false
	r.Register(&Command{
		Name: "show",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := &flags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "")
			return fl, s
		},
		Callback: func(fs any, a []string, w StringWriter) error {
			gotPretty = fs.(*flags).Pretty
			return nil
		},
	})

	if err := r.Dispatch([]string{"show", "-pretty"}, NewStringWriter(&bytes.Buffer{})); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !gotPretty {
		t.Fatal("-pretty flag was not parsed into the command's flag struct")
	}
}

// TestRegistryUnknownCommand: an unknown name prints a message and the command listing.
func TestRegistryUnknownCommand(t *testing.T) {
	r := NewRegistry()
	buf := &bytes.Buffer{}
	if err := r.Dispatch([]string{"nope"}, NewStringWriter(buf)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "did not understand") {
		t.Fatalf("missing did-not-understand: %q", out)
	}
	if !strings.Contains(out, "Available commands") {
		t.Fatalf("missing command listing: %q", out)
	}
}

// TestRegistryHelpMatchClone covers the built-in help, the empty-argv listing, -h routing,
// tab-complete prefix matching, and that a per-transport Clone (e.g. the sshd session's
// logout) does not leak back into the shared registry.
func TestRegistryHelpMatchClone(t *testing.T) {
	r := NewRegistry()
	r.Register(&Command{
		Name:             "version",
		ShortDescription: "prints version",
		Callback:         func(_ any, _ []string, _ StringWriter) error { return nil },
	})

	// Empty argv -> command listing.
	buf := &bytes.Buffer{}
	_ = r.Dispatch(nil, NewStringWriter(buf))
	if !strings.Contains(buf.String(), "version") {
		t.Fatalf("listing missing version: %q", buf.String())
	}

	// -h routes to the command's help (its short description).
	buf.Reset()
	_ = r.Dispatch([]string{"version", "-h"}, NewStringWriter(buf))
	if !strings.Contains(buf.String(), "prints version") {
		t.Fatalf("help missing description: %q", buf.String())
	}

	// Prefix match for tab-complete.
	if m := r.Match("ver"); len(m) != 1 || m[0] != "version" {
		t.Fatalf("Match(ver) = %v, want [version]", m)
	}

	// Clone isolation: a command added to the clone must not appear in the parent.
	clone := r.Clone()
	clone.Register(&Command{Name: "logout", Callback: func(_ any, _ []string, _ StringWriter) error { return nil }})
	if cmd, _ := r.Lookup("logout"); cmd != nil {
		t.Fatal("clone leaked logout into the parent registry")
	}
	if cmd, _ := clone.Lookup("logout"); cmd == nil {
		t.Fatal("clone did not register logout")
	}
}

// TestRegistryHelpDetailed exercises help for a command that has both Help text and a
// FlagSet, so the help body prints the description, the Help line, and the flag defaults.
func TestRegistryHelpDetailed(t *testing.T) {
	r := NewRegistry()
	r.Register(&Command{
		Name:             "print-cert",
		ShortDescription: "prints the cert",
		Help:             "pass a vpn addr to print that peer's cert",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := &struct{ Pretty bool }{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, s
		},
		Callback: func(_ any, _ []string, _ StringWriter) error { return nil },
	})

	buf := &bytes.Buffer{}
	if err := r.Help([]string{"print-cert"}, NewStringWriter(buf)); err != nil {
		t.Fatalf("help: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"prints the cert", "pass a vpn addr", "-pretty"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help output missing %q: %q", want, out)
		}
	}

	// Help for an unknown command is a graceful message, not an error.
	buf.Reset()
	if err := r.Help([]string{"nope"}, NewStringWriter(buf)); err != nil {
		t.Fatalf("help unknown: %v", err)
	}
	if !strings.Contains(buf.String(), "Command not available") {
		t.Fatalf("help unknown output: %q", buf.String())
	}
}

// TestStringWriter covers the StringWriter surface, including WriteBytes (used by print-cert
// for raw PEM/JSON) which the other tests do not hit.
func TestStringWriter(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewStringWriter(buf)
	if err := w.WriteBytes([]byte("raw-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteLine("a-line"); err != nil {
		t.Fatal(err)
	}
	if w.GetWriter() != buf {
		t.Fatal("GetWriter did not return the underlying writer")
	}
	if got := buf.String(); got != "raw-bytesa-line\n" {
		t.Fatalf("buffer = %q", got)
	}
}

// TestExecFlagParseError covers Exec's flag-parse error branch: an undefined flag makes
// FlagSet.Parse fail, which Exec (and thus Dispatch) returns.
func TestExecFlagParseError(t *testing.T) {
	r := NewRegistry()
	r.Register(&Command{
		Name: "show",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := &struct{ Pretty bool }{}
			fl.BoolVar(&s.Pretty, "pretty", false, "")
			return fl, s
		},
		Callback: func(_ any, _ []string, _ StringWriter) error { return nil },
	})
	if err := r.Dispatch([]string{"show", "-nope"}, NewStringWriter(io.Discard)); err == nil {
		t.Fatal("expected a flag parse error for the undefined -nope flag")
	}
}

// TestWriterErrorPaths covers the WriteLine/Write error branches: Dump bails after the first
// failing write, and Dispatch's unknown-command path returns the write error.
func TestWriterErrorPaths(t *testing.T) {
	r := NewRegistry()
	w := NewStringWriter(errWriter{})

	r.Dump(w) // must not panic; bails on the first failing WriteLine

	if err := r.Dispatch([]string{"bogus"}, w); err == nil {
		t.Fatal("expected the unknown-command WriteLine error to propagate from Dispatch")
	}
}
