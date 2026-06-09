package control

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// RunCtl is the `nebula ctl` client: connect to the daemon's control socket, send one command
// line, stream the response to stdout, and return the command's exit code. It is the transport
// peer of SocketServer - same line protocol, same trailing "\x04<code>\n" status frame.
//
// argv is everything after the "ctl" subcommand, e.g. ["-socket","/run/nebula.sock",
// "list-hostmap","-pretty"]. ctl's own flags (-socket) come first; flag parsing stops at the
// first non-flag argument, so the command name and everything after it pass through to the
// daemon verbatim. All output goes to the supplied writers (no globals) so the whole client is
// unit-testable.
func RunCtl(argv []string, defaultSocket string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nebula ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", defaultSocket, "path to the nebula control socket")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: nebula ctl [-socket path] <command> [args...]")
		fmt.Fprintln(stderr, "       nebula ctl help   # list available commands")
		fs.PrintDefaults()
	}

	if err := fs.Parse(argv); err != nil {
		// flag.Parse already wrote the error (and usage, via fs.Usage) to stderr.
		return 2
	}

	cmd := fs.Args()
	if len(cmd) == 0 {
		fs.Usage()
		return 2
	}

	conn, err := net.Dial("unix", *socket)
	if err != nil {
		fmt.Fprintf(stderr, "nebula ctl: cannot connect to %s: %v\n", *socket, err)
		return 1
	}
	defer conn.Close()

	return exchange(conn, cmd, stdout, stderr)
}

// exchange runs one request/response over an already-connected control socket: write the
// command line, read the streamed response, split off the trailing status frame, emit the body
// to stdout, and return the exit code. Split out from RunCtl so the I/O error paths are
// reachable in tests with a failing io.ReadWriter.
func exchange(rw io.ReadWriter, cmd []string, stdout, stderr io.Writer) int {
	if _, err := fmt.Fprintf(rw, "%s\n", strings.Join(cmd, " ")); err != nil {
		fmt.Fprintf(stderr, "nebula ctl: write failed: %v\n", err)
		return 1
	}

	data, err := io.ReadAll(rw)
	if err != nil {
		fmt.Fprintf(stderr, "nebula ctl: read failed: %v\n", err)
		return 1
	}

	// The response is the command's text output followed by "\x04<exitcode>\n".
	idx := bytes.LastIndexByte(data, StatusEOT)
	if idx < 0 {
		// No status frame (a non-conforming server) - emit what we got and assume success.
		stdout.Write(data)
		return 0
	}

	stdout.Write(data[:idx])
	code, _ := strconv.Atoi(strings.TrimSpace(string(data[idx+1:])))
	return code
}
