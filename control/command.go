// Package control is the transport-neutral command plane for the nebula daemon: a
// name-keyed registry of debug/admin commands (list-hostmap, close-tunnel, reload,
// pprof, ...) that act on the live daemon's in-memory state. It carries NO transport: the
// embedded sshd (-tags sshd) dispatches into a Registry, and the upcoming local control
// socket will dispatch into the same one (see .notes/NEBULA-CONTROL-PLANE.md). The command
// model (Command/CommandFlags/CommandCallback/StringWriter) is upstream nebula's verbatim,
// lifted out of sshd/ so it no longer drags in golang.org/x/crypto/ssh.
package control

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/armon/go-radix"
)

// CommandFlags is a function called before help or command execution to parse command line flags
// It should return a flag.FlagSet instance and a pointer to the struct that will contain parsed flags
type CommandFlags func() (*flag.FlagSet, any)

// CommandCallback is the function called when your command should execute.
// fs will be a a pointer to the struct provided by Command.Flags callback, if there was one. -h and -help are reserved
// and handled automatically for you.
// a will be any unconsumed arguments, if no Command.Flags was available this will be all the flags passed in.
// w is the writer to use when sending messages back to the client.
// If an error is returned by the callback it is logged locally, the callback should handle messaging errors to the user
// where appropriate
type CommandCallback func(fs any, a []string, w StringWriter) error

type Command struct {
	Name             string
	ShortDescription string
	Help             string
	Flags            CommandFlags
	Callback         CommandCallback
}

// Registry is a name-keyed set of control commands plus the dispatch/help/tab-complete
// logic over them. It is the transport-neutral seam every front end (embedded sshd, the
// control socket) shares: register commands once, dispatch by name from any transport.
type Registry struct {
	commands *radix.Tree
}

// NewRegistry returns a registry preloaded with the built-in `help` command.
func NewRegistry() *Registry {
	r := &Registry{commands: radix.New()}
	r.Register(&Command{
		Name:             "help",
		ShortDescription: "prints available commands or help <command> for specific usage info",
		Callback: func(_ any, args []string, w StringWriter) error {
			return r.Help(args, w)
		},
	})
	return r
}

// Register adds a command, keyed by its Name. Last registration of a name wins.
func (r *Registry) Register(c *Command) {
	r.commands.Insert(c.Name, c)
}

// Clone returns a registry with a copy of the current command set, so a transport can add
// connection-scoped commands (e.g. the sshd session's `logout`) without mutating the shared
// registry. The Command values themselves are shared (callbacks are stateless re: copies).
func (r *Registry) Clone() *Registry {
	return &Registry{commands: radix.NewFromMap(r.commands.ToMap())}
}

// Lookup returns the command registered under exactly sCmd, or (nil, nil) if none.
func (r *Registry) Lookup(sCmd string) (*Command, error) {
	cmd, ok := r.commands.Get(sCmd)
	if !ok {
		return nil, nil
	}

	command, ok := cmd.(*Command)
	if !ok {
		return nil, errors.New("failed to cast command")
	}

	return command, nil
}

// Match returns the registered command names that have cmd as a prefix (for tab-complete).
func (r *Registry) Match(cmd string) []string {
	cmds := make([]string, 0)
	r.commands.WalkPrefix(cmd, func(found string, v any) bool {
		cmds = append(cmds, found)
		return false
	})
	sort.Strings(cmds)
	return cmds
}

// Dump writes the "Available commands:" listing to w.
func (r *Registry) Dump(w StringWriter) {
	err := w.WriteLine("Available commands:")
	if err != nil {
		return
	}

	cmds := make([]string, 0)
	for _, l := range r.all() {
		cmds = append(cmds, fmt.Sprintf("%s - %s", l.Name, l.ShortDescription))
	}

	sort.Strings(cmds)
	_ = w.Write(strings.Join(cmds, "\n") + "\n\n")
}

func (r *Registry) all() []*Command {
	cmds := make([]*Command, 0)
	r.commands.WalkPrefix("", func(found string, v any) bool {
		cmd, ok := v.(*Command)
		if ok {
			cmds = append(cmds, cmd)
		}
		return false
	})
	return cmds
}

// Dispatch runs argv as a single command invocation: argv[0] is the command name, argv[1:]
// its arguments. Empty argv lists the commands; an unknown name prints a message + the
// listing; a -h/-help anywhere routes to the command's help. This is the entry point every
// transport calls after splitting a request line into argv.
func (r *Registry) Dispatch(argv []string, w StringWriter) error {
	if len(argv) == 0 {
		r.Dump(w)
		return nil
	}

	c, err := r.Lookup(argv[0])
	if err != nil {
		return err
	}

	if c == nil {
		if err := w.WriteLine(fmt.Sprintf("did not understand: %s", strings.Join(argv, " "))); err != nil {
			return err
		}
		r.Dump(w)
		return nil
	}

	if CheckHelpArgs(argv[1:]) {
		return r.Help([]string{c.Name}, w)
	}

	return Exec(c, argv[1:], w)
}

// Help writes the command listing (no args) or a single command's help text (args[0]).
func (r *Registry) Help(a []string, w StringWriter) (err error) {
	// Just typed help
	if len(a) == 0 {
		r.Dump(w)
		return nil
	}

	// We are printing a specific commands help text
	cmd, err := r.Lookup(a[0])
	if err != nil {
		return
	}

	if cmd != nil {
		err = w.WriteLine(fmt.Sprintf("%s - %s", cmd.Name, cmd.ShortDescription))
		if err != nil {
			return err
		}

		if cmd.Help != "" {
			err = w.WriteLine(fmt.Sprintf("  %s", cmd.Help))
			if err != nil {
				return err
			}
		}

		if cmd.Flags != nil {
			fs, _ := cmd.Flags()
			if fs != nil {
				fs.SetOutput(w.GetWriter())
				fs.PrintDefaults()
			}
		}

		return nil
	}

	err = w.WriteLine("Command not available " + a[0])
	if err != nil {
		return err
	}

	return nil
}

// Exec parses a command's flags (if any) out of args and invokes its callback. Exposed so a
// transport that has already resolved a *Command (the sshd session does) can run it directly.
func Exec(c *Command, args []string, w StringWriter) error {
	var (
		fl *flag.FlagSet
		fs any
	)

	if c.Flags != nil {
		fl, fs = c.Flags()
		if fl != nil {
			// SetOutput() here in case fl.Parse dumps usage.
			fl.SetOutput(w.GetWriter())
			err := fl.Parse(args)
			if err != nil {
				// fl.Parse has dumped error information to the user via the w writer.
				return err
			}
			args = fl.Args()
		}
	}

	return c.Callback(fs, args, w)
}

// CheckHelpArgs reports whether -h or -help appears in args.
func CheckHelpArgs(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "-help" {
			return true
		}
	}

	return false
}
