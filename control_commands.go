package nebula

// Transport-neutral control commands: the ~20 debug/admin commands (list-hostmap,
// close-tunnel, reload, pprof, ...) that act on the live daemon's in-memory state. They
// register on a control.Registry and are served by whatever transport is present - the
// embedded sshd (-tags sshd) today, the local control socket next (see
// .notes/NEBULA-CONTROL-PLANE.md). NOTHING here depends on a transport: callbacks take only
// (parsed flags, args, control.StringWriter). Lifted out of ssh.go (which was -tags sshd)
// so the default build carries the commands without the embedded ssh server or x/crypto/ssh.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/control"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/logging"
)

type sshListHostMapFlags struct {
	Json    bool
	Pretty  bool
	ByIndex bool
}

type sshPrintCertFlags struct {
	Json   bool
	Pretty bool
	Raw    bool
}

type sshPrintTunnelFlags struct {
	Pretty bool
}

type sshChangeRemoteFlags struct {
	Address string
}

type sshCloseTunnelFlags struct {
	LocalOnly bool
}

type sshCreateTunnelFlags struct {
	Address string
}

type sshDeviceInfoFlags struct {
	Json   bool
	Pretty bool
}

// attachCommands registers the daemon's control commands on reg. Called once during startup
// (in both builds) after the Interface is up; the commands close over f for live state.
func attachCommands(l *slog.Logger, c *config.C, reg *control.Registry, f *Interface) {
	// sandboxDir defaults to a dir in temp. The intention is that end user will
	// create this dir as needed. Overriding this config value to "" allows
	// writing to anywhere in the system. Migrated from the old `sshd.sandbox_dir`
	// to `control.sandbox_dir` (still falls back to the legacy key for old configs).
	defaultDir := filepath.Join(os.TempDir(), "nebula-debug")
	sandboxDir := c.GetString("control.sandbox_dir", c.GetString("sshd.sandbox_dir", defaultDir))

	reg.Register(&control.Command{
		Name:             "list-hostmap",
		ShortDescription: "List all known previously connected hosts",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.ByIndex, "by-index", false, "gets all hosts in the hostmap from the index table")
			return fl, &s
		},
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshListHostMap(f.hostMap, fs, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "list-pending-hostmap",
		ShortDescription: "List all handshaking hosts",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.ByIndex, "by-index", false, "gets all hosts in the hostmap from the index table")
			return fl, &s
		},
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshListHostMap(f.handshakeManager, fs, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "list-lighthouse-addrmap",
		ShortDescription: "List all lighthouse map entries",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshListLighthouseMap(f.lightHouse, fs, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "reload",
		ShortDescription: "Reloads configuration from disk, same as sending HUP to the process",
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshReload(c, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "start-cpu-profile",
		ShortDescription: "Starts a cpu profile and write output to the provided file, ex: `cpu-profile.pb.gz`",
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshStartCpuProfile(sandboxDir, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "stop-cpu-profile",
		ShortDescription: "Stops a cpu profile and writes output to the previously provided file",
		Callback: func(fs any, a []string, w control.StringWriter) error {
			pprof.StopCPUProfile()
			return w.WriteLine("If a CPU profile was running it is now stopped")
		},
	})

	reg.Register(&control.Command{
		Name:             "save-heap-profile",
		ShortDescription: "Saves a heap profile to the provided path, ex: `heap-profile.pb.gz`",
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshGetHeapProfile(sandboxDir, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "mutex-profile-fraction",
		ShortDescription: "Gets or sets runtime.SetMutexProfileFraction",
		Callback:         sshMutexProfileFraction,
	})

	reg.Register(&control.Command{
		Name:             "save-mutex-profile",
		ShortDescription: "Saves a mutex profile to the provided path, ex: `mutex-profile.pb.gz`",
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshGetMutexProfile(sandboxDir, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "log-level",
		ShortDescription: "Gets or sets the current log level",
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshLogLevel(l, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "log-format",
		ShortDescription: "Gets or sets the current log format",
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshLogFormat(l, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "version",
		ShortDescription: "Prints the currently running version of nebula",
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshVersion(f, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "device-info",
		ShortDescription: "Prints information about the network device.",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshDeviceInfoFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshDeviceInfo(f, fs, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "print-cert",
		ShortDescription: "Prints the current certificate being used or the certificate for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintCertFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.Raw, "raw", false, "raw prints the PEM encoded certificate, not compatible with -json or -pretty")
			return fl, &s
		},
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshPrintCert(f, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "print-tunnel",
		ShortDescription: "Prints json details about a tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshPrintTunnel(f, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "print-relays",
		ShortDescription: "Prints json details about all relay info",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshPrintRelays(f, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "change-remote",
		ShortDescription: "Changes the remote address used in the tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshChangeRemoteFlags{}
			fl.StringVar(&s.Address, "address", "", "The new remote address, ip:port")
			return fl, &s
		},
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshChangeRemote(f, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "close-tunnel",
		ShortDescription: "Closes a tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshCloseTunnelFlags{}
			fl.BoolVar(&s.LocalOnly, "local-only", false, "Disables notifying the remote that the tunnel is shutting down")
			return fl, &s
		},
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshCloseTunnel(f, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "create-tunnel",
		ShortDescription: "Creates a tunnel for the provided vpn address",
		Help:             "The lighthouses will be queried for real addresses but you can provide one as well.",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshCreateTunnelFlags{}
			fl.StringVar(&s.Address, "address", "", "Optionally provide a real remote address, ip:port ")
			return fl, &s
		},
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshCreateTunnel(f, fs, a, w)
		},
	})

	reg.Register(&control.Command{
		Name:             "query-lighthouse",
		ShortDescription: "Query the lighthouses for the provided vpn address",
		Help:             "This command is asynchronous. Only currently known udp addresses will be printed.",
		Callback: func(fs any, a []string, w control.StringWriter) error {
			return sshQueryLighthouse(f, fs, a, w)
		},
	})
}

func sshListHostMap(hl controlHostLister, a any, w control.StringWriter) error {
	fs, ok := a.(*sshListHostMapFlags)
	if !ok {
		return nil
	}

	var hm []ControlHostInfo
	if fs.ByIndex {
		hm = listHostMapIndexes(hl)
	} else {
		hm = listHostMapHosts(hl)
	}

	sort.Slice(hm, func(i, j int) bool {
		return hm[i].VpnAddrs[0].Compare(hm[j].VpnAddrs[0]) < 0
	})

	if fs.Json || fs.Pretty {
		js := json.NewEncoder(w.GetWriter())
		if fs.Pretty {
			js.SetIndent("", "    ")
		}

		err := js.Encode(hm)
		if err != nil {
			return nil
		}

	} else {
		for _, v := range hm {
			err := w.WriteLine(fmt.Sprintf("%s: %s", v.VpnAddrs, v.RemoteAddrs))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func sshListLighthouseMap(lightHouse *LightHouse, a any, w control.StringWriter) error {
	fs, ok := a.(*sshListHostMapFlags)
	if !ok {
		return nil
	}

	type lighthouseInfo struct {
		VpnAddr string    `json:"vpnAddr"`
		Addrs   *CacheMap `json:"addrs"`
	}

	lightHouse.RLock()
	addrMap := make([]lighthouseInfo, len(lightHouse.addrMap))
	x := 0
	for k, v := range lightHouse.addrMap {
		addrMap[x] = lighthouseInfo{
			VpnAddr: k.String(),
			Addrs:   v.CopyCache(),
		}
		x++
	}
	lightHouse.RUnlock()

	sort.Slice(addrMap, func(i, j int) bool {
		return strings.Compare(addrMap[i].VpnAddr, addrMap[j].VpnAddr) < 0
	})

	if fs.Json || fs.Pretty {
		js := json.NewEncoder(w.GetWriter())
		if fs.Pretty {
			js.SetIndent("", "    ")
		}

		err := js.Encode(addrMap)
		if err != nil {
			return nil
		}

	} else {
		for _, v := range addrMap {
			b, err := json.Marshal(v.Addrs)
			if err != nil {
				return err
			}
			err = w.WriteLine(fmt.Sprintf("%s: %s", v.VpnAddr, string(b)))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// sshSanitizeFilePath validates that the given file path is within the sandbox directory.
// If sandboxDir is empty, the path is returned as-is for backwards compatibility.
func sshSanitizeFilePath(sandboxDir, filePath string) (string, error) {
	if sandboxDir == "" {
		return filePath, nil
	}

	// Clean and resolve the path relative to the sandbox directory
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(sandboxDir, filePath)
	}
	cleaned := filepath.Clean(filePath)

	// Ensure the resolved path is within the sandbox directory
	cleanedSandbox := filepath.Clean(sandboxDir)
	if cleaned == cleanedSandbox {
		return "", fmt.Errorf("path %q resolves to the sandbox directory itself %q", filePath, sandboxDir)
	}
	if !strings.HasPrefix(cleaned, cleanedSandbox+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside the sandbox directory %q", filePath, sandboxDir)
	}

	return cleaned, nil
}

func sshStartCpuProfile(sandboxDir string, fs any, a []string, w control.StringWriter) error {
	if len(a) == 0 {
		err := w.WriteLine("No path to write profile provided")
		return err
	}

	filePath, err := sshSanitizeFilePath(sandboxDir, a[0])
	if err != nil {
		return w.WriteLine(err.Error())
	}

	file, err := os.Create(filePath)
	if err != nil {
		err = w.WriteLine(fmt.Sprintf("Unable to create profile file: %s", err))
		return err
	}

	err = pprof.StartCPUProfile(file)
	if err != nil {
		err = w.WriteLine(fmt.Sprintf("Unable to start cpu profile: %s", err))
		return err
	}

	err = w.WriteLine(fmt.Sprintf("Started cpu profile, issue stop-cpu-profile to write the output to %s", a))
	return err
}

func sshVersion(ifce *Interface, fs any, a []string, w control.StringWriter) error {
	return w.WriteLine(fmt.Sprintf("%s", ifce.version))
}

func sshQueryLighthouse(ifce *Interface, fs any, a []string, w control.StringWriter) error {
	if len(a) == 0 {
		return w.WriteLine("No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	var cm *CacheMap
	rl := ifce.lightHouse.Query(vpnAddr)
	if rl != nil {
		cm = rl.CopyCache()
	}
	return json.NewEncoder(w.GetWriter()).Encode(cm)
}

func sshCloseTunnel(ifce *Interface, fs any, a []string, w control.StringWriter) error {
	flags, ok := fs.(*sshCloseTunnelFlags)
	if !ok {
		return nil
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn address: %v", a[0]))
	}

	if !flags.LocalOnly {
		ifce.send(
			header.CloseTunnel,
			0,
			hostInfo.ConnectionState,
			hostInfo,
			[]byte{},
			make([]byte, 12, 12),
			make([]byte, mtu),
		)
	}

	ifce.closeTunnel(hostInfo)
	return w.WriteLine("Closed")
}

func sshCreateTunnel(ifce *Interface, fs any, a []string, w control.StringWriter) error {
	flags, ok := fs.(*sshCreateTunnelFlags)
	if !ok {
		return nil
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo != nil {
		return w.WriteLine(fmt.Sprintf("Tunnel already exists"))
	}

	hostInfo = ifce.handshakeManager.QueryVpnAddr(vpnAddr)
	if hostInfo != nil {
		return w.WriteLine(fmt.Sprintf("Tunnel already handshaking"))
	}

	var addr netip.AddrPort
	if flags.Address != "" {
		addr, err = netip.ParseAddrPort(flags.Address)
		if err != nil {
			return w.WriteLine("Address could not be parsed")
		}
	}

	hostInfo = ifce.handshakeManager.StartHandshake(vpnAddr, nil)
	if addr.IsValid() {
		hostInfo.SetRemote(addr)
	}

	return w.WriteLine("Created")
}

func sshChangeRemote(ifce *Interface, fs any, a []string, w control.StringWriter) error {
	flags, ok := fs.(*sshChangeRemoteFlags)
	if !ok {
		return nil
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn address was provided")
	}

	if flags.Address == "" {
		return w.WriteLine("No address was provided")
	}

	addr, err := netip.ParseAddrPort(flags.Address)
	if err != nil {
		return w.WriteLine("Address could not be parsed")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn address: %v", a[0]))
	}

	hostInfo.SetRemote(addr)
	return w.WriteLine("Changed")
}

func sshGetHeapProfile(sandboxDir string, fs any, a []string, w control.StringWriter) error {
	if len(a) == 0 {
		return w.WriteLine("No path to write profile provided")
	}

	filePath, err := sshSanitizeFilePath(sandboxDir, a[0])
	if err != nil {
		return w.WriteLine(err.Error())
	}

	file, err := os.Create(filePath)
	if err != nil {
		err = w.WriteLine(fmt.Sprintf("Unable to create profile file: %s", err))
		return err
	}

	err = pprof.WriteHeapProfile(file)
	if err != nil {
		err = w.WriteLine(fmt.Sprintf("Unable to write profile: %s", err))
		return err
	}

	err = w.WriteLine(fmt.Sprintf("Mem profile created at %s", a))
	return err
}

func sshMutexProfileFraction(fs any, a []string, w control.StringWriter) error {
	if len(a) == 0 {
		rate := runtime.SetMutexProfileFraction(-1)
		return w.WriteLine(fmt.Sprintf("Current value: %d", rate))
	}

	newRate, err := strconv.Atoi(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Invalid argument: %s", a[0]))
	}

	oldRate := runtime.SetMutexProfileFraction(newRate)
	return w.WriteLine(fmt.Sprintf("New value: %d. Old value: %d", newRate, oldRate))
}

func sshGetMutexProfile(sandboxDir string, fs any, a []string, w control.StringWriter) error {
	if len(a) == 0 {
		return w.WriteLine("No path to write profile provided")
	}

	filePath, err := sshSanitizeFilePath(sandboxDir, a[0])
	if err != nil {
		return w.WriteLine(err.Error())
	}

	file, err := os.Create(filePath)
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Unable to create profile file: %s", err))
	}
	defer file.Close()

	mutexProfile := pprof.Lookup("mutex")
	if mutexProfile == nil {
		return w.WriteLine("Unable to get pprof.Lookup(\"mutex\")")
	}

	err = mutexProfile.WriteTo(file, 0)
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Unable to write profile: %s", err))
	}

	return w.WriteLine(fmt.Sprintf("Mutex profile created at %s", a))
}

func sshLogLevel(l *slog.Logger, fs any, a []string, w control.StringWriter) error {
	ctrl, ok := l.Handler().(interface {
		GetLevel() slog.Level
		SetLevel(slog.Level)
	})
	if !ok {
		return w.WriteLine("Log level is not reconfigurable on this logger")
	}

	if len(a) == 0 {
		return w.WriteLine(fmt.Sprintf("Log level is: %s", logging.LevelName(ctrl.GetLevel())))
	}

	level, err := logging.ParseLevel(strings.ToLower(a[0]))
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Unknown log level %s. Possible log levels: trace, debug, info, warn, error", a))
	}

	ctrl.SetLevel(level)
	return w.WriteLine(fmt.Sprintf("Log level is: %s", logging.LevelName(ctrl.GetLevel())))
}

func sshLogFormat(l *slog.Logger, fs any, a []string, w control.StringWriter) error {
	ctrl, ok := l.Handler().(interface {
		GetFormat() string
		SetFormat(string) error
	})
	if !ok {
		return w.WriteLine("Log format is not reconfigurable on this logger")
	}

	if len(a) == 0 {
		return w.WriteLine(fmt.Sprintf("Log format is: %s", ctrl.GetFormat()))
	}

	if err := ctrl.SetFormat(strings.ToLower(a[0])); err != nil {
		return err
	}
	return w.WriteLine(fmt.Sprintf("Log format is: %s", ctrl.GetFormat()))
}

func sshPrintCert(ifce *Interface, fs any, a []string, w control.StringWriter) error {
	args, ok := fs.(*sshPrintCertFlags)
	if !ok {
		return nil
	}

	cert := ifce.pki.getCertState().GetDefaultCertificate()
	if len(a) > 0 {
		vpnAddr, err := netip.ParseAddr(a[0])
		if err != nil {
			return w.WriteLine(fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
		}

		if !vpnAddr.IsValid() {
			return w.WriteLine(fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
		}

		hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
		if hostInfo == nil {
			return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn addr: %v", a[0]))
		}

		cert = hostInfo.GetCert().Certificate
	}

	if args.Json || args.Pretty {
		b, err := cert.MarshalJSON()
		if err != nil {
			return nil
		}

		if args.Pretty {
			buf := new(bytes.Buffer)
			err := json.Indent(buf, b, "", "    ")
			b = buf.Bytes()
			if err != nil {
				return nil
			}
		}

		return w.WriteBytes(b)
	}

	if args.Raw {
		b, err := cert.MarshalPEM()
		if err != nil {
			return nil
		}

		return w.WriteBytes(b)
	}

	return w.WriteLine(cert.String())
}

func sshPrintRelays(ifce *Interface, fs any, a []string, w control.StringWriter) error {
	args, ok := fs.(*sshPrintTunnelFlags)
	if !ok {
		w.WriteLine(fmt.Sprintf("sshPrintRelays failed to convert args type"))
		return nil
	}

	relays := map[uint32]*HostInfo{}
	ifce.hostMap.Lock()
	maps.Copy(relays, ifce.hostMap.Relays)
	ifce.hostMap.Unlock()

	type RelayFor struct {
		Error          error
		Type           string
		State          string
		PeerAddr       netip.Addr
		LocalIndex     uint32
		RemoteIndex    uint32
		RelayedThrough []netip.Addr
	}

	type RelayOutput struct {
		NebulaAddr    netip.Addr
		RelayForAddrs []RelayFor
	}

	type CmdOutput struct {
		Relays []*RelayOutput
	}

	co := CmdOutput{}

	enc := json.NewEncoder(w.GetWriter())

	if args.Pretty {
		enc.SetIndent("", "    ")
	}

	for k, v := range relays {
		ro := RelayOutput{NebulaAddr: v.vpnAddrs[0]}
		co.Relays = append(co.Relays, &ro)
		relayHI := ifce.hostMap.QueryVpnAddr(v.vpnAddrs[0])
		if relayHI == nil {
			ro.RelayForAddrs = append(ro.RelayForAddrs, RelayFor{Error: errors.New("could not find hostinfo")})
			continue
		}
		for _, vpnAddr := range relayHI.relayState.CopyRelayForIps() {
			rf := RelayFor{Error: nil}
			r, ok := relayHI.relayState.GetRelayForByAddr(vpnAddr)
			if ok {
				t := ""
				switch r.Type {
				case ForwardingType:
					t = "forwarding"
				case TerminalType:
					t = "terminal"
				default:
					t = "unknown"
				}

				s := ""
				switch r.State {
				case Requested:
					s = "requested"
				case Established:
					s = "established"
				default:
					s = "unknown"
				}

				rf.LocalIndex = r.LocalIndex
				rf.RemoteIndex = r.RemoteIndex
				rf.PeerAddr = r.PeerAddr
				rf.Type = t
				rf.State = s
				if rf.LocalIndex != k {
					rf.Error = fmt.Errorf("hostmap LocalIndex '%v' does not match RelayState LocalIndex", k)
				}
			}
			relayedHI := ifce.hostMap.QueryVpnAddr(vpnAddr)
			if relayedHI != nil {
				rf.RelayedThrough = append(rf.RelayedThrough, relayedHI.relayState.CopyRelayIps()...)
			}

			ro.RelayForAddrs = append(ro.RelayForAddrs, rf)
		}
	}
	err := enc.Encode(co)
	if err != nil {
		return err
	}
	return nil
}

func sshPrintTunnel(ifce *Interface, fs any, a []string, w control.StringWriter) error {
	args, ok := fs.(*sshPrintTunnelFlags)
	if !ok {
		return nil
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return w.WriteLine(fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn addr: %v", a[0]))
	}

	enc := json.NewEncoder(w.GetWriter())
	if args.Pretty {
		enc.SetIndent("", "    ")
	}

	return enc.Encode(copyHostInfo(hostInfo, ifce.hostMap.GetPreferredRanges()))
}

func sshDeviceInfo(ifce *Interface, fs any, w control.StringWriter) error {

	data := struct {
		Name string         `json:"name"`
		Cidr []netip.Prefix `json:"cidr"`
	}{
		Name: ifce.inside.Name(),
		Cidr: make([]netip.Prefix, len(ifce.inside.Networks())),
	}

	copy(data.Cidr, ifce.inside.Networks())

	flags, ok := fs.(*sshDeviceInfoFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be sshDeviceInfoFlags but was %+v", fs)
	}

	if flags.Json || flags.Pretty {
		js := json.NewEncoder(w.GetWriter())
		if flags.Pretty {
			js.SetIndent("", "    ")
		}

		return js.Encode(data)
	} else {
		return w.WriteLine(fmt.Sprintf("name=%v cidr=%v", data.Name, data.Cidr))
	}
}

func sshReload(c *config.C, w control.StringWriter) error {
	err := w.WriteLine("Reloading config")
	c.ReloadConfig()
	return err
}
