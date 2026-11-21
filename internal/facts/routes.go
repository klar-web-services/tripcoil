package facts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// Routes is facts/routes.json: what the proxies and tunnels on this machine route to. Their
// configuration is often readable by root only, so root reads it, and keeps nothing of it but the
// targets and the names served.
type Routes struct {
	Programs []RouteProgram `json:"programs"`
}

type RouteProgram struct {
	Item    string `json:"item"`
	Program string `json:"program"`
	// Kind is ViaProxy or ViaTunnel.
	Kind string `json:"kind"`
	// Tailnet: only the tailnet reaches what it serves (Tailscale Serve), whatever its sockets say.
	Tailnet bool `json:"tailnet,omitempty"`
	// Complete is true only when everything the program routes by was found, read and understood.
	// Otherwise it may route to things this fact does not name, and Gaps say why.
	Complete  bool          `json:"complete"`
	Gaps      []string      `json:"gaps,omitempty"`
	Hostnames []string      `json:"hostnames"`
	Targets   []RouteTarget `json:"targets"`
}

type RouteTarget struct {
	Target string `json:"target"`
	// Item is the item that answers there, when it is one of this machine's.
	Item string `json:"item,omitempty"`
}

// The programs whose routing Tripcoil reads, and those it only knows by name.
var (
	readRouters  = map[string]string{"traefik": ViaProxy, "caddy": ViaProxy, "nginx": ViaProxy, "cloudflared": ViaTunnel}
	knownRouters = map[string]string{"haproxy": ViaProxy, "envoy": ViaProxy, "ngrok": ViaTunnel, "frpc": ViaTunnel}
)

const (
	maxRouteFiles     = 200
	maxIncludeDeep    = 4
	maxRouteProcesses = 8
	// What is read of one process, and how long that and all of it may take: a configuration is a
	// file a local user may have written.
	maxRouteBytes = 16 << 20
	maxRouteTime  = 10 * time.Second
	maxRoutesTime = 60 * time.Second
)

var tooMuch = fmt.Sprintf("its configuration is more than Tripcoil reads of one program (%d files, %d MiB, %d seconds)", maxRouteFiles, maxRouteBytes>>20, int(maxRouteTime.Seconds()))

// routeSource is one routing process: its arguments, environment and the files it may read.
type routeSource struct {
	args []string
	env  map[string]string
	cwd  string
	r    *confined
	ctx  context.Context
	// files and includes count what was read and followed, against maxRouteFiles each; bytes what was
	// read, against maxRouteBytes; until is when reading ends.
	files, includes, bytes int
	until                  time.Time
}

// routeSource opens the process pid, which must still be the program called name. Reading it ends
// at stop at the latest.
func (c collector) routeSource(pid int, name string, stop time.Time) (*routeSource, error) {
	r, err := c.confine(pid)
	if err != nil {
		return nil, err
	}
	s := &routeSource{env: map[string]string{}, r: r, ctx: c.ctx, until: time.Now().Add(maxRouteTime)}
	if s.until.After(stop) {
		s.until = stop
	}
	if comm, _ := r.procFile("comm"); strings.TrimSpace(string(comm)) != name {
		r.close()
		return nil, errGone
	}
	if data, err := r.procFile("cmdline"); err == nil {
		for _, a := range bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0}) {
			s.args = append(s.args, string(a))
		}
	}
	// nginx rewrites its command line to one string: "nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf".
	if len(s.args) == 1 && strings.HasPrefix(s.args[0], "nginx:") {
		s.args = strings.Fields(s.args[0])
	}
	if data, err := r.procFile("environ"); err == nil {
		for _, kv := range bytes.Split(data, []byte{0}) {
			if k, v, ok := strings.Cut(string(kv), "="); ok {
				s.env[k] = v
			}
		}
	}
	if s.cwd = r.procLink("cwd"); !path.IsAbs(s.cwd) {
		s.cwd = "/"
	}
	return s, nil
}

// flag is the value of a command-line option, written "--name value" or "--name=value".
func (s *routeSource) flag(names ...string) string {
	for i, a := range s.args {
		for _, n := range names {
			if strings.EqualFold(a, n) && i+1 < len(s.args) {
				return s.args[i+1]
			}
			if k, v, ok := strings.Cut(a, "="); ok && strings.EqualFold(k, n) {
				return v
			}
		}
	}
	return ""
}

func (s *routeSource) has(arg string) bool { return slices.Contains(s.args, arg) }

func (s *routeSource) abs(base, p string) string {
	if path.IsAbs(p) {
		return path.Clean(p)
	}
	return path.Join(base, p)
}

// full reports that a limit of the program is used up: files, includes, bytes or time.
func (s *routeSource) full() bool {
	return s.files >= maxRouteFiles || s.includes >= maxRouteFiles || s.bytes >= maxRouteBytes ||
		time.Now().After(s.until) || s.ctx != nil && s.ctx.Err() != nil
}

// read returns a file's text, counting it against the program's limits.
func (s *routeSource) read(p string) (string, error) {
	if s.full() {
		return "", errors.New("a limit was reached")
	}
	s.files++
	data, err := s.r.read(p)
	s.bytes += len(data)
	return string(data), err
}

// hosts reads the process's hosts file: the names it gives an address (Docker's extra_hosts, the
// machine's own name).
func (s *routeSource) hosts() map[string]string {
	data, err := s.r.read("/etc/hosts")
	if err != nil {
		return nil
	}
	return hostsFile(string(data))
}

// expandInclude turns an include into files: the path itself, or the files of its directory that
// match its last part.
func (s *routeSource) expandInclude(p string) ([]string, error) {
	dir, pattern := path.Split(p)
	if strings.ContainsAny(dir, "*?[") {
		return nil, fmt.Errorf("an include has a pattern in a directory name")
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{p}, nil
	}
	names, err := s.r.list(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	slices.Sort(names)
	for _, n := range names {
		if ok, _ := path.Match(pattern, n); ok {
			out = append(out, path.Join(dir, n))
		}
	}
	return out, nil
}

// follow reads a configuration file and the files it includes, with parse for each. An include
// without a full path is looked up in base, or, when nested, beside the file that names it. skip
// says, when its turn comes, that an include is none (a Caddy snippet that a file read meanwhile
// defines).
func (s *routeSource) follow(file, base string, nested bool, deep int, parse func(string) parsed, skip func(string) bool) parsed {
	var p parsed
	text, err := s.read(file)
	switch {
	case err != nil && s.full():
		p.gap("%s", tooMuch)
		return p
	case err != nil && deep == 0:
		p.gap("%s could not be read: %v", file, shortError(err))
		return p
	case err != nil:
		// An included file's name can hold a value from the environment: it is not printed.
		p.gap("an included file could not be read: %v", shortError(err))
		return p
	}
	one := parse(text)
	includes := one.includes
	one.includes = nil
	p.add(one)
	if nested {
		base = path.Dir(file)
	}
	for _, inc := range includes {
		switch {
		case deep >= maxIncludeDeep:
			p.gap("its includes go deeper than %d files", maxIncludeDeep)
			return p
		case s.full():
			p.gap("%s", tooMuch)
			return p
		case skip != nil && skip(inc):
			continue
		}
		s.includes++
		files, err := s.expandInclude(s.abs(base, inc))
		if err != nil {
			p.gap("an include could not be followed: %v", shortError(err))
			continue
		}
		for _, f := range files {
			if s.full() {
				p.gap("%s", tooMuch)
				return p
			}
			p.add(s.follow(f, base, nested, deep+1, parse, skip))
		}
	}
	return p
}

// shortError is an error without the long path of a process's root in it.
func shortError(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err.Error()
	}
	return err.Error()
}

func (s *routeSource) exists(p string) bool {
	_, err := s.r.read(p)
	return err == nil
}

func (s *routeSource) caddy() parsed {
	var p parsed
	if s.has("reverse-proxy") {
		for i, a := range s.args {
			v := ""
			if (a == "--to" || a == "-t") && i+1 < len(s.args) {
				v = s.args[i+1]
			} else if rest, ok := strings.CutPrefix(a, "--to="); ok {
				v = rest
			}
			if v == "" {
				continue
			}
			if t, ok := target(v); ok {
				p.targets = append(p.targets, t)
			} else {
				p.gap("its --to is not an address Tripcoil can read")
			}
		}
		return p
	}
	if a := s.flag("--adapter", "-a"); a != "" && a != "caddyfile" {
		p.gap("its configuration uses the %s adapter, which Tripcoil does not read", a)
		return p
	}
	file := s.flag("--config", "-c")
	if file == "" {
		// Without --config Caddy takes the Caddyfile of its working directory, when there is one.
		file = path.Join(s.cwd, "Caddyfile")
		if _, err := s.r.read(file); s.has("--resume") || errors.Is(err, fs.ErrNotExist) {
			p.gap("it runs without a configuration file: it is configured through its API")
			return p
		}
	}
	file = s.abs(s.cwd, file)
	// What --envfile sets is in Caddy's memory, not in the environment the process was started with.
	env := s.env
	if s.flag("--envfile") != "" {
		env = nil
	}
	snippets := map[string]bool{}
	return s.follow(file, "", true, 0, func(text string) parsed { return caddyfileWith(text, env, snippets) },
		func(inc string) bool { return snippets[inc] })
}

func (s *routeSource) nginx() parsed {
	// With -p the configuration is looked up below that directory.
	base, file := s.cwd, s.flag("-c")
	if prefix := s.flag("-p"); prefix != "" {
		if base = s.abs(s.cwd, prefix); file == "" {
			file = "conf/nginx.conf"
		}
	}
	if file == "" {
		file = "/etc/nginx/nginx.conf"
	}
	file = s.abs(base, file)
	upstreams, bare := map[string]bool{}, map[string]string{}
	p := s.follow(file, path.Dir(file), false, 0, func(text string) parsed { return nginxConfWith(text, upstreams, bare) }, nil)
	// A bare name that an upstream block defines, in whichever file, is that block and no target.
	p.targets = slices.DeleteFunc(p.targets, func(t string) bool { return upstreams[bare[t]] })
	return p
}

func (s *routeSource) traefik() parsed {
	var p parsed
	file := s.flag("--configfile")
	if file == "" {
		for _, f := range []string{"/etc/traefik/traefik.yml", "/etc/traefik/traefik.yaml", path.Join(s.cwd, "traefik.yml"), path.Join(s.cwd, "traefik.yaml"), "/etc/traefik/traefik.toml"} {
			if s.exists(f) {
				file = f
				break
			}
		}
	}
	found := file != ""
	switch {
	case strings.HasSuffix(file, ".toml"):
		p.gap("its configuration is TOML, which Tripcoil does not read")
	case found:
		text, err := s.read(s.abs(s.cwd, file))
		if err != nil {
			p.gap("%s could not be read: %v", file, shortError(err))
		} else {
			p.add(traefikStatic(text))
		}
	}
	// A provider that is named at all routes to every container, unless exposedByDefault says no.
	exposed := map[string]bool{}
	for i, a := range s.args {
		k, v, hasValue := strings.Cut(strings.ToLower(a), "=")
		rest, ok := strings.CutPrefix(k, "--providers.")
		if !ok {
			continue
		}
		found = true
		raw := a[min(len(a), len(k)+1):]
		if !hasValue && i+1 < len(s.args) { // "--option value"
			raw = s.args[i+1]
		}
		switch name, option, _ := strings.Cut(rest, "."); {
		case name == "file" && option == "directory":
			p.dirs = append(p.dirs, raw)
		case name == "file" && option == "filename":
			p.includes = append(p.includes, raw)
		case name == "docker" || name == "swarm":
			if _, seen := exposed[name]; !seen {
				exposed[name] = true
			}
			if on, err := strconv.ParseBool(v); option == "exposedbydefault" && hasValue && err == nil {
				exposed[name] = on
			}
		case name == "file" || name == "providersthrottleduration":
		default:
			p.gap("it takes routes from the %s provider, which Tripcoil does not read", name)
		}
	}
	for _, all := range exposed {
		p.labels, p.labelsAll = true, p.labelsAll || all
	}
	for k := range s.env {
		if strings.HasPrefix(k, "TRAEFIK_PROVIDERS_") {
			p.gap("it takes its providers from its environment, which Tripcoil does not read")
			break
		}
	}
	if !found {
		p.gap("its configuration was not found")
	}
	files := p.includes
	p.includes = nil
	// The file provider reads a directory with the directories inside it.
	var walk func(d string, deep int)
	walk = func(d string, deep int) {
		if deep > maxIncludeDeep {
			p.gap("its routing files lie deeper than %d directories", maxIncludeDeep)
			return
		}
		if s.full() {
			p.gap("%s", tooMuch)
			return
		}
		s.includes++
		names, err := s.r.list(d)
		if err != nil {
			p.gap("%s could not be read: %v", d, shortError(err))
			return
		}
		slices.Sort(names)
		for _, n := range names {
			switch f := path.Join(d, n); {
			case s.full():
				p.gap("%s", tooMuch)
				return
			case path.Ext(n) == ".yml" || path.Ext(n) == ".yaml":
				files = append(files, f)
			case path.Ext(n) == ".toml":
				p.gap("a routing file is TOML, which Tripcoil does not read")
			case s.r.isDir(f):
				walk(f, deep+1)
			}
		}
	}
	for _, d := range p.dirs {
		walk(s.abs(s.cwd, d), 0)
	}
	p.dirs = nil
	for _, f := range files {
		if strings.HasSuffix(f, ".toml") {
			p.gap("a routing file is TOML, which Tripcoil does not read")
			continue
		}
		if s.full() {
			p.gap("%s", tooMuch)
			break
		}
		text, err := s.read(s.abs(s.cwd, f))
		if err != nil {
			p.gap("%s could not be read: %v", f, shortError(err))
			continue
		}
		p.add(traefikDynamic(text))
	}
	return p
}

// cloudflared reads a tunnel's routes. ok is false for a cloudflared that runs no tunnel.
func (s *routeSource) cloudflared() (p parsed, ok bool) {
	if !s.has("tunnel") && s.flag("--url") == "" {
		return p, false
	}
	if u := s.flag("--url"); u != "" {
		if t, shaped := target(u); shaped {
			p.targets = append(p.targets, t)
		} else {
			p.gap("its --url is not an address Tripcoil can read")
		}
		return p, true
	}
	if s.has("--hello-world") {
		return p, true
	}
	if s.has("--token") || s.flag("--token") != "" || s.flag("--token-file") != "" || s.env["TUNNEL_TOKEN"] != "" {
		p.gap("the tunnel is started with a token: its routes are configured at its provider")
		return p, true
	}
	file := s.flag("--config")
	if file == "" {
		home := s.env["HOME"]
		for _, f := range []string{path.Join(home, ".cloudflared/config.yml"), path.Join(home, ".cloudflared/config.yaml"), "/etc/cloudflared/config.yml", "/etc/cloudflared/config.yaml", "/usr/local/etc/cloudflared/config.yml"} {
			if s.exists(f) {
				file = f
				break
			}
		}
	}
	if file == "" {
		p.gap("its configuration was not found")
		return p, true
	}
	text, err := s.read(s.abs(s.cwd, file))
	if err != nil {
		p.gap("%s could not be read: %v", file, shortError(err))
		return p, true
	}
	p.add(cloudflaredConf(text))
	return p, true
}

// routes reads every proxy and tunnel among the items.
func (c collector) routes(n Network, conts []Container, a Addresses) Routes {
	out := Routes{Programs: []RouteProgram{}}
	var stop time.Time // when reading the programs ends; set with the first one
	byItem := map[string]Container{}
	for _, ct := range conts {
		byItem[ct.Item] = ct
	}
	add := func(it inventory.Item, program, kind string, p parsed, tailnet bool) {
		rp := RouteProgram{Item: it.ID, Program: program, Kind: kind, Tailnet: tailnet, Hostnames: []string{}, Targets: []RouteTarget{}}
		slices.Sort(p.targets)
		for _, t := range slices.Compact(p.targets) {
			items, local := c.resolve(t, it, n, conts, a, p.hosts)
			if local && len(items) == 0 {
				p.gap("its target %s could not be matched to an item", t)
			}
			if len(items) == 0 {
				rp.Targets = append(rp.Targets, RouteTarget{Target: t})
			}
			for _, item := range items {
				rp.Targets = append(rp.Targets, RouteTarget{Target: t, Item: item})
			}
		}
		if p.labels {
			// A container is routed to when its labels switch that on, when it carries a router's or a
			// service's label, or, with a provider that exposes by default, unless they switch it off.
			for _, ct := range conts {
				rt := ct.Routing
				if ct.Item == it.ID || rt == nil && !p.labelsAll || rt != nil && rt.Enable == "false" {
					continue
				}
				if rt == nil || len(rt.Ports) == 0 {
					rp.Targets = append(rp.Targets, RouteTarget{Target: "container " + ct.Name, Item: ct.Item})
					continue
				}
				for _, port := range rt.Ports {
					rp.Targets = append(rp.Targets, RouteTarget{Target: net.JoinHostPort(ct.Name, strconv.Itoa(port)), Item: ct.Item})
				}
			}
			for _, ct := range conts {
				if rt := ct.Routing; rt != nil && ct.Item != it.ID && rt.Enable != "false" {
					p.hostnames = append(p.hostnames, rt.Hostnames...)
				}
			}
		}
		slices.Sort(p.hostnames)
		rp.Hostnames = append(rp.Hostnames, slices.Compact(p.hostnames)...)
		if len(rp.Targets) > maxRouteValues || len(rp.Hostnames) > maxRouteValues {
			rp.Targets, rp.Hostnames = rp.Targets[:min(len(rp.Targets), maxRouteValues)], rp.Hostnames[:min(len(rp.Hostnames), maxRouteValues)]
			p.gap("it names more than %d targets or hostnames", maxRouteValues)
		}
		slices.Sort(p.gaps)
		rp.Gaps = slices.Compact(p.gaps)
		rp.Complete = len(rp.Gaps) == 0
		out.Programs = append(out.Programs, rp)
	}
	for _, it := range c.inv.Items {
		if it.Kind == inventory.KindKernel {
			continue
		}
		pids := slices.Clone(it.PIDs)
		for _, p := range it.Processes {
			pids = append(pids, p.PID)
		}
		slices.Sort(pids)
		// A program can run more than once in an item (two nginx instances, a tunnel beside a DNS proxy
		// of the same name): every process with a command line of its own is read, into one program.
		found := map[string]*parsed{}
		seen, asked := map[string]bool{}, false
		if stop.IsZero() {
			stop = time.Now().Add(maxRoutesTime)
		}
		merge := func(name string, p parsed) {
			if found[name] == nil {
				found[name] = &parsed{}
			}
			found[name].add(p)
		}
		for _, pid := range pids {
			data, err := os.ReadFile(filepath.Join(c.d.Root, "proc", strconv.Itoa(pid), "comm"))
			name := strings.TrimSpace(string(data))
			if err != nil {
				continue
			}
			if _, ok := knownRouters[name]; ok {
				if !seen[name] {
					merge(name, gapOnly("Tripcoil does not read %s's configuration", name))
				}
				seen[name] = true
				continue
			}
			if name == "tailscaled" {
				if !asked {
					c.tailscale(it, add)
				}
				asked = true
				continue
			}
			if _, ok := readRouters[name]; !ok {
				continue
			}
			if time.Now().After(stop) {
				merge(name, gapOnly("the time for reading routes was used up before its turn"))
				continue
			}
			src, err := c.routeSource(pid, name, stop)
			if err == errGone {
				continue
			}
			if err != nil {
				merge(name, gapOnly("its process could not be read: %s", shortError(err)))
				continue
			}
			key := name + "\x00" + src.cwd + "\x00" + strings.Join(src.args, "\x00")
			// An nginx worker has neither the master's command line nor its rights.
			worker := name == "nginx" && len(src.args) > 1 && src.args[0] == "nginx:" && src.args[1] != "master"
			switch {
			case seen[key] || worker:
			case len(seen) >= maxRouteProcesses:
				merge(name, gapOnly("it runs in more than %d processes with command lines of their own", maxRouteProcesses))
			default:
				seen[key] = true
				switch name {
				case "caddy":
					merge(name, src.caddy())
				case "nginx":
					merge(name, src.nginx())
				case "traefik":
					merge(name, src.traefik())
				case "cloudflared":
					if p, ok := src.cloudflared(); ok {
						merge(name, p)
					}
				}
				if found[name] != nil && found[name].hosts == nil {
					found[name].hosts = src.hosts()
				}
			}
			src.r.close()
		}
		for _, name := range slices.Sorted(maps.Keys(found)) {
			kind, ok := readRouters[name]
			if !ok {
				kind = knownRouters[name]
			}
			add(it, name, kind, *found[name], false)
		}
	}
	slices.SortFunc(out.Programs, func(x, y RouteProgram) int {
		return cmpAll(strings.Compare(x.Item, y.Item), strings.Compare(x.Program, y.Program), boolCmp(x.Tailnet, y.Tailnet))
	})
	return out
}

// tailscale asks Tailscale what it serves: Funnel publishes to the internet, Serve to the tailnet.
func (c collector) tailscale(it inventory.Item, add func(inventory.Item, string, string, parsed, bool)) {
	// The tailscale command on this machine asks this machine's Tailscale, not one in a container.
	if it.Kind == inventory.KindContainer {
		add(it, "tailscaled", ViaTunnel, gapOnly("Tailscale runs in a container: what it serves cannot be asked from outside"), false)
		return
	}
	var out []byte
	_, err := c.d.LookPath("tailscale")
	if err == nil {
		out, err = c.d.Run(c.ctx, "tailscale", "serve", "status", "--json")
	}
	if err != nil {
		add(it, "tailscaled", ViaTunnel, gapOnly("what Tailscale serves could not be asked: %s", shortError(err)), false)
		return
	}
	public, tailnet, err := funnel(out)
	if err != nil {
		add(it, "tailscaled", ViaTunnel, gapOnly("what Tailscale serves could not be read"), false)
		return
	}
	if len(public.targets)+len(public.gaps) > 0 {
		add(it, "tailscaled", ViaTunnel, public, false)
	}
	if len(tailnet.targets)+len(tailnet.gaps) > 0 {
		add(it, "tailscaled", ViaProxy, tailnet, true)
	}
}

// Names every machine has for itself, and the names a container has for the machine it runs on.
var (
	loopbackNames = []string{"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
	gatewayNames  = []string{"host.docker.internal", "gateway.docker.internal", "host.containers.internal"}
)

// hostname is the machine's own name, in lower case.
func (c collector) hostname() string {
	data, _ := os.ReadFile(filepath.Join(c.d.Root, "proc/sys/kernel/hostname"))
	return strings.ToLower(strings.TrimSpace(string(data)))
}

// resolve finds the items that answer at a target, seen from the routing item: more than one when
// the fact cannot tell them apart (two containers with the same service name; a published port and
// a listener on the same number). hosts are the names of the router's hosts file. local says that
// the target is on this machine even when no item could be named for it.
func (c collector) resolve(t string, router inventory.Item, n Network, conts []Container, a Addresses, hosts map[string]string) (items []string, local bool) {
	if strings.HasPrefix(t, "unix:") {
		return nil, true
	}
	host, portText, err := net.SplitHostPort(t)
	if err != nil {
		return nil, false
	}
	port, _ := strconv.Atoi(portText)
	host = strings.TrimPrefix(host, "tasks.") // Swarm's name for the tasks of a service
	named := func(h string) (out []string) {
		for _, ct := range conts {
			if slices.ContainsFunc(ct.Names, func(n string) bool { return strings.EqualFold(n, h) }) || slices.Contains(ct.Addresses, h) {
				out = append(out, ct.Item)
			}
		}
		return out
	}
	if items = named(host); len(items) > 0 {
		return items, true
	}
	if addr, ok := hosts[host]; ok {
		if items = named(addr); len(items) > 0 {
			return items, true
		}
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil && strings.Trim(host, "0123456789.") == "" {
		return nil, true // an address in a short form (127.1): on this machine or not, Tripcoil cannot tell
	}
	loopback := slices.Contains(loopbackNames, host) || strings.HasSuffix(host, ".localhost") || ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
	inContainer := router.Kind == inventory.KindContainer && router.NetworkMode != "host"
	if loopback && inContainer {
		owner, shared := strings.CutPrefix(router.NetworkMode, "container:")
		if !shared {
			return []string{router.ID}, true
		}
		// It shares another container's network: the target is that container, or one that shares it too.
		for _, it := range c.inv.Items {
			if it.Kind == inventory.KindContainer && it.ID != router.ID && (it.ContainerID == owner || it.Name == owner || it.NetworkMode == router.NetworkMode) {
				items = append(items, it.ID)
			}
		}
		return items, true
	}
	own := loopback || slices.Contains(gatewayNames, host)
	if name := c.hostname(); !inContainer && name != "" && (host == name || host == strings.SplitN(name, ".", 2)[0]) {
		own = true
	}
	for _, i := range a.Interfaces {
		for _, ad := range i.Addresses {
			if p, _, _ := strings.Cut(ad.Address, "/"); ip != nil && p == ip.String() {
				own = true
			}
		}
	}
	if !own {
		return nil, false
	}
	// The listening socket of a published port belongs to Docker's proxy, so the container is named
	// by its port; a listener on the same number may be another program, and is named as well.
	for _, ct := range conts {
		if slices.ContainsFunc(slices.Concat(ct.Ports, ct.MeshPorts), func(p inventory.Port) bool { return p.HostPort == port && p.Protocol != "udp" }) {
			items = append(items, ct.Item)
		}
	}
	for _, s := range n.Exposed() {
		if s.Proto == "tcp" && s.Port == port {
			items = append(items, s.Items...)
		}
	}
	slices.Sort(items)
	// Nothing listens there: the program routes to nothing, and nothing is left unnamed.
	return slices.Compact(items), len(items) > 0
}
