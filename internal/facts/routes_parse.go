package facts

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// parsed is what one configuration says about routing. Only two kinds of value leave a file:
// where the program forwards to, and the names it serves. Everything else stays where it is.
type parsed struct {
	targets   []string
	hostnames []string
	// includes are further files, as the format names them: a path, or a pattern for the last part of one.
	includes []string
	// dirs are directories whose files are all configuration (Traefik's file provider).
	dirs []string
	// labels: containers are routed to by their labels; labelsAll: every container is, unless its labels say no.
	labels, labelsAll bool
	// gaps say why the routing is not fully known.
	gaps []string
	// hosts are the names the program's hosts file gives an address.
	hosts map[string]string
	// routers, services and middlewares are what Traefik's routing files say about who may call a
	// target, each by protocol and name (routesTo); loose says that they do not settle it.
	routers     map[string]traefikRouter
	services    map[string][]string
	middlewares map[string]traefikMiddleware
	loose       bool
}

type traefikRouter struct {
	service     string
	middlewares []string
	tls         bool
	route       Route
}

// traefikMiddleware is what a middleware does to callers: an allow-list of source ranges, a
// redirect to a scheme, or further middlewares it stands for.
type traefikMiddleware struct {
	allow    []string
	redirect string
	chain    []string
}

const (
	maxGaps   = 20
	maxGapLen = 200
	// maxRouteValues bounds the targets, and the hostnames, kept of one program.
	maxRouteValues = 500
	// What is kept of the routes to one target, and of one route: more says nothing, or less.
	maxTargetRoutes = 50
	maxRouteList    = 20
	maxRouteText    = 200
)

// gap notes why the routing is not fully known. Parts of the sentence come from a command line or a
// file name, so it is kept printable and short, and only the first few are kept.
func (p *parsed) gap(format string, a ...any) {
	if len(p.gaps) >= maxGaps {
		return
	}
	text := []rune(strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, fmt.Sprintf(format, a...)))
	if len(text) > maxGapLen {
		text = append(text[:maxGapLen], '…')
	}
	p.gaps = append(p.gaps, string(text))
}

// gapOnly is a program of which nothing is known but why.
func gapOnly(format string, a ...any) parsed {
	var p parsed
	p.gap(format, a...)
	return p
}

// bound keeps a list of values from growing without limit while files are read: past the limit one
// value too many stays, which marks the program as not fully read.
func bound(values []string) []string {
	if len(values) <= 8*maxRouteValues {
		return values
	}
	slices.Sort(values)
	values = slices.Compact(values)
	return values[:min(len(values), maxRouteValues+1)]
}

func (p *parsed) add(o parsed) {
	p.targets = bound(append(p.targets, o.targets...))
	p.hostnames = bound(append(p.hostnames, o.hostnames...))
	p.includes = append(p.includes, o.includes...)
	p.dirs = append(p.dirs, o.dirs...)
	p.labels, p.labelsAll = p.labels || o.labels, p.labelsAll || o.labelsAll
	for _, g := range o.gaps {
		if len(p.gaps) < maxGaps {
			p.gaps = append(p.gaps, g)
		}
	}
	if p.hosts == nil {
		p.hosts = o.hosts
	}
	// A name that two files define is one Traefik may drop or take from either.
	p.loose = p.loose || o.loose || merge(&p.routers, o.routers) || merge(&p.services, o.services) || merge(&p.middlewares, o.middlewares)
}

// merge adds src to dst and reports whether a key was in both.
func merge[V any](dst *map[string]V, src map[string]V) (twice bool) {
	for k, v := range src {
		if *dst == nil {
			*dst = map[string]V{}
		}
		if _, ok := (*dst)[k]; ok {
			twice = true
		}
		(*dst)[k] = v
	}
	return twice
}

// hostsFile reads the names of a hosts file: "address name name".
func hostsFile(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) < 2 || net.ParseIP(f[0]) == nil || len(out) >= maxRouteValues {
			continue
		}
		for _, name := range f[1:] {
			if _, set := out[strings.ToLower(name)]; !set {
				out[strings.ToLower(name)] = f[0]
			}
		}
	}
	return out
}

var (
	schemePattern = regexp.MustCompile(`^([a-z][a-z0-9+.-]*)://`)
	hostPattern   = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_.-]*[A-Za-z0-9_])?$`)
	defaultPorts  = map[string]string{"http": "80", "https": "443", "h2c": "80", "ws": "80", "wss": "443", "fastcgi": "9000", "ssh": "22", "rdp": "3389", "smb": "445"}
)

// target brings an upstream as a configuration writes it to "host:port" or "unix:/path". It refuses
// anything that is not shaped like one: a value with a variable in it, a word, a secret.
func target(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, prefix := range []string{"unix//", "unix:"} {
		if path, ok := strings.CutPrefix(s, prefix); ok {
			if path = "/" + strings.TrimLeft(path, "/"); len(path) > 1 && !strings.ContainsAny(path, " \t{}$") {
				return "unix:" + path, true
			}
			return "", false
		}
	}
	scheme := ""
	if m := schemePattern.FindStringSubmatch(s); m != nil {
		scheme, s = m[1], s[len(m[0]):]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 { // never keep a user or a password
		return "", false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = strings.Trim(s, "[]"), defaultPorts[scheme]
	}
	if host == "" {
		host = "localhost"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", false
	}
	if net.ParseIP(host) == nil && !hostPattern.MatchString(host) {
		return "", false
	}
	return net.JoinHostPort(strings.ToLower(host), port), true
}

// hostname keeps a name a program serves, without scheme, port and path; nothing for an address, a
// bare port or a catch-all.
func hostname(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if m := schemePattern.FindString(s); m != "" {
		s = s[len(m):]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.ToLower(strings.Trim(s, "[]"))
	name := strings.TrimPrefix(s, "*.")
	if name == "" || net.ParseIP(name) != nil || !strings.Contains(name, ".") || !hostPattern.MatchString(name) || len(s) > 253 {
		return "", false
	}
	return s, true
}

var placeholderPattern = regexp.MustCompile(`\{\$([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}|\{env\.([A-Za-z_][A-Za-z0-9_]*)\}`)

// expand fills in Caddy's environment placeholders from the process's environment. ok is false
// when one stays open. A nil env is an environment Tripcoil does not know (caddy --envfile): every
// placeholder stays open then.
func expand(s string, env map[string]string) (string, bool) {
	ok := true
	out := placeholderPattern.ReplaceAllStringFunc(s, func(m string) string {
		g := placeholderPattern.FindStringSubmatch(m)
		name := g[1] + g[3]
		if env == nil {
			ok = false
			return m
		}
		if v, set := env[name]; set {
			return v
		}
		if strings.Contains(m, ":") && g[1] != "" {
			return g[2]
		}
		ok = false
		return m
	})
	return out, ok && !strings.ContainsAny(out, "{}")
}

// fields splits a configuration line into words; a quoted word stays one, and a # starts a comment.
func fields(line string) []string {
	var out []string
	var cur strings.Builder
	quote, has := rune(0), false
	flush := func() {
		if has {
			out = append(out, cur.String())
		}
		cur.Reset()
		has = false
	}
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '`':
			quote, has = r, true
		case r == '#' && !has:
			flush()
			return out
		case r == ' ' || r == '\t' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	flush()
	return out
}

// caddyfile reads a Caddyfile: the site addresses, and where reverse_proxy, php_fastcgi and
// forward_auth send requests.
func caddyfile(text string, env map[string]string) parsed {
	return caddyfileWith(text, env, map[string]bool{})
}

// caddyfileWith also knows the snippets that the files read before this one define, and adds its own.
func caddyfileWith(text string, env map[string]string, snippets map[string]bool) parsed {
	var p parsed
	if t := strings.TrimSpace(text); strings.HasPrefix(t, "{") && json.Valid([]byte(t)) {
		p.gap("its configuration is JSON, which Tripcoil does not read")
		return p
	}
	lines := strings.Split(text, "\n")
	for _, l := range lines {
		if f := fields(l); len(f) == 2 && f[1] == "{" && strings.HasPrefix(f[0], "(") && strings.HasSuffix(f[0], ")") {
			snippets[strings.Trim(f[0], "()")] = true
		}
	}
	upstream := func(directive, raw string) {
		v, ok := expand(raw, env)
		if t, shaped := target(v); ok && shaped {
			p.targets = append(p.targets, t)
		} else {
			p.gap("a %s upstream is not an address Tripcoil can read", directive)
		}
	}
	depth, proxyDepth := 0, -1
	for _, l := range lines {
		f := fields(l)
		if len(f) == 0 {
			continue
		}
		opens := f[len(f)-1] == "{"
		if opens {
			f = f[:len(f)-1]
		}
		switch {
		case len(f) == 1 && f[0] == "}":
			if depth--; depth <= proxyDepth {
				proxyDepth = -1
			}
			continue
		case len(f) > 0 && f[0] == "layer4":
			p.gap("it forwards connections with the layer4 plugin, which Tripcoil does not read")
		case len(f) >= 2 && f[0] == "import" && !snippets[f[1]]:
			// Arguments after the path fill {args[n]} in the file; a target with one stays open there.
			if file, ok := expand(f[1], env); ok {
				p.includes = append(p.includes, file)
			} else {
				p.gap("an import names its file through a placeholder")
			}
		case depth == 0 && opens && len(f) > 0 && !strings.HasPrefix(f[0], "("):
			for _, a := range f {
				for _, name := range strings.Split(a, ",") {
					if v, _ := expand(name, env); v != "" {
						if h, ok := hostname(v); ok {
							p.hostnames = append(p.hostnames, h)
						}
					}
				}
			}
		case len(f) >= 3 && strings.HasPrefix(f[0], "@") && f[1] == "host", len(f) >= 2 && f[0] == "host" && depth > 0:
			// A host matcher names the hosts a wildcard site tells apart: names that can be looked up.
			for _, name := range f[1:] {
				if v, _ := expand(name, env); v != "" {
					if h, ok := hostname(v); ok {
						p.hostnames = append(p.hostnames, h)
					}
				}
			}
		case len(f) > 0 && (f[0] == "reverse_proxy" || f[0] == "php_fastcgi" || f[0] == "forward_auth"):
			args := f[1:]
			if len(args) > 0 && (strings.HasPrefix(args[0], "/") || strings.HasPrefix(args[0], "@") || args[0] == "*") {
				args = args[1:]
			}
			for _, a := range args {
				upstream(f[0], a)
			}
			if opens && f[0] == "reverse_proxy" {
				proxyDepth = depth
			} else if len(args) == 0 {
				p.gap("a %s names no upstream on its line", f[0])
			}
		case proxyDepth >= 0 && depth == proxyDepth+1 && len(f) > 0 && f[0] == "to":
			for _, a := range f[1:] {
				upstream("reverse_proxy", a)
			}
		case proxyDepth >= 0 && depth == proxyDepth+1 && len(f) > 0 && f[0] == "dynamic":
			p.gap("a reverse_proxy finds its upstreams at run time")
		}
		if opens {
			depth++
		}
	}
	return p
}

// nginxWords splits an nginx configuration into its statements: the words before each ; { or }.
// The body of a *_by_lua_block is code, not configuration, and is left out. ok is false when the
// text ends inside a quote or such a block: what follows the opening was not read as configuration.
func nginxWords(text string) (out [][]string, ok bool) {
	var cur []string
	var word strings.Builder
	quote, comment, has, lua := rune(0), false, false, 0
	flush := func() {
		if has {
			cur = append(cur, word.String())
		}
		word.Reset()
		has = false
	}
	end := func(mark string) {
		flush()
		if mark == "{" && len(cur) > 0 && strings.HasSuffix(cur[0], "_by_lua_block") {
			lua = 1
		}
		out = append(out, append(cur, mark))
		cur = nil
	}
	for _, r := range text {
		switch {
		case lua > 0:
			switch r {
			case '{':
				lua++
			case '}':
				if lua--; lua == 0 {
					end("}")
				}
			}
		case comment:
			comment = r != '\n'
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
		case (r == '"' || r == '\'') && !has:
			quote, has = r, true
		case r == '#' && !has:
			comment = true
		case r == ';':
			end(";")
		case r == '{':
			end("{")
		case r == '}':
			end("}")
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			word.WriteRune(r)
			has = true
		}
	}
	return out, quote == 0 && lua == 0
}

var nginxPass = []string{"proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass", "memcached_pass"}

// nginxConf reads an nginx configuration: server_name, the *_pass directives and the servers of
// upstream blocks.
func nginxConf(text string) parsed {
	return nginxConfWith(text, map[string]bool{}, map[string]string{})
}

// nginxConfWith also notes the upstream blocks it sees, and for each target that is a bare name the
// name: an upstream block of that name, in whichever file, makes it no target of its own.
func nginxConfWith(text string, upstreams map[string]bool, bare map[string]string) parsed {
	var p parsed
	words, whole := nginxWords(text)
	if !whole {
		p.gap("a configuration file ends inside a quote or a block of code")
	}
	for _, w := range words {
		if len(w) == 3 && w[0] == "upstream" && w[2] == "{" {
			upstreams[w[1]] = true
		}
	}
	var stack []string
	for _, w := range words {
		mark, w := w[len(w)-1], w[:len(w)-1]
		if mark == "}" {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		name := ""
		if len(w) > 0 {
			name = w[0]
		}
		inUpstream := len(stack) > 0 && stack[len(stack)-1] == "upstream"
		if strings.Contains(name, "_by_lua") || strings.HasPrefix(name, "js_") {
			p.gap("it runs Lua or JavaScript code, which can pass requests on to anywhere")
		}
		switch {
		case mark == "{":
			stack = append(stack, name)
			continue
		case name == "server_name":
			for _, n := range w[1:] {
				if h, ok := hostname(n); ok {
					p.hostnames = append(p.hostnames, h)
				}
			}
		case name == "server" && inUpstream && len(w) > 1:
			if t, ok := target(strings.TrimSuffix(w[1], ":") + defaultPort(w[1], "80")); ok {
				p.targets = append(p.targets, t)
			} else {
				p.gap("an upstream server is not an address Tripcoil can read")
			}
		case slices.Contains(nginxPass, name) && len(w) > 1:
			v := w[1]
			rest := schemePattern.ReplaceAllString(v, "")
			if i := strings.IndexAny(rest, "/?"); i >= 0 {
				rest = rest[:i]
			}
			// A variable in the path, or right behind the port (…:8080$request_uri), changes the path
			// and not the target.
			variable := strings.Contains(rest, "$")
			if head, _, _ := strings.Cut(rest, "$"); variable {
				if _, port, err := net.SplitHostPort(head); err == nil && port != "" && strings.Trim(port, "0123456789") == "" {
					variable, rest, v = false, head, v[:strings.Index(v, "$")]
				}
			}
			switch t, ok := target(withScheme(v, name)); {
			case upstreams[rest]:
			case variable:
				p.gap("a %s names its target through a variable", name)
			case ok:
				p.targets = append(p.targets, t)
				if !strings.Contains(rest, ":") {
					bare[t] = rest
				}
			default:
				p.gap("a %s target is not an address Tripcoil can read", name)
			}
		case name == "include" && len(w) > 1:
			p.includes = append(p.includes, w[1])
		}
	}
	return p
}

// defaultPort is ":port" for an address that names none.
func defaultPort(addr, port string) string {
	if strings.HasPrefix(addr, "unix:") {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return ""
	}
	return ":" + port
}

// withScheme gives a *_pass target that has no scheme and no port its directive's default port.
func withScheme(v, directive string) string {
	if schemePattern.MatchString(v) || strings.HasPrefix(v, "unix:") {
		return v
	}
	port := map[string]string{"fastcgi_pass": "9000", "memcached_pass": "11211", "grpc_pass": "80"}[directive]
	if port == "" {
		port = "80"
	}
	return v + defaultPort(v, port)
}

var hostRule = regexp.MustCompile("Host(?:SNI)?\\(([^)]*)\\)")
var quoted = regexp.MustCompile("[`'\"]([^`'\"]+)[`'\"]")

// ruleHosts are the names in a Traefik rule's Host(...) and HostSNI(...).
func ruleHosts(rule string) []string {
	var out []string
	for _, m := range hostRule.FindAllStringSubmatch(rule, -1) {
		for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
			if h, ok := hostname(q[1]); ok {
				out = append(out, h)
			}
		}
	}
	return out
}

var pathRule = regexp.MustCompile("Path(?:Prefix)?\\(([^)]*)\\)")

// rulePaths are the paths and path prefixes a Traefik rule is limited to. It names none for a rule
// that is more than conditions joined by "and": such a rule may let other paths through.
func rulePaths(rule string) []string {
	if strings.Contains(rule, "||") || strings.Contains(rule, "!") {
		return nil
	}
	var out []string
	for _, m := range pathRule.FindAllStringSubmatch(rule, -1) {
		for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
			if !strings.HasPrefix(q[1], "/") || !plain(q[1]) || len(out) == maxRouteList {
				return nil
			}
			out = append(out, q[1])
		}
	}
	return out
}

// plain reports that a value from a file is short and printable.
func plain(s string) bool {
	return len(s) <= maxRouteText && !strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsPrint(r) })
}

// words are the strings of a YAML list; ok is false when it is none or holds something else.
func words(v any) (out []string, ok bool) {
	list, ok := v.([]any)
	for _, e := range list {
		s, isString := e.(string)
		if !isString {
			return nil, false
		}
		out = append(out, s)
	}
	return out, ok
}

// routesTo are, for each target, the routers of Traefik's files that forward to it. It is nil where
// the files do not settle that: a router whose service they do not hold, a service that spreads
// over other services, a name defined twice, an allow-list Tripcoil cannot read.
func (p parsed) routesTo() map[string][]Route {
	if p.loose {
		return nil
	}
	out := map[string][]Route{}
	for key, r := range p.routers {
		proto, _, _ := strings.Cut(key, "\x00")
		service := strings.TrimSuffix(r.service, "@file")
		if strings.HasSuffix(service, "@internal") { // Traefik's own dashboard and API
			continue
		}
		targets, ok := p.services[proto+"\x00"+service]
		if !ok {
			return nil
		}
		route := r.route
		for _, m := range p.inFront(proto, r.middlewares, 0) {
			// Of several allow-lists the first is named: what passes all of them passes that one.
			if route.Allow == nil {
				route.Allow = m.allow
			}
			// A router without TLS takes plain requests only, and the redirect sends each of them away.
			if m.redirect == "https" && !r.tls {
				route.Redirect = m.redirect
			}
		}
		for _, t := range targets {
			out[t] = append(out[t], route)
		}
	}
	for t, routes := range out {
		if len(routes) > maxTargetRoutes {
			delete(out, t)
			continue
		}
		slices.SortFunc(routes, func(x, y Route) int {
			a, _ := json.Marshal(x)
			b, _ := json.Marshal(y)
			return strings.Compare(string(a), string(b))
		})
	}
	return out
}

// inFront are the middlewares of the given names that the files define, with those a chain stands for.
func (p parsed) inFront(proto string, names []string, deep int) (out []traefikMiddleware) {
	for _, n := range names {
		m, ok := p.middlewares[proto+"\x00"+strings.TrimSuffix(n, "@file")]
		if !ok || deep > maxIncludeDeep {
			continue
		}
		out = append(append(out, m), p.inFront(proto, m.chain, deep+1)...)
	}
	return out
}

// lookup walks nested YAML maps; keys compare without case, as Traefik reads them.
func lookup(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = nil
		for name, val := range m {
			if strings.EqualFold(name, k) {
				v = val
			}
		}
	}
	return v
}

// traefikStatic reads Traefik's own configuration file: which providers tell it where to route.
func traefikStatic(text string) parsed {
	var p parsed
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		p.gap("its configuration is not YAML that Tripcoil can read")
		return p
	}
	providers, _ := lookup(doc, "providers").(map[string]any)
	for name, v := range providers {
		switch strings.ToLower(name) {
		case "file":
			if d, ok := lookup(v, "directory").(string); ok && d != "" {
				p.dirs = append(p.dirs, d)
			}
			if f, ok := lookup(v, "filename").(string); ok && f != "" {
				p.includes = append(p.includes, f)
			}
		case "docker", "swarm":
			p.labels = true
			if exposed, ok := lookup(v, "exposedByDefault").(bool); !ok || exposed {
				p.labelsAll = true
			}
		case "providersthrottleduration":
		default:
			p.gap("it takes routes from the %s provider, which Tripcoil does not read", name)
		}
	}
	return p
}

// traefikDynamic reads a file of Traefik's file provider: the routers' rules, the services'
// servers, and of the middlewares the allow-lists and redirects.
func traefikDynamic(text string) parsed {
	p := parsed{routers: map[string]traefikRouter{}, services: map[string][]string{}, middlewares: map[string]traefikMiddleware{}}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		p.gap("a routing file is not YAML that Tripcoil can read")
		return p
	}
	for _, proto := range []string{"http", "tcp", "udp"} {
		routers, _ := lookup(doc, proto, "routers").(map[string]any)
		for name, r := range routers {
			rule, _ := lookup(r, "rule").(string)
			hosts := ruleHosts(rule)
			p.hostnames = append(p.hostnames, hosts...)
			tr := traefikRouter{tls: lookup(r, "tls") != nil, route: Route{Hostnames: slices.Compact(slices.Sorted(slices.Values(hosts))), Paths: rulePaths(rule)}}
			tr.service, _ = lookup(r, "service").(string)
			tr.middlewares, _ = words(lookup(r, "middlewares"))
			if entries, _ := words(lookup(r, "entryPoints")); len(entries) <= maxRouteList && !slices.ContainsFunc(entries, func(e string) bool { return !plain(e) }) {
				tr.route.EntryPoints = entries
			}
			p.routers[proto+"\x00"+name] = tr
		}
		services, _ := lookup(doc, proto, "services").(map[string]any)
		for name, s := range services {
			servers, _ := lookup(s, "loadBalancer", "servers").([]any)
			targets := []string{}
			for _, srv := range servers {
				addr, _ := lookup(srv, "url").(string)
				if addr == "" {
					addr, _ = lookup(srv, "address").(string)
				}
				if t, ok := target(addr); ok {
					p.targets = append(p.targets, t)
					targets = append(targets, t)
				} else {
					p.gap("a service's server is not an address Tripcoil can read")
				}
			}
			// A service of another kind (weighted, mirroring, failover) passes on to services, not servers.
			if lookup(s, "loadBalancer") == nil {
				p.loose = true
				continue
			}
			p.services[proto+"\x00"+name] = targets
		}
		middlewares, _ := lookup(doc, proto, "middlewares").(map[string]any)
		for name, m := range middlewares {
			var tm traefikMiddleware
			for _, kind := range []string{"ipAllowList", "ipWhiteList"} {
				list := lookup(m, kind)
				if list == nil {
					continue
				}
				// With an ipStrategy the list is held against a header, not against the caller's address.
				ranges, ok := words(lookup(list, "sourceRange"))
				if !ok || len(ranges) == 0 || len(ranges) > maxRouteList || lookup(list, "ipStrategy") != nil || slices.ContainsFunc(ranges, func(r string) bool { return !sourceRange(r) }) {
					p.loose = true
					continue
				}
				tm.allow = ranges
			}
			if scheme, _ := lookup(m, "redirectScheme", "scheme").(string); strings.EqualFold(scheme, "https") {
				tm.redirect = "https"
			}
			tm.chain, _ = words(lookup(m, "chain", "middlewares"))
			p.middlewares[proto+"\x00"+name] = tm
		}
	}
	return p
}

// sourceRange reports that s is an address or a range of addresses.
func sourceRange(s string) bool {
	_, errRange := netip.ParsePrefix(s)
	_, errAddr := netip.ParseAddr(s)
	return errRange == nil || errAddr == nil
}

// cloudflaredConf reads cloudflared's configuration: the ingress rules of a tunnel that is
// configured on this machine.
func cloudflaredConf(text string) parsed {
	var p parsed
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		p.gap("its configuration is not YAML that Tripcoil can read")
		return p
	}
	service := func(s string) {
		switch {
		case s == "" || strings.HasPrefix(s, "http_status:") || s == "hello_world" || s == "hello-world":
		case s == "bastion" || s == "socks-proxy":
			p.gap("the tunnel lets its users pick the destination (%s)", s)
		default:
			if t, ok := target(s); ok {
				p.targets = append(p.targets, t)
			} else {
				p.gap("an ingress rule's service is not an address Tripcoil can read")
			}
		}
	}
	rules, _ := lookup(doc, "ingress").([]any)
	for _, r := range rules {
		if h, ok := lookup(r, "hostname").(string); ok {
			if name, ok := hostname(h); ok {
				p.hostnames = append(p.hostnames, name)
			}
		}
		s, _ := lookup(r, "service").(string)
		service(s)
	}
	if u, ok := lookup(doc, "url").(string); ok {
		service(u)
	}
	if len(rules) == 0 && lookup(doc, "url") == nil {
		p.gap("its configuration has no ingress rules: the tunnel is configured at its provider")
	}
	return p
}

// serveConfig is what `tailscale serve status --json` prints.
type serveConfig struct {
	TCP map[string]struct {
		TCPForward string `json:"TCPForward"`
	} `json:"TCP"`
	Web map[string]struct {
		Handlers map[string]struct {
			Proxy string `json:"Proxy"`
		} `json:"Handlers"`
	} `json:"Web"`
	AllowFunnel map[string]bool `json:"AllowFunnel"`
	// Tun: a service takes every packet for its address, whatever the port.
	Tun bool `json:"Tun"`
	// Foreground holds what `tailscale serve` and `tailscale funnel` serve while they run in a terminal.
	Foreground map[string]*serveConfig `json:"Foreground"`
	// Services are served under names of their own, to the tailnet.
	Services map[string]*serveConfig `json:"Services"`
}

// funnel reads `tailscale serve status --json`: what Tailscale forwards to, split into what
// Funnel publishes to the internet and what Serve offers the tailnet only.
func funnel(data []byte) (public, tailnet parsed, err error) {
	var cfg serveConfig
	if len(strings.TrimSpace(string(data))) == 0 {
		return public, tailnet, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return public, tailnet, err
	}
	var walk func(cfg *serveConfig, deep int)
	walk = func(cfg *serveConfig, deep int) {
		if cfg == nil || deep > 2 {
			return
		}
		funnelled := func(port string) bool {
			for hostPort, on := range cfg.AllowFunnel {
				if _, p, err := net.SplitHostPort(hostPort); on && err == nil && p == port {
					return true
				}
			}
			return false
		}
		put := func(port, addr string) {
			p := &tailnet
			if funnelled(port) {
				p = &public
			}
			if t, ok := target(addr); ok {
				p.targets = append(p.targets, t)
			} else {
				p.gap("a Tailscale forward is not an address Tripcoil can read")
			}
		}
		if cfg.Tun {
			tailnet.gap("a Tailscale service takes all traffic for its address")
		}
		for port, h := range cfg.TCP {
			if h.TCPForward != "" {
				put(port, h.TCPForward)
			}
		}
		for hostPort, w := range cfg.Web {
			name, port, err := net.SplitHostPort(hostPort)
			if err != nil {
				continue
			}
			for _, h := range w.Handlers {
				if h.Proxy != "" {
					put(port, h.Proxy)
					if n, ok := hostname(name); ok && funnelled(port) {
						public.hostnames = append(public.hostnames, n)
					}
				}
			}
		}
		for _, sub := range cfg.Foreground {
			walk(sub, deep+1)
		}
		for _, sub := range cfg.Services {
			walk(sub, deep+1)
		}
	}
	walk(&cfg, 0)
	return public, tailnet, nil
}
