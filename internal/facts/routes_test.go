package facts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// proc makes proc/<pid> of a process: its name, command line, environment and root directory.
func proc(t *testing.T, root string, pid int, comm string, rootDir string, args []string, env ...string) {
	t.Helper()
	p := fmt.Sprintf("proc/%d", pid)
	write(t, root, p+"/comm", comm+"\n")
	write(t, root, p+"/cmdline", strings.Join(args, "\x00")+"\x00")
	write(t, root, p+"/environ", strings.Join(env, "\x00")+"\x00")
	write(t, root, p+"/status", "Name:\t"+comm+"\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000 \n")
	link(t, root, p+"/root", rootDir)
	link(t, root, p+"/cwd", "/")
}

// workstation is the owner's machine in small: a Caddy of the user's behind a cloudflared tunnel, and
// a Caddy in a container in front of the media stack.
func workstation(t *testing.T) (collector, Network, []Container) {
	t.Helper()
	root, guest := t.TempDir(), t.TempDir()
	write(t, root, "home/u/.config/mcp/Caddyfile", caddyFront)
	write(t, root, "home/u/.config/mcp/cloudflared.yml", cloudflaredTunnel)
	write(t, guest, "etc/caddy/Caddyfile", caddyStack)
	write(t, guest, "etc/caddy/sites/jelly.caddy", "jelly.{$BASE_DOMAIN} {\n\treverse_proxy jellyfin:8096\n}\n")
	write(t, guest, "etc/caddy/sites/notes.txt", "reverse_proxy evil:1\n")
	proc(t, root, 700, "caddy", root, []string{"/home/u/bin/caddy", "run", "--config", "/home/u/.config/mcp/Caddyfile", "--adapter", "caddyfile"}, "SECRET_PATH=x", "MCP_HTTP_TOKEN=planted-token")
	proc(t, root, 710, "cloudflared", root, []string{"/home/u/bin/cloudflared", "tunnel", "--config", "/home/u/.config/mcp/cloudflared.yml", "run"})
	proc(t, root, 720, "caddy", guest, []string{"caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"},
		"BASE_DOMAIN=home.example.net", "ACME_EMAIL=owner@example.net", "CLOUDFLARE_API_TOKEN=planted-cf-token", "BACKEND_HOST=jellyfin")
	proc(t, root, 730, "mcp", root, []string{"mcp"})
	inv := &inventory.Inventory{Items: []inventory.Item{
		{ID: "kernel", Kind: inventory.KindKernel},
		{ID: "proc:caddy", Kind: inventory.KindProcess, Exe: "/home/u/bin/caddy", Processes: []inventory.Process{{PID: 700}}},
		{ID: "proc:cloudflared", Kind: inventory.KindProcess, Exe: "/home/u/bin/cloudflared", Processes: []inventory.Process{{PID: 710}}},
		{ID: "proc:mcp", Kind: inventory.KindProcess, Exe: "/usr/bin/mcp", Processes: []inventory.Process{{PID: 730}}},
		{ID: "proc:api", Kind: inventory.KindProcess, Exe: "/usr/bin/api"},
		{ID: "proc:editor", Kind: inventory.KindProcess, Exe: "/usr/bin/editor"},
		{ID: "container:caddy", Kind: inventory.KindContainer, Name: "caddy", PIDs: []int{720}},
		{ID: "container:sonarr", Kind: inventory.KindContainer, Name: "sonarr"},
		{ID: "container:arr-dashboard", Kind: inventory.KindContainer, Name: "arr-dashboard"},
		{ID: "container:gluetun", Kind: inventory.KindContainer, Name: "gluetun"},
		{ID: "container:jellyfin", Kind: inventory.KindContainer, Name: "jellyfin"},
		{ID: "container:flaresolverr", Kind: inventory.KindContainer, Name: "flaresolverr"},
	}}
	n := Network{LocalPortRangeStart: 32768, Sockets: []Socket{
		{Proto: "tcp", Address: "127.0.0.1", Port: 8787, Items: []string{"proc:caddy"}},
		{Proto: "tcp", Address: "127.0.0.1", Port: 3334, Items: []string{"proc:mcp"}},
		{Proto: "tcp", Address: "127.0.0.1", Port: 8790, Items: []string{"proc:api"}},
		{Proto: "tcp", Address: "127.0.0.1", Port: 6000, Items: []string{"proc:editor"}},
	}}
	port := func(host int) []inventory.Port {
		return []inventory.Port{{IP: "0.0.0.0", HostPort: host, ContainerPort: host, Protocol: "tcp"}}
	}
	conts := []Container{
		{Item: "container:caddy", Name: "caddy", Names: []string{"caddy"}, Addresses: []string{"172.20.0.2"}, Ports: port(443)},
		{Item: "container:sonarr", Name: "sonarr", Names: []string{"sonarr"}, Addresses: []string{"172.20.0.3"}, Ports: port(8989)},
		{Item: "container:arr-dashboard", Name: "arr-dashboard", Names: []string{"arr", "arr-dashboard"}, Addresses: []string{"172.20.0.4"}},
		{Item: "container:gluetun", Name: "gluetun", Names: []string{"gluetun"}, Addresses: []string{"172.20.0.5"}},
		{Item: "container:jellyfin", Name: "jellyfin", Names: []string{"jellyfin"}, Addresses: []string{"172.20.0.6"}},
		{Item: "container:flaresolverr", Name: "flaresolverr", Names: []string{"flaresolverr"}, Addresses: []string{"172.20.0.7"}, Ports: []inventory.Port{{IP: "127.0.0.1", HostPort: 8891, ContainerPort: 8191, Protocol: "tcp"}}},
	}
	c := collector{ctx: context.Background(), inv: inv, d: Deps{Root: root, LookPath: func(string) (string, error) { return "", errNotFound },
		Run: func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("not run") }, ResolveHost: homeResolver}}
	return c, n, conts
}

// homeResolver answers like the resolver of a home network: the stack's names point at the machine's
// LAN address, the tunnel's API at its provider, and one name is not known.
func homeResolver(_ context.Context, host string) ([]netip.Addr, error) {
	switch {
	case strings.HasSuffix(host, ".home.example.net"):
		return []netip.Addr{netip.MustParseAddr("192.168.178.100"), netip.MustParseAddr("fd00::100")}, nil
	case host == "api.example.com":
		return []netip.Addr{netip.MustParseAddr("203.0.113.50"), netip.MustParseAddr("192.168.178.100")}, nil
	case host == "slow.example.com":
		return nil, errors.New("i/o timeout")
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func resolvedOf(p RouteProgram) string {
	var out []string
	for _, r := range p.Resolved {
		s := r.Hostname + "=" + strings.Join(r.Classes, ",")
		if r.Unanswered {
			s += "?"
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

func routesOf(r Routes) map[string]string {
	out := map[string]string{}
	for _, p := range r.Programs {
		var targets []string
		for _, t := range p.Targets {
			targets = append(targets, t.Target+"="+t.Item)
		}
		s := fmt.Sprintf("%s complete=%v %s", p.Kind, p.Complete, strings.Join(targets, " "))
		if p.Tailnet {
			s += " (tailnet)"
		}
		out[p.Item+"/"+p.Program] = strings.TrimSpace(s)
	}
	return out
}

func TestRoutes(t *testing.T) {
	c, n, conts := workstation(t)
	home := homeAddresses(t, false)
	r := c.routes(n, conts, home)
	want := map[string]string{
		"proc:caddy/caddy":             "proxy complete=true 127.0.0.1:3334=proc:mcp",
		"proc:cloudflared/cloudflared": "tunnel complete=true 127.0.0.1:8787=proc:caddy 127.0.0.1:8790=proc:api",
		// authelia is no container of this machine: another host, or a name that is gone. Nothing here answers there.
		"container:caddy/caddy": "proxy complete=true arr-dashboard:3000=container:arr-dashboard authelia:9091= gluetun:8080=container:gluetun gluetun:8081=container:gluetun jellyfin:8096=container:jellyfin sonarr:8989=container:sonarr",
	}
	if got := routesOf(r); !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	for _, p := range r.Programs {
		switch p.Item + "/" + p.Program {
		case "proc:cloudflared/cloudflared":
			if !reflect.DeepEqual(p.Hostnames, []string{"api.example.com", "obsidian-mcp.example.com"}) {
				t.Errorf("the tunnel's hostnames: %v", p.Hostnames)
			}
			if want := "api.example.com=global,private obsidian-mcp.example.com="; resolvedOf(p) != want || p.pointTo() != "global" {
				t.Errorf("the tunnel's names point to %q (%s)", resolvedOf(p), p.pointTo())
			}
		case "proc:caddy/caddy":
			if len(p.Resolved) != 0 || p.pointTo() != "" {
				t.Errorf("a program without hostnames: %+v", p.Resolved)
			}
		case "container:caddy/caddy":
			if !reflect.DeepEqual(p.Hostnames, []string{"*.home.example.net", "arr.home.example.net", "auth.home.example.net", "jelly.home.example.net", "qbittorrent.home.example.net", "sonarr.home.example.net"}) {
				t.Errorf("the stack's hostnames: %v", p.Hostnames)
			}
			// Where the names point, as this machine's resolver answers; a wildcard cannot be looked up.
			if want := "arr.home.example.net=private auth.home.example.net=private jelly.home.example.net=private qbittorrent.home.example.net=private sonarr.home.example.net=private"; resolvedOf(p) != want || p.pointTo() != "private" {
				t.Errorf("the stack's names point to %q (%s)", resolvedOf(p), p.pointTo())
			}
		}
		for _, v := range append(p.Hostnames, p.Gaps...) {
			if strings.Contains(v, "planted") || strings.Contains(v, "owner@") {
				t.Errorf("%q left a configuration", v)
			}
		}
	}
}

// Each way a program's routing is not fully known makes it incomplete, with the reason.
func TestRoutesIncomplete(t *testing.T) {
	for name, tc := range map[string]struct {
		comm string
		args []string
		env  []string
		file [2]string
		kind string
		gap  string
	}{
		"a tunnel started with a token":   {"cloudflared", []string{"cloudflared", "tunnel", "run", "--token", "eyJplanted"}, nil, [2]string{}, ViaTunnel, "configured at its provider"},
		"a token in the environment":      {"cloudflared", []string{"cloudflared", "tunnel", "run"}, []string{"TUNNEL_TOKEN=eyJplanted"}, [2]string{}, ViaTunnel, "configured at its provider"},
		"a tunnel without a file":         {"cloudflared", []string{"cloudflared", "tunnel", "run", "mine"}, []string{"HOME=/home/u"}, [2]string{}, ViaTunnel, "was not found"},
		"a Caddy without a file":          {"caddy", []string{"caddy", "run"}, nil, [2]string{}, ViaProxy, "configured through its API"},
		"a Caddy with a JSON file":        {"caddy", []string{"caddy", "run", "--config", "/etc/caddy/caddy.json"}, nil, [2]string{"etc/caddy/caddy.json", `{"apps":{}}`}, ViaProxy, "JSON"},
		"a file that is missing":          {"nginx", []string{"nginx:", "master", "process", "/usr/sbin/nginx", "-c", "/etc/nginx/none.conf"}, nil, [2]string{}, ViaProxy, "could not be read: no such file"},
		"a unix socket target":            {"nginx", []string{"nginx: master process /usr/sbin/nginx -g daemon off;"}, nil, [2]string{"etc/nginx/nginx.conf", "http { server { location / { fastcgi_pass unix:/run/php.sock; } } }"}, ViaProxy, "could not be matched to an item"},
		"a Traefik with another provider": {"traefik", []string{"traefik", "--providers.kubernetescrd=true"}, nil, [2]string{}, ViaProxy, "kubernetescrd provider"},
		"a Traefik without anything":      {"traefik", []string{"traefik"}, nil, [2]string{}, ViaProxy, "was not found"},
		"a proxy Tripcoil only knows":     {"haproxy", []string{"haproxy", "-f", "/etc/haproxy/haproxy.cfg"}, nil, [2]string{}, ViaProxy, "does not read haproxy's configuration"},
		"a tunnel Tripcoil only knows":    {"ngrok", []string{"ngrok", "http", "3000"}, nil, [2]string{}, ViaTunnel, "does not read ngrok's configuration"},
	} {
		root := t.TempDir()
		proc(t, root, 800, tc.comm, root, tc.args, tc.env...)
		if tc.file[0] != "" {
			write(t, root, tc.file[0], tc.file[1])
		}
		inv := &inventory.Inventory{Items: []inventory.Item{{ID: "proc:x", Kind: inventory.KindProcess, Processes: []inventory.Process{{PID: 800}}}}}
		c := collector{ctx: context.Background(), inv: inv, d: Deps{Root: root}}
		r := c.routes(Network{}, nil, Addresses{})
		if len(r.Programs) != 1 || r.Programs[0].Kind != tc.kind || r.Programs[0].Complete || !strings.Contains(strings.Join(r.Programs[0].Gaps, "; "), tc.gap) {
			t.Errorf("%s: %+v", name, r.Programs)
		}
		for _, p := range r.Programs {
			if strings.Contains(fmt.Sprint(p), "planted") {
				t.Errorf("%s: a secret left the command line: %+v", name, p)
			}
		}
	}
	// A cloudflared that runs no tunnel is no router.
	root := t.TempDir()
	proc(t, root, 800, "cloudflared", root, []string{"cloudflared", "proxy-dns"})
	inv := &inventory.Inventory{Items: []inventory.Item{{ID: "proc:x", Kind: inventory.KindProcess, Processes: []inventory.Process{{PID: 800}}}}}
	if r := (collector{ctx: context.Background(), inv: inv, d: Deps{Root: root}}).routes(Network{}, nil, Addresses{}); len(r.Programs) != 0 {
		t.Errorf("a DNS proxy: %+v", r.Programs)
	}
}

// taskmaster in small: Traefik with its file provider's directory and the Docker providers, an nginx
// with includes, and Tailscale serving one port to the tailnet and one to the internet.
func TestRoutesServer(t *testing.T) {
	root, guest := t.TempDir(), t.TempDir()
	write(t, guest, "etc/traefik/traefik.yml", traefikMain)
	write(t, guest, "etc/dokploy/traefik/dynamic/dokploy.yml", traefikPanel)
	write(t, guest, "etc/dokploy/traefik/dynamic/site.yml", "http:\n  routers:\n    s:\n      rule: Host(`shop.example.org`)\n  services:\n    s:\n      loadBalancer:\n        servers:\n          - url: http://shop:3000\n")
	write(t, guest, "etc/dokploy/traefik/dynamic/acme.json", `{"letsencrypt":{"Account":{"PrivateKey":"planted"}}}`)
	write(t, guest, "etc/dokploy/traefik/dynamic/access.log", "GET /\n")
	proc(t, root, 900, "traefik", guest, []string{"traefik"})
	write(t, root, "etc/nginx/nginx.conf", "http {\n\tinclude conf.d/*.conf;\n}\n")
	write(t, root, "etc/nginx/conf.d/a.conf", "server { server_name a.example.org; location / { proxy_pass http://127.0.0.1:8000; } }")
	write(t, root, "etc/nginx/conf.d/b.conf.disabled", "server { location / { proxy_pass http://127.0.0.1:1; } }")
	proc(t, root, 910, "nginx", root, []string{"nginx: master process /usr/sbin/nginx -g daemon off;"})
	proc(t, root, 911, "nginx", root, []string{"nginx: worker process"})
	proc(t, root, 920, "tailscaled", root, []string{"/usr/sbin/tailscaled", "--port=41641"})
	inv := &inventory.Inventory{Items: []inventory.Item{
		{ID: "container:traefik", Kind: inventory.KindContainer, Name: "traefik", PIDs: []int{900}},
		{ID: "container:dokploy", Kind: inventory.KindContainer, Name: "dokploy.1.abc"},
		{ID: "container:shop", Kind: inventory.KindContainer, Name: "shop.1.def"},
		{ID: "container:labelled", Kind: inventory.KindContainer, Name: "labelled"},
		{ID: "container:quiet", Kind: inventory.KindContainer, Name: "quiet"},
		{ID: "proc:nginx", Kind: inventory.KindProcess, Processes: []inventory.Process{{PID: 911}, {PID: 910}}},
		{ID: "proc:app", Kind: inventory.KindProcess},
		{ID: "proc:tailscaled", Kind: inventory.KindProcess, Processes: []inventory.Process{{PID: 920}}},
		{ID: "proc:grafana", Kind: inventory.KindProcess},
	}}
	n := Network{Sockets: []Socket{
		{Proto: "tcp", Address: "127.0.0.1", Port: 8000, Items: []string{"proc:app"}},
		{Proto: "tcp", Address: "127.0.0.1", Port: 3000, Items: []string{"proc:grafana"}},
	}}
	conts := []Container{
		{Item: "container:traefik", Name: "traefik", Names: []string{"traefik"}},
		{Item: "container:dokploy", Name: "dokploy.1.abc", Names: []string{"dokploy", "dokploy.1.abc"}},
		{Item: "container:shop", Name: "shop.1.def", Names: []string{"shop"}},
		{Item: "container:labelled", Name: "labelled", Names: []string{"labelled"}, Routing: &Routing{Enable: "true", Hostnames: []string{"l.example.org"}}},
		{Item: "container:quiet", Name: "quiet", Names: []string{"quiet"}},
	}
	serve := `{"TCP":{"443":{"HTTPS":true},"8443":{"HTTPS":true}},"Web":{"tm.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}},"tm.ts.net:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:8000"}}}},"AllowFunnel":{"tm.ts.net:443":true}}`
	c := collector{ctx: context.Background(), inv: inv, d: Deps{Root: root, LookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name+" "+strings.Join(args, " ") != "tailscale serve status --json" {
				t.Errorf("ran %s %v", name, args)
			}
			return []byte(serve), nil
		}}}
	r := c.routes(n, conts, Addresses{})
	want := map[string]string{
		// 10.0.1.5 is another host. The container with routing labels is a target; the one without is not, because the provider does not expose by default.
		"container:traefik/traefik":  "proxy complete=true 10.0.1.5:5432= dokploy:3000=container:dokploy shop:3000=container:shop container labelled=container:labelled",
		"proc:nginx/nginx":           "proxy complete=true 127.0.0.1:8000=proc:app",
		"proc:tailscaled/tailscaled": "proxy complete=true 127.0.0.1:8000=proc:app (tailnet)",
	}
	got := map[string]string{}
	for _, p := range r.Programs {
		key := p.Item + "/" + p.Program
		if p.Kind == ViaTunnel {
			key += " funnel"
		}
		got[key] = routesOf(Routes{Programs: []RouteProgram{p}})[p.Item+"/"+p.Program]
	}
	want["proc:tailscaled/tailscaled funnel"] = "tunnel complete=true 127.0.0.1:3000=proc:grafana"
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	for _, p := range r.Programs {
		if p.Program == "traefik" && !reflect.DeepEqual(p.Hostnames, []string{"db.fkws.example", "fkws.example", "l.example.org", "shop.example.org", "www.fkws.example"}) {
			t.Errorf("Traefik's hostnames: %v", p.Hostnames)
		}
		if strings.Contains(fmt.Sprint(p), "planted") || strings.Contains(fmt.Sprint(p), "PLANTED") {
			t.Errorf("a secret left a configuration: %+v", p)
		}
	}

	// Without its command-line tool Tailscale cannot be asked: it may publish anything.
	c.d.LookPath = func(string) (string, error) { return "", errNotFound }
	for _, p := range c.routes(n, conts, Addresses{}).Programs {
		if p.Program == "tailscaled" && (p.Kind != ViaTunnel || p.Complete || !strings.Contains(p.Gaps[0], "could not be asked")) {
			t.Errorf("Tailscale without its tool: %+v", p)
		}
	}
}

// A target is matched to every item that may answer there, and to the container behind a published
// port rather than to Docker's proxy, which holds the listening socket.
func TestResolve(t *testing.T) {
	inv := &inventory.Inventory{Items: []inventory.Item{
		{ID: "container:app", Kind: inventory.KindContainer, Name: "app", ContainerID: "aaa"},
		{ID: "container:sidecar", Kind: inventory.KindContainer, Name: "sidecar", NetworkMode: "container:aaa"},
		{ID: "container:other", Kind: inventory.KindContainer, Name: "other", NetworkMode: "container:aaa"},
		{ID: "container:lonely", Kind: inventory.KindContainer, Name: "lonely", NetworkMode: "container:gone"},
		{ID: "container:hostnet", Kind: inventory.KindContainer, Name: "hostnet", NetworkMode: "host"},
		{ID: "container:bridged", Kind: inventory.KindContainer, Name: "bridged", NetworkMode: "bridge"},
	}}
	conts := []Container{
		{Item: "container:app", Name: "app", Names: []string{"app", "web"}, Addresses: []string{"172.20.0.2"}, Ports: []inventory.Port{{IP: "127.0.0.1", HostPort: 8891, ContainerPort: 80, Protocol: "tcp"}}},
		{Item: "container:shop-web", Name: "shop-web", Names: []string{"shop-web", "web"}, Addresses: []string{"172.21.0.2"}},
		{Item: "container:mesh", Name: "mesh", Names: []string{"mesh"}, MeshPorts: []inventory.Port{{HostPort: 9443, ContainerPort: 443, Protocol: "tcp"}}},
	}
	n := Network{Sockets: []Socket{
		{Proto: "tcp", Address: "127.0.0.1", Port: 8891, Items: []string{"proc:docker-proxy"}},
		{Proto: "tcp", Address: "0.0.0.0", Port: 8000, Items: []string{"proc:app"}},
	}}
	root := t.TempDir()
	write(t, root, "proc/sys/kernel/hostname", "Tower.example.net\n")
	c := collector{inv: inv, d: Deps{Root: root}}
	// The router's hosts file: the machine's alias, and what Docker's extra_hosts writes.
	hosts := hostsFile("127.0.0.1 localhost\n127.0.1.1 tower # this machine\n192.168.178.100 dockerhost nas\n172.21.0.2 shop\n198.51.100.77 elsewhere\n")
	host := inventory.Item{ID: "proc:caddy", Kind: inventory.KindProcess}
	for _, tc := range []struct {
		target string
		router inventory.Item
		items  []string
		local  bool
	}{
		// The published port's container, and whatever holds the socket of that number (here Docker's proxy).
		{"127.0.0.1:8891", host, []string{"container:app", "proc:docker-proxy"}, true},
		{"localhost.localdomain:8000", host, []string{"proc:app"}, true},
		{"app.localhost:8000", host, []string{"proc:app"}, true},
		{"tower:8000", host, []string{"proc:app"}, true},             // the machine's own name
		{"tower.example.net:8000", host, []string{"proc:app"}, true}, // and in full
		{"dockerhost:8000", host, []string{"proc:app"}, true},        // a name of the hosts file
		{"shop:80", host, []string{"container:shop-web"}, true},      // one that is a container's address
		{"elsewhere:8000", host, nil, false},
		{"host.containers.internal:8000", inv.Items[5], []string{"proc:app"}, true},
		{"tasks.web:80", inv.Items[5], []string{"container:app", "container:shop-web"}, true},
		{"127.1:8000", host, nil, true}, // a short form of an address: a gap
		{"localhost:9443", host, []string{"container:mesh"}, true},
		{"0.0.0.0:8000", host, []string{"proc:app"}, true},
		{"[::]:8000", host, []string{"proc:app"}, true},
		{"192.168.178.100:8000", host, []string{"proc:app"}, true}, // an address of this machine
		{"127.0.0.1:1", host, nil, false},                          // nothing listens there
		{"198.51.100.78:443", host, nil, false},
		{"web:80", host, []string{"container:app", "container:shop-web"}, true},
		{"172.21.0.2:80", host, []string{"container:shop-web"}, true},
		{"unix:/run/php.sock", host, nil, true},
		{"127.0.0.1:8080", inv.Items[5], []string{"container:bridged"}, true},
		{"127.0.0.1:8000", inv.Items[4], []string{"proc:app"}, true},
		{"localhost:8080", inv.Items[1], []string{"container:app", "container:other"}, true},
		{"localhost:8080", inv.Items[3], nil, true}, // the container whose network it shares is not known
	} {
		items, local := c.resolve(tc.target, tc.router, n, conts, homeAddresses(t, false), hosts)
		if !reflect.DeepEqual(items, tc.items) || local != tc.local {
			t.Errorf("%s from %s: %v %v, want %v %v", tc.target, tc.router.ID, items, local, tc.items, tc.local)
		}
	}
}

// What a review of the first version found: each of these was once a program called complete, with a
// target missing.
func TestRoutesOfEveryProcess(t *testing.T) {
	root := t.TempDir()
	run := func(items []inventory.Item, conts []Container) map[string]RouteProgram {
		t.Helper()
		c := collector{ctx: context.Background(), inv: &inventory.Inventory{Items: items}, d: Deps{Root: root,
			Run: func(context.Context, string, ...string) ([]byte, error) {
				t.Error("a command was run")
				return nil, nil
			}}}
		out := map[string]RouteProgram{}
		for _, p := range c.routes(Network{}, conts, Addresses{}).Programs {
			if _, twice := out[p.Item+"/"+p.Program]; twice {
				t.Errorf("%s/%s is listed twice", p.Item, p.Program)
			}
			out[p.Item+"/"+p.Program] = p
		}
		return out
	}
	item := func(id string, pids ...int) inventory.Item {
		it := inventory.Item{ID: id, Kind: inventory.KindProcess}
		for _, pid := range pids {
			it.Processes = append(it.Processes, inventory.Process{PID: pid})
		}
		return it
	}
	targets := func(p RouteProgram) string {
		return routesOf(Routes{Programs: []RouteProgram{p}})[p.Item+"/"+p.Program]
	}

	// A DNS proxy of the same name does not hide the tunnel, and two nginx instances are both read.
	proc(t, root, 800, "cloudflared", root, []string{"cloudflared", "proxy-dns"})
	proc(t, root, 801, "cloudflared", root, []string{"cloudflared", "tunnel", "--url", "http://10.0.0.5:3000"})
	write(t, root, "etc/nginx/a.conf", "server { location / { proxy_pass http://10.0.0.6:8000; } }")
	write(t, root, "etc/nginx/b.conf", "server { location / { proxy_pass http://10.0.0.7:8000; } }")
	proc(t, root, 810, "nginx", root, []string{"nginx: worker process"})
	proc(t, root, 811, "nginx", root, []string{"nginx: master process nginx -c /etc/nginx/a.conf"})
	proc(t, root, 812, "nginx", root, []string{"nginx: master process nginx -c /etc/nginx/b.conf"})
	proc(t, root, 813, "nginx", root, []string{"nginx: master process nginx -c /etc/nginx/b.conf"})
	// nginx -p: the configuration lies below that directory.
	write(t, root, "srv/ngx/conf/nginx.conf", "http { include extra/*.conf; }")
	write(t, root, "srv/ngx/conf/extra/x.conf", "server { location / { proxy_pass http://10.0.0.8:8000; } }")
	proc(t, root, 814, "nginx", root, []string{"nginx: master process nginx -p /srv/ngx"})
	got := run([]inventory.Item{item("proc:cloudflared", 800, 801), item("proc:nginx", 810, 811, 812, 813), item("proc:ngx", 814)}, nil)
	for key, want := range map[string]string{
		"proc:cloudflared/cloudflared": "tunnel complete=true 10.0.0.5:3000=",
		"proc:nginx/nginx":             "proxy complete=true 10.0.0.6:8000= 10.0.0.7:8000=",
		"proc:ngx/nginx":               "proxy complete=true 10.0.0.8:8000=",
	} {
		if targets(got[key]) != want {
			t.Errorf("%s: %q, want %q", key, targets(got[key]), want)
		}
	}

	// Caddy looks an import up beside the file that names it; what --envfile sets is not known.
	write(t, root, "etc/caddy/Caddyfile", "import sites/*.caddy\n")
	write(t, root, "etc/caddy/sites/a.caddy", "import apps/*.caddy\n")
	write(t, root, "etc/caddy/sites/apps/x.caddy", "x.example.org {\n\treverse_proxy 10.0.0.9:80\n}\n")
	write(t, root, "etc/caddy/env.Caddyfile", "y.example.org {\n\treverse_proxy {$APP:10.0.0.10}:80\n}\n")
	proc(t, root, 820, "caddy", root, []string{"caddy", "run", "--config", "/etc/caddy/Caddyfile"})
	proc(t, root, 821, "caddy", root, []string{"caddy", "run", "--config", "/etc/caddy/env.Caddyfile", "--envfile", "/etc/caddy/env"})
	// A program that runs with its caller's command line and its owner's rights is not read at all,
	// and what a command line puts into a sentence stays short and printable.
	proc(t, root, 822, "caddy", root, []string{"caddy", "run", "--config", "/etc/shadow"})
	write(t, root, "proc/822/status", "Name:\tcaddy\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000\n")
	proc(t, root, 823, "caddy", root, []string{"caddy", "run", "--config", "/" + strings.Repeat("planted", 500) + "\nline two"})
	got = run([]inventory.Item{item("proc:a", 820), item("proc:b", 821), item("proc:c", 822), item("proc:d", 823)}, nil)
	if targets(got["proc:a/caddy"]) != "proxy complete=true 10.0.0.9:80=" {
		t.Errorf("a nested import: %+v", got["proc:a/caddy"])
	}
	if p := got["proc:b/caddy"]; p.Complete || len(p.Targets) != 0 {
		t.Errorf("an environment file: %+v", p)
	}
	if p := got["proc:c/caddy"]; p.Complete || len(p.Targets) != 0 || !strings.Contains(strings.Join(p.Gaps, " "), "one user and group") {
		t.Errorf("a setuid program: %+v", p)
	}
	if p := got["proc:d/caddy"]; p.Complete || len(p.Gaps) != 1 || len([]rune(p.Gaps[0])) > maxGapLen+1 || strings.Contains(p.Gaps[0], "\n") {
		t.Errorf("a long command line: %+v", p)
	}

	// Traefik: a provider named by any of its options exposes every container unless told otherwise;
	// labels compare without case; a label's port is the target; the file provider reads directories inside.
	write(t, root, "dyn/a.yml", "http:\n  services:\n    a:\n      loadBalancer:\n        servers:\n          - url: http://10.0.0.11:80\n")
	write(t, root, "dyn/sub/deeper/b.yaml", "http:\n  services:\n    b:\n      loadBalancer:\n        servers:\n          - url: http://10.0.0.12:80\n")
	proc(t, root, 830, "traefik", root, []string{"traefik", "--providers.docker.endpoint=unix:///var/run/docker.sock", "--providers.file.directory=/dyn"})
	proc(t, root, 831, "traefik", root, []string{"traefik", "--providers.docker.exposedByDefault=false", "--providers.docker.endpoint=unix:///var/run/docker.sock"})
	conts := []Container{
		{Item: "container:plain", Name: "plain", Names: []string{"plain"}},
		{Item: "container:on", Name: "on", Names: []string{"on"}, Routing: &Routing{Enable: "true", Ports: []int{8080, 9090}, Hostnames: []string{"on.example.org"}}},
		{Item: "container:off", Name: "off", Names: []string{"off"}, Routing: &Routing{Enable: "false", Ports: []int{80}, Hostnames: []string{"off.example.org"}}},
	}
	got = run([]inventory.Item{item("proc:t1", 830), item("proc:t2", 831)}, conts)
	if want := "proxy complete=true 10.0.0.11:80= 10.0.0.12:80= container plain=container:plain on:8080=container:on on:9090=container:on"; targets(got["proc:t1/traefik"]) != want {
		t.Errorf("exposed by default:\n got %q\nwant %q", targets(got["proc:t1/traefik"]), want)
	}
	if want := "proxy complete=true on:8080=container:on on:9090=container:on"; targets(got["proc:t2/traefik"]) != want || !reflect.DeepEqual(got["proc:t2/traefik"].Hostnames, []string{"on.example.org"}) {
		t.Errorf("not exposed by default: %q %v", targets(got["proc:t2/traefik"]), got["proc:t2/traefik"].Hostnames)
	}

	// A configuration that includes without end is read up to the limit and then given up, quickly.
	var bomb strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&bomb, "include /bomb/*.conf;\ninclude /none/%d/*.conf;\n", i)
	}
	write(t, root, "etc/nginx/bomb.conf", bomb.String())
	for i := 0; i < 300; i++ {
		write(t, root, fmt.Sprintf("bomb/%d.conf", i), fmt.Sprintf("server { location / { proxy_pass http://10.1.0.%d:80; } }", i%250))
	}
	proc(t, root, 840, "nginx", root, []string{"nginx: master process nginx -c /etc/nginx/bomb.conf"})
	if p := run([]inventory.Item{item("proc:bomb", 840)}, nil)["proc:bomb/nginx"]; p.Complete || len(p.Targets) >= maxRouteFiles || len(p.Gaps) > maxGaps ||
		!strings.Contains(strings.Join(p.Gaps, " "), "more than Tripcoil reads of one program") {
		t.Errorf("an include bomb: complete=%v, %d targets, gaps %v", p.Complete, len(p.Targets), p.Gaps)
	}

	// Traefik takes "--option value" like "--option=value"; an upstream block of another nginx file is
	// no target of its own, and a variable behind the port does not hide the address; a Caddy snippet
	// may be defined in a file that is imported before its use; a file name with a value from the
	// environment is not printed; plugins that forward are gaps.
	write(t, root, "dyn2/c.yml", "http:\n  services:\n    c:\n      loadBalancer:\n        servers:\n          - url: http://10.0.0.13:80\n")
	proc(t, root, 860, "traefik", root, []string{"traefik", "--providers.file.directory", "/dyn2"})
	write(t, root, "etc/nginx/up.conf", "http { include up.d/*.conf; server { location / { proxy_pass http://backend; } location /x { proxy_pass http://10.0.0.14:8080$request_uri; } location /y { proxy_pass http://$host_from_header; } } }")
	write(t, root, "etc/nginx/up.d/pool.conf", "upstream backend { server 10.0.0.15:9000; }")
	proc(t, root, 861, "nginx", root, []string{"nginx: master process nginx -c /etc/nginx/up.conf"})
	write(t, root, "etc/caddy/snip.Caddyfile", "import snippets.caddy\nz.example.org {\n\timport common\n\treverse_proxy 10.0.0.16:80\n}\nimport tenants/{$TENANT}.caddy\n")
	write(t, root, "etc/caddy/snippets.caddy", "(common) {\n\tencode gzip\n}\n")
	proc(t, root, 862, "caddy", root, []string{"caddy", "run", "--config", "/etc/caddy/snip.Caddyfile"}, "TENANT=planted-tenant-secret")
	write(t, root, "etc/caddy/l4.Caddyfile", "{\n\tlayer4 {\n\t\t:5432 {\n\t\t\troute {\n\t\t\t\tproxy 10.0.0.17:5432\n\t\t\t}\n\t\t}\n\t}\n}\n")
	proc(t, root, 863, "caddy", root, []string{"caddy", "run", "--config", "/etc/caddy/l4.Caddyfile"})
	write(t, root, "etc/nginx/js.conf", "http { js_import main from app.js; server { location / { js_content main.route; } } }")
	proc(t, root, 864, "nginx", root, []string{"nginx: master process nginx -c /etc/nginx/js.conf"})
	got = run([]inventory.Item{item("proc:t3", 860), item("proc:n3", 861), item("proc:c3", 862), item("proc:c4", 863), item("proc:n4", 864)}, nil)
	if targets(got["proc:t3/traefik"]) != "proxy complete=true 10.0.0.13:80=" {
		t.Errorf("an option and its value in two words: %+v", got["proc:t3/traefik"])
	}
	if p := got["proc:n3/nginx"]; targets(p) != "proxy complete=false 10.0.0.14:8080= 10.0.0.15:9000=" || len(p.Gaps) != 1 || !strings.Contains(p.Gaps[0], "through a variable") {
		t.Errorf("nginx with an upstream in another file: %q %v", targets(p), p.Gaps)
	}
	if p := got["proc:c3/caddy"]; targets(p) != "proxy complete=false 10.0.0.16:80=" || len(p.Gaps) != 1 || strings.Contains(strings.Join(p.Gaps, " "), "planted") {
		t.Errorf("a snippet from an imported file, and a file named through the environment: %q %v", targets(p), p.Gaps)
	}
	for _, key := range []string{"proc:c4/caddy", "proc:n4/nginx"} {
		if got[key].Complete {
			t.Errorf("%s forwards with a plugin and is called complete", key)
		}
	}

	// Reading ends in time: a program whose turn comes after the run's time is not read, and says so.
	slow := collector{ctx: context.Background(), inv: &inventory.Inventory{Items: []inventory.Item{item("proc:t3", 860)}}, d: Deps{Root: root}}
	src, err := slow.routeSource(860, "traefik", time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if p := src.traefik(); len(p.targets) != 0 || len(p.gaps) == 0 || !strings.Contains(strings.Join(p.gaps, " "), "more than Tripcoil reads") {
		t.Errorf("a program read after its time: %+v", p)
	}
	src.r.close()

	// Names are looked up a few at a time and within the run's time; a lookup that got no answer says so,
	// and without a resolver nothing is looked up.
	var many strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&many, "server { server_name n%02d.home.example.net; }\n", i)
	}
	write(t, root, "etc/nginx/names.conf", many.String()+"server { server_name slow.example.com; }\n")
	proc(t, root, 870, "nginx", root, []string{"nginx: master process nginx -c /etc/nginx/names.conf"})
	names := collector{ctx: context.Background(), inv: &inventory.Inventory{Items: []inventory.Item{item("proc:names", 870)}}, d: Deps{Root: root, ResolveHost: homeResolver}}
	p := names.routes(Network{}, nil, Addresses{}).Programs[0]
	if len(p.Hostnames) != 41 || len(p.Resolved) != maxResolved || p.Resolved[0].Hostname != "n00.home.example.net" || p.pointTo() != "private" {
		t.Errorf("%d hostnames, %d looked up: %s", len(p.Hostnames), len(p.Resolved), resolvedOf(p))
	}
	write(t, root, "etc/nginx/names.conf", "server { server_name slow.example.com; }\n")
	if p := names.routes(Network{}, nil, Addresses{}).Programs[0]; resolvedOf(p) != "slow.example.com=?" || p.pointTo() != "" {
		t.Errorf("a lookup without an answer: %s (%s)", resolvedOf(p), p.pointTo())
	}
	names.d.ResolveHost = nil
	if p := names.routes(Network{}, nil, Addresses{}).Programs[0]; len(p.Resolved) != 0 {
		t.Errorf("without a resolver: %s", resolvedOf(p))
	}

	// A Tailscale in a container cannot be asked with this machine's command.
	proc(t, root, 850, "tailscaled", root, []string{"tailscaled"})
	sidecar := inventory.Item{ID: "container:ts", Kind: inventory.KindContainer, Name: "ts", PIDs: []int{850}}
	if p := run([]inventory.Item{sidecar}, nil)["container:ts/tailscaled"]; p.Kind != ViaTunnel || p.Complete || !strings.Contains(strings.Join(p.Gaps, " "), "in a container") {
		t.Errorf("a Tailscale sidecar: %+v", p)
	}
}
