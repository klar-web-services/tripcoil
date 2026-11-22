package facts

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestTarget(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:3334":              "127.0.0.1:3334",
		"http://127.0.0.1:8787":       "127.0.0.1:8787",
		"https://app.internal/path?x": "app.internal:443",
		"http://dokploy:3000":         "dokploy:3000",
		"sonarr:8989":                 "sonarr:8989",
		":8080":                       "localhost:8080",
		"h2c://localhost:9000":        "localhost:9000",
		"[::1]:9000":                  "[::1]:9000",
		"tcp://10.0.0.5:5432":         "10.0.0.5:5432",
		"ssh://localhost":             "localhost:22",
		"unix//run/php/php-fpm.sock":  "unix:/run/php/php-fpm.sock",
		"unix:/run/app.sock":          "unix:/run/app.sock",
		"Arr-Dashboard:3000":          "arr-dashboard:3000",
	} {
		if got, ok := target(in); !ok || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, ok, want)
		}
	}
	// Nothing that is not shaped like an address gets out of a configuration: no word, no variable,
	// no user or password. (A value is only looked at where the format puts an upstream, so the shape
	// is the second guard, not the first.)
	for _, in := range []string{"", "localhost", "backend", "http://admin:hunter2@10.0.0.5:8080", "{$UPSTREAM}", "$backend", "host:port",
		"host:0", "host:70000", "Bearer:abc123", "a b:80", "unix:", "unix:/run/{x}.sock", "admin:$apr1$x", "user:pass@host"} {
		if got, ok := target(in); ok {
			t.Errorf("%q was taken as the target %q", in, got)
		}
	}
}

func TestHostname(t *testing.T) {
	for in, want := range map[string]string{
		"obsidian-mcp.example.com": "obsidian-mcp.example.com", "https://Shop.Example.org:8443/x": "shop.example.org", "*.home.example.net": "*.home.example.net",
	} {
		if got, ok := hostname(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{":8787", "localhost", "_", "192.168.1.5", "http://", "*", "a b.example.org", "{$BASE_DOMAIN}", "tok_en.with spaces"} {
		if got, ok := hostname(in); ok {
			t.Errorf("%q was taken as the hostname %q", in, got)
		}
	}
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return slices.Compact(out)
}

// The owner's two Caddyfiles (2026-11-21), with their secrets replaced by planted ones.
const caddyFront = `{
	admin off
	auto_https off
}

# Front proxy. Only requests under the secret path are forwarded; everything else 404s.
:8787 {
	handle_path /{$SECRET_PATH}/* {
		reverse_proxy 127.0.0.1:3334 {
			header_up Host 127.0.0.1:3333
			header_up Authorization "Bearer {$MCP_HTTP_TOKEN}"
			flush_interval -1
		}
	}
	respond "not found" 404
}
`

const caddyStack = `# Reverse proxy for the whole stack.
{
	email {$ACME_EMAIL}
}

(common) {
	encode zstd gzip
}

*.{$BASE_DOMAIN} {
	tls {
		dns cloudflare {env.CLOUDFLARE_API_TOKEN}
	}
	import common
	import sites/*.caddy

	@sonarr host sonarr.{$BASE_DOMAIN}
	handle @sonarr {
		reverse_proxy sonarr:8989
	}
	@arr host arr.{$BASE_DOMAIN}
	handle @arr {
		reverse_proxy arr-dashboard:3000
	}
	@qbit host qbittorrent.{$BASE_DOMAIN}
	handle @qbit {
		reverse_proxy /api/* gluetun:8080 gluetun:8081
	}
	@auth host auth.{$BASE_DOMAIN}
	handle @auth {
		forward_auth authelia:9091 {
			uri /api/verify
		}
		reverse_proxy {
			to {$BACKEND_HOST}:8096
			lb_policy first
		}
	}
	basicauth {
		admin $2a$14$PLANTEDHASHPLANTEDHASHPLANTEDHASH
	}
	handle {
		respond "unknown host" 404
	}
}
`

func TestCaddyfile(t *testing.T) {
	p := caddyfile(caddyFront, map[string]string{"SECRET_PATH": "s3cret-path", "MCP_HTTP_TOKEN": "planted-token"})
	if !reflect.DeepEqual(p.targets, []string{"127.0.0.1:3334"}) || len(p.hostnames) != 0 || len(p.gaps) != 0 || len(p.includes) != 0 {
		t.Errorf("the front proxy: %+v", p)
	}
	env := map[string]string{"BASE_DOMAIN": "home.example.net", "ACME_EMAIL": "owner@example.net", "CLOUDFLARE_API_TOKEN": "planted-cf-token", "BACKEND_HOST": "jellyfin"}
	p = caddyfile(caddyStack, env)
	if want := []string{"arr-dashboard:3000", "authelia:9091", "gluetun:8080", "gluetun:8081", "jellyfin:8096", "sonarr:8989"}; !reflect.DeepEqual(sorted(p.targets), want) {
		t.Errorf("targets %v", sorted(p.targets))
	}
	// The site's address, and the names its host matchers tell apart: those are the ones that can be looked up.
	if want := []string{"*.home.example.net", "arr.home.example.net", "auth.home.example.net", "qbittorrent.home.example.net", "sonarr.home.example.net"}; !reflect.DeepEqual(sorted(p.hostnames), want) || !reflect.DeepEqual(p.includes, []string{"sites/*.caddy"}) || len(p.gaps) != 0 {
		t.Errorf("hostnames %v, includes %v, gaps %v", p.hostnames, p.includes, p.gaps)
	}
	for _, v := range append(append(p.targets, p.hostnames...), p.includes...) {
		for _, secret := range []string{"planted", "PLANTED", "owner@", "admin"} {
			if strings.Contains(v, secret) {
				t.Errorf("%q left the file", v)
			}
		}
	}
	// A variable Tripcoil cannot fill in, upstreams found at run time, and a JSON configuration: the routing is not fully known.
	for name, text := range map[string]string{
		"an open variable":  "example.org {\n\treverse_proxy {$UPSTREAM}\n}\n",
		"dynamic upstreams": "example.org {\n\treverse_proxy {\n\t\tdynamic a app.internal 8080\n\t}\n}\n",
		"no upstream":       "example.org {\n\treverse_proxy\n}\n",
		"JSON":              `{"apps":{"http":{"servers":{}}}}`,
	} {
		if p := caddyfile(text, map[string]string{}); len(p.gaps) == 0 {
			t.Errorf("%s: no gap in %+v", name, p)
		}
	}
	// One site without braces, and a default for a variable.
	p = caddyfile("shop.example.org\nreverse_proxy {$APP:localhost}:9000\n", map[string]string{})
	if !reflect.DeepEqual(p.targets, []string{"localhost:9000"}) || len(p.gaps) != 0 {
		t.Errorf("without braces: %+v", p)
	}
}

const nginxMain = `user www-data;
events { worker_connections 768; }
http {
	include /etc/nginx/mime.types;
	include /etc/nginx/conf.d/*.conf;
	include sites-enabled/*;
	upstream app {
		server 127.0.0.1:8000 weight=5;
		server unix:/run/app.sock backup;
		server backend.internal;
	}
	server {
		listen 443 ssl;
		server_name shop.example.org www.shop.example.org _;
		ssl_certificate_key /etc/ssl/private/planted.key;
		auth_basic_user_file /etc/nginx/planted.htpasswd;
		location / { proxy_pass http://app; }
		location /api/ { proxy_pass http://127.0.0.1:9000/v1/; proxy_set_header Authorization "Bearer planted-token"; }
		location ~ \.php$ { fastcgi_pass unix:/run/php/php8.2-fpm.sock; }
		location /grpc { grpc_pass grpc://10.0.0.7:50051; }
		location /mem { memcached_pass cache; } # a host without a port
	}
}
stream {
	server { listen 5432; proxy_pass db.internal:5432; }
}
`

func TestNginxConf(t *testing.T) {
	p := nginxConf(nginxMain)
	want := []string{"10.0.0.7:50051", "127.0.0.1:8000", "127.0.0.1:9000", "backend.internal:80", "cache:11211", "db.internal:5432", "unix:/run/app.sock", "unix:/run/php/php8.2-fpm.sock"}
	if !reflect.DeepEqual(sorted(p.targets), want) {
		t.Errorf("targets %v", sorted(p.targets))
	}
	if !reflect.DeepEqual(p.hostnames, []string{"shop.example.org", "www.shop.example.org"}) || len(p.gaps) != 0 ||
		!reflect.DeepEqual(p.includes, []string{"/etc/nginx/mime.types", "/etc/nginx/conf.d/*.conf", "sites-enabled/*"}) {
		t.Errorf("hostnames %v, includes %v, gaps %v", p.hostnames, p.includes, p.gaps)
	}
	for _, v := range append(p.targets, p.hostnames...) {
		if strings.Contains(v, "planted") {
			t.Errorf("%q left the file", v)
		}
	}
	if p := nginxConf("server { location / { proxy_pass http://$upstream_host; } }"); len(p.gaps) != 1 || len(p.targets) != 0 {
		t.Errorf("a target through a variable: %+v", p)
	}
}

// taskmaster's Traefik (2026-11-21): its own file, and the routing file for the Dokploy panel.
const traefikMain = `global:
  sendAnonymousUsage: false
providers:
  swarm:
    exposedByDefault: false
    watch: true
  docker:
    exposedByDefault: false
    watch: true
    network: dokploy-network
  file:
    directory: /etc/dokploy/traefik/dynamic
    watch: true
entryPoints:
  web:
    address: :80
certificatesResolvers:
  letsencrypt:
    acme:
      email: planted@example.org
`

const traefikPanel = `http:
  middlewares:
    tailnet-only:
      ipAllowList:
        sourceRange:
          - 100.64.0.0/10
    auth:
      basicAuth:
        users:
          - "admin:$apr1$PLANTED$hash"
  routers:
    dokploy-router-app-secure:
      rule: Host(` + "`fkws.example`" + `)
      service: dokploy-service-app
      middlewares:
        - tailnet-only
    dokploy-router-webhooks-secure:
      rule: Host(` + "`fkws.example`, `www.fkws.example`" + `) && PathPrefix(` + "`/api/deploy/`" + `)
      service: dokploy-service-app
  services:
    dokploy-service-app:
      loadBalancer:
        servers:
          - url: http://dokploy:3000
        passHostHeader: true
tcp:
  routers:
    db:
      rule: HostSNI(` + "`db.fkws.example`" + `)
  services:
    db:
      loadBalancer:
        servers:
          - address: 10.0.1.5:5432
`

func TestTraefik(t *testing.T) {
	p := traefikStatic(traefikMain)
	if !p.labels || p.labelsAll || !reflect.DeepEqual(p.dirs, []string{"/etc/dokploy/traefik/dynamic"}) || len(p.gaps) != 0 || len(p.targets) != 0 {
		t.Errorf("its own file: %+v", p)
	}
	if p := traefikStatic("providers:\n  docker: {}\n"); !p.labels || !p.labelsAll {
		t.Errorf("Docker's provider exposes every container unless told otherwise: %+v", p)
	}
	if p := traefikStatic("providers:\n  file:\n    filename: /etc/traefik/routes.yml\n  kubernetesCRD: {}\n"); !reflect.DeepEqual(p.includes, []string{"/etc/traefik/routes.yml"}) || len(p.gaps) != 1 {
		t.Errorf("a provider Tripcoil does not read: %+v", p)
	}
	p = traefikDynamic(traefikPanel)
	if !reflect.DeepEqual(sorted(p.targets), []string{"10.0.1.5:5432", "dokploy:3000"}) ||
		!reflect.DeepEqual(sorted(p.hostnames), []string{"db.fkws.example", "fkws.example", "www.fkws.example"}) || len(p.gaps) != 0 {
		t.Errorf("the panel's routes: %+v", p)
	}
	for _, v := range append(p.targets, p.hostnames...) {
		if strings.Contains(v, "PLANTED") || strings.Contains(v, "admin") {
			t.Errorf("%q left the file", v)
		}
	}
	if p := traefikDynamic("http:\n  services:\n    a:\n      loadBalancer:\n        servers:\n          - url: '{{ env \"BACKEND\" }}'\n"); len(p.gaps) != 1 {
		t.Errorf("a templated server: %+v", p)
	}
	if p := traefikDynamic("[http.routers]\n"); len(p.gaps) != 1 {
		t.Errorf("a file that is not YAML: %+v", p)
	}
}

// The owner's cloudflared configuration (2026-11-21), with planted identifiers.
const cloudflaredTunnel = `tunnel: 11111111-2222-3333-4444-555555555555
credentials-file: /home/u/.cloudflared/planted-credentials.json
ingress:
  - hostname: obsidian-mcp.example.com
    service: http://127.0.0.1:8787
  - hostname: api.example.com
    service: http://127.0.0.1:8790
  - service: http_status:404
`

func TestCloudflaredConf(t *testing.T) {
	p := cloudflaredConf(cloudflaredTunnel)
	if !reflect.DeepEqual(p.targets, []string{"127.0.0.1:8787", "127.0.0.1:8790"}) || !reflect.DeepEqual(p.hostnames, []string{"obsidian-mcp.example.com", "api.example.com"}) || len(p.gaps) != 0 {
		t.Errorf("%+v", p)
	}
	if p := cloudflaredConf("url: http://localhost:8000\n"); !reflect.DeepEqual(p.targets, []string{"localhost:8000"}) || len(p.gaps) != 0 {
		t.Errorf("a quick tunnel's url: %+v", p)
	}
	for name, text := range map[string]string{
		"no ingress rules": "tunnel: 11111111-2222-3333-4444-555555555555\ncredentials-file: /x.json\n",
		"a bastion":        "ingress:\n  - hostname: ssh.example.com\n    service: bastion\n",
		"not YAML":         "ingress: [",
	} {
		if p := cloudflaredConf(text); len(p.gaps) == 0 {
			t.Errorf("%s: no gap in %+v", name, p)
		}
	}
}

func TestFunnel(t *testing.T) {
	status := `{"TCP":{"443":{"HTTPS":true},"8443":{"HTTPS":true},"2222":{"TCPForward":"127.0.0.1:22"}},
		"Web":{"pc.tail1234.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}},"pc.tail1234.ts.net:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:9000"},"/files":{"Path":"/srv/files"}}}},
		"AllowFunnel":{"pc.tail1234.ts.net:443":true,"pc.tail1234.ts.net:8443":false}}`
	public, tailnet, err := funnel([]byte(status))
	if err != nil || !reflect.DeepEqual(public.targets, []string{"127.0.0.1:3000"}) || !reflect.DeepEqual(public.hostnames, []string{"pc.tail1234.ts.net"}) ||
		!reflect.DeepEqual(sorted(tailnet.targets), []string{"127.0.0.1:22", "127.0.0.1:9000"}) || len(public.gaps)+len(tailnet.gaps) != 0 {
		t.Errorf("public %+v, tailnet %+v, %v", public, tailnet, err)
	}
	for _, empty := range []string{"", "{}\n"} {
		if public, tailnet, err := funnel([]byte(empty)); err != nil || len(public.targets)+len(tailnet.targets) != 0 {
			t.Errorf("nothing served: %+v %+v %v", public, tailnet, err)
		}
	}
	if _, _, err := funnel([]byte("Serve is not enabled")); err == nil {
		t.Error("output that is no JSON")
	}
}

// A reader must not call a configuration fully read when it skipped part of it.
func TestReadersAdmitWhatTheySkip(t *testing.T) {
	// Caddy: an environment Tripcoil does not know (--envfile) leaves every placeholder open, a default too.
	if p := caddyfile("shop.example.org\nreverse_proxy {$APP:localhost}:9000\n", nil); len(p.targets) != 0 || len(p.gaps) != 1 {
		t.Errorf("an unknown environment: %+v", p)
	}
	// An import with arguments is followed like any other; one whose path has an open placeholder is a gap.
	p := caddyfile("import sites/app.caddy 8080 internal\nimport {$DIR}/more.caddy\n", map[string]string{})
	if !reflect.DeepEqual(p.includes, []string{"sites/app.caddy"}) || len(p.gaps) != 1 {
		t.Errorf("imports: %+v", p)
	}
	// {args[0]} in an imported file is filled in by the import's arguments, which Tripcoil does not do.
	if p := caddyfile("reverse_proxy app:{args[0]}\n", map[string]string{}); len(p.targets) != 0 || len(p.gaps) != 1 {
		t.Errorf("an argument placeholder: %+v", p)
	}
	// A snippet of an earlier file is no file to look for.
	snippets := map[string]bool{}
	caddyfileWith("(common) {\n\tencode gzip\n}\n", map[string]string{}, snippets)
	if p := caddyfileWith("a.example.org {\n\timport common\n\timport other\n}\n", map[string]string{}, snippets); !reflect.DeepEqual(p.includes, []string{"other"}) {
		t.Errorf("a snippet from another file: %+v", p)
	}

	// nginx: Lua code is no configuration. An apostrophe in it must not swallow what follows, and it is a gap.
	lua := "http { server {\n\tlocation /a { content_by_lua_block {\n\t\t-- don't trust {this}; or 'that\n\t\tngx.say(\"hello\")\n\t} }\n\tlocation /b { proxy_pass http://127.0.0.1:8000; }\n} }\n"
	p = nginxConf(lua)
	if !reflect.DeepEqual(p.targets, []string{"127.0.0.1:8000"}) || len(p.gaps) != 1 || !strings.Contains(p.gaps[0], "Lua") {
		t.Errorf("a Lua block: %+v", p)
	}
	// A quote inside a word is a character like any other.
	if p := nginxConf("server { set $who o'brien; location / { proxy_pass http://127.0.0.1:8001; } }"); !reflect.DeepEqual(p.targets, []string{"127.0.0.1:8001"}) || len(p.gaps) != 0 {
		t.Errorf("a quote inside a word: %+v", p)
	}
	if p := nginxConf("server { add_header X 'open; location / { proxy_pass http://127.0.0.1:8002; } }"); len(p.targets) != 0 || len(p.gaps) != 1 {
		t.Errorf("a quote that never closes: %+v", p)
	}

	// Tailscale: what `tailscale funnel 3000` serves while it runs in a terminal, and its services.
	fg := `{"Foreground":{"a1b2":{"TCP":{"443":{"HTTPS":true}},"Web":{"h.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}},"AllowFunnel":{"h.ts.net:443":true}}},
		"Services":{"svc:db":{"TCP":{"5432":{"TCPForward":"127.0.0.1:5432"}}},"svc:all":{"Tun":true}}}`
	public, tailnet, err := funnel([]byte(fg))
	if err != nil || !reflect.DeepEqual(public.targets, []string{"127.0.0.1:3000"}) || !reflect.DeepEqual(public.hostnames, []string{"h.ts.net"}) ||
		!reflect.DeepEqual(tailnet.targets, []string{"127.0.0.1:5432"}) || len(tailnet.gaps) != 1 {
		t.Errorf("foreground and services: %+v %+v %v", public, tailnet, err)
	}

	// A sentence about a gap holds text from a command line or a file name: it stays printable and short,
	// and a program keeps a few of them, however many files it names.
	var g parsed
	for i := 0; i < 3*maxGaps; i++ {
		g.gap("%s could not be read", strings.Repeat("x", 3000)+"\n\x1b[31m"+fmt.Sprint(i))
	}
	g.add(g)
	if len(g.gaps) != maxGaps || len([]rune(g.gaps[0])) > maxGapLen+1 || strings.ContainsAny(strings.Join(g.gaps, ""), "\n\x1b") {
		t.Errorf("%d gaps, the first of %d characters", len(g.gaps), len(g.gaps[0]))
	}
	var many parsed
	for i := 0; i < 20; i++ {
		var one parsed
		for k := 0; k < 1000; k++ {
			one.targets = append(one.targets, fmt.Sprintf("10.%d.%d.1:80", i, k%256))
			one.hostnames = append(one.hostnames, fmt.Sprintf("h%d-%d.example.org", i, k))
		}
		many.add(one)
	}
	if len(many.targets) > 8*maxRouteValues || len(many.hostnames) > 8*maxRouteValues || len(many.hostnames) <= maxRouteValues {
		t.Errorf("%d targets and %d hostnames were kept", len(many.targets), len(many.hostnames))
	}
}
