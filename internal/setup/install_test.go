package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const npmInstall = "npm install -g --allow-scripts=@anthropic-ai/claude-code @anthropic-ai/claude-code"

// withoutClaude is a systemd host without Claude Code, with the package manager pm (or none).
func withoutClaude(t *testing.T, pm string) *fakeHost {
	f := newFake(t, Systemd)
	delete(f.tools, "claude")
	if pm != "" {
		f.tools[pm] = true
	}
	return f
}

func TestClaudeCodeInstalled(t *testing.T) {
	f := newFake(t, Systemd)
	if _, err := f.Setup(Options{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(f.cmds, func(c string) bool { return strings.HasPrefix(c, "node") || strings.HasPrefix(c, "npm") }) {
		t.Fatalf("commands %q", f.cmds)
	}
	out := f.out.String()
	if !strings.Contains(out, "· Claude Code is installed (/usr/bin/claude).\n") || strings.Contains(out, npmInstall) {
		t.Fatalf("output:\n%s", out)
	}

	f = newFake(t, Systemd)
	f.FindCLI = func(string, string) (string, error) { return "", errors.New("/usr/bin/claude is not owned by root") }
	if _, err := f.Setup(Options{Yes: true}); err == nil || err.Error() != "/usr/bin/claude is not owned by root" {
		t.Fatalf("got %v", err)
	}
	if slices.ContainsFunc(f.cmds, func(c string) bool { return strings.HasPrefix(c, "npm") }) {
		t.Fatalf("commands %q", f.cmds)
	}
}

func TestClaudeCodeSkipped(t *testing.T) {
	f := withoutClaude(t, "apt-get")
	f.tools["node"], f.tools["npm"] = true, true
	f.replies["node --version"] = "v22.1.0\n"
	f.In = strings.NewReader("no\n")
	if _, err := f.Setup(Options{Agent: "claude"}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.cmds, npmInstall) || slices.Contains(f.cmds, "apt-get update") {
		t.Fatalf("commands %q", f.cmds)
	}
	for _, l := range []string{"Claude Code is not installed. Install Claude Code (npm)? yes or no [yes]: ", "! Skipped installing Claude Code.\n",
		"  1. Install Claude Code system-wide", "       npm install -g --allow-scripts=@anthropic-ai/claude-code @anthropic-ai/claude-code\n"} {
		if !strings.Contains(f.out.String(), l) {
			t.Errorf("output lacks %q:\n%s", l, f.out.String())
		}
	}
}

func TestClaudeCodeWithNode(t *testing.T) {
	f := withoutClaude(t, "apt-get")
	f.tools["node"], f.tools["npm"] = true, true
	f.replies["node --version"] = "v24.0.1\n"
	did, installed, err := f.claudeCode(Options{Yes: true})
	if err != nil || !did || !installed {
		t.Fatal(did, installed, err)
	}
	if !slices.Equal(f.cmds, []string{"node --version", npmInstall}) {
		t.Fatalf("commands %q", f.cmds)
	}
	if out := f.out.String(); out != "… Installing Claude Code with npm.\n✓ Installed Claude Code (/usr/bin/claude).\n" {
		t.Fatalf("output:\n%s", out)
	}
}

func TestClaudeCodePackageManagers(t *testing.T) {
	for _, tc := range []struct {
		pm, query, reply, what string
		cmds                   []string
	}{
		{"apk", "apk search -x nodejs", "nodejs-22.11.0-r0\n", "Node.js 22 (apk)",
			[]string{"apk update", "apk search -x nodejs", "apk add nodejs npm"}},
		{"pacman", "pacman -Si nodejs", "Repository      : extra\nName            : nodejs\nVersion         : 23.1.0-1\n", "Node.js 23 (pacman)",
			[]string{"pacman -Si nodejs", "pacman -S --noconfirm --needed nodejs npm"}},
		{"apt-get", "apt-cache policy nodejs", "nodejs:\n  Installed: (none)\n  Candidate: 22.11.0+dfsg-1\n", "Node.js 22 (apt-get)",
			[]string{"apt-get update", "apt-cache policy nodejs", "apt-get install -y nodejs npm"}},
		{"dnf", `dnf -q repoquery --latest-limit 1 --qf %{version}\n nodejs`, "22.11.0\n22.10.0\n", "Node.js 22 (dnf)",
			[]string{`dnf -q repoquery --latest-limit 1 --qf %{version}\n nodejs`, "dnf install -y nodejs npm"}},
	} {
		t.Run(tc.pm, func(t *testing.T) {
			f := withoutClaude(t, tc.pm)
			f.replies[tc.query] = tc.reply
			f.In = strings.NewReader("\n")
			did, installed, err := f.claudeCode(Options{})
			if err != nil || !did || !installed {
				t.Fatal(did, installed, err)
			}
			if want := append(tc.cmds, "node --version", npmInstall); !slices.Equal(f.cmds, want) {
				t.Fatalf("commands\n%q\nwant\n%q", f.cmds, want)
			}
			for _, l := range []string{"Claude Code is not installed. Install " + tc.what + " and Claude Code (npm)? yes or no [yes]: ",
				"… Installing Node.js 22 with " + tc.pm + " (this takes a minute).\n", "✓ Installed Node.js 22.11.0 and Claude Code (/usr/bin/claude).\n"} {
				if !strings.Contains(f.out.String(), l) {
					t.Errorf("output lacks %q:\n%s", l, f.out.String())
				}
			}
			if _, err := os.Stat(filepath.Join(f.Root, "etc/apt")); err == nil {
				t.Fatal("a distribution's nodejs needs no NodeSource")
			}
		})
	}
}

func nodeSourceArch(amd, arm string) string {
	if runtime.GOARCH == "arm64" {
		return arm
	}
	return amd
}

func TestClaudeCodeNodeSourceApt(t *testing.T) {
	f := withoutClaude(t, "apt-get")
	f.replies["apt-cache policy nodejs"] = "nodejs:\n  Installed: (none)\n  Candidate: 18.19.0+dfsg-6\n"
	key := "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBF\n-----END PGP PUBLIC KEY BLOCK-----\n"
	var fetched []string
	f.Fetch = func(url string) ([]byte, error) { fetched = append(fetched, url); return []byte(key), nil }
	f.In = strings.NewReader("yes\n")
	if _, _, err := f.claudeCode(Options{}); err != nil {
		t.Fatal(err)
	}
	want := []string{"apt-get update", "apt-cache policy nodejs", "apt-get install -y ca-certificates", "apt-get update", "apt-get install -y nodejs", "node --version", npmInstall}
	if !slices.Equal(f.cmds, want) {
		t.Fatalf("commands\n%q\nwant\n%q", f.cmds, want)
	}
	if !slices.Equal(fetched, []string{"https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"}) {
		t.Fatalf("fetched %q", fetched)
	}
	if !strings.Contains(f.out.String(), "Install Node.js 22 (NodeSource's apt repository) and Claude Code (npm)? yes or no [yes]: ") {
		t.Fatalf("output:\n%s", f.out.String())
	}
	for p, data := range map[string]string{
		NodeSourceKeyPath: key,
		NodeSourceSourcesPath: fmt.Sprintf(`# Added by tripcoil setup; tripcoil uninstall removes it.
Types: deb
URIs: https://deb.nodesource.com/node_22.x
Suites: nodistro
Components: main
Architectures: %s
Signed-By: /etc/apt/keyrings/nodesource.asc
`, nodeSourceArch("amd64", "arm64")),
		NodeSourcePinPath: `# Added by tripcoil setup; tripcoil uninstall removes it.
Package: nodejs
Pin: origin deb.nodesource.com
Pin-Priority: 600
`,
	} {
		if got := f.read(t, p); got != data {
			t.Errorf("%s:\n%s\nwant\n%s", p, got, data)
		}
		if fi, _ := os.Stat(filepath.Join(f.Root, p)); fi.Mode().Perm() != 0o644 {
			t.Errorf("%s mode %v", p, fi.Mode())
		}
	}
	if f.read(t, NodeSourceKeyMarkPath) != AddedMarker+"\n" {
		t.Error("the key's mark was not written")
	}
	if fi, _ := os.Stat(filepath.Join(f.Root, "etc/apt/keyrings")); fi.Mode().Perm() != 0o755 {
		t.Errorf("keyrings mode %v", fi.Mode())
	}
}

func TestClaudeCodeNodeSourceAptWithCerts(t *testing.T) {
	f := withoutClaude(t, "apt-get")
	f.replies["apt-cache policy nodejs"] = "nodejs:\n  Candidate: 18.19.0+dfsg-6\n"
	os.MkdirAll(filepath.Join(f.Root, "etc/ssl/certs"), 0o755)
	os.WriteFile(filepath.Join(f.Root, "etc/ssl/certs/ca-certificates.crt"), []byte("certs\n"), 0o644)
	f.Fetch = func(string) ([]byte, error) { return []byte(armoredKey + "\n"), nil }
	if _, _, err := f.claudeCode(Options{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.cmds, "apt-get install -y ca-certificates") || !slices.Contains(f.cmds, "apt-get install -y nodejs") {
		t.Fatalf("commands %q", f.cmds)
	}
}

func TestClaudeCodeNodeSourceDnf(t *testing.T) {
	f := withoutClaude(t, "dnf")
	f.replies[`dnf -q repoquery --latest-limit 1 --qf %{version}\n nodejs`] = "16.20.2\n"
	if _, _, err := f.claudeCode(Options{Yes: true}); err != nil {
		t.Fatal(err)
	}
	want := []string{`dnf -q repoquery --latest-limit 1 --qf %{version}\n nodejs`, "dnf install -y nodejs", "node --version", npmInstall}
	if !slices.Equal(f.cmds, want) {
		t.Fatalf("commands\n%q\nwant\n%q", f.cmds, want)
	}
	arch := nodeSourceArch("x86_64", "aarch64")
	repo := fmt.Sprintf(`# Added by tripcoil setup; tripcoil uninstall removes it.
[nodesource-nodejs]
name=Node.js Packages for Linux RPM based distros - %s
baseurl=https://rpm.nodesource.com/pub_22.x/nodistro/nodejs/%s
priority=9
enabled=1
gpgcheck=1
gpgkey=https://rpm.nodesource.com/gpgkey/ns-operations-public.key
module_hotfixes=1
`, arch, arch)
	if got := f.read(t, NodeSourceRepoPath); got != repo {
		t.Fatalf("repo:\n%s\nwant\n%s", got, repo)
	}
	if fi, _ := os.Stat(filepath.Join(f.Root, NodeSourceRepoPath)); fi.Mode().Perm() != 0o644 {
		t.Fatalf("repo mode %v", fi.Mode())
	}
}

func TestClaudeCodeKeepsTheHostsNodeSource(t *testing.T) {
	f := withoutClaude(t, "apt-get")
	f.replies["apt-cache policy nodejs"] = "nodejs:\n  Candidate: (none)\n"
	own := map[string]string{
		NodeSourceSourcesPath: "Types: deb\nURIs: https://deb.nodesource.com/node_24.x\n",
		NodeSourcePinPath:     "host's own\n",
	}
	for p, data := range own {
		os.MkdirAll(filepath.Dir(filepath.Join(f.Root, p)), 0o755)
		os.WriteFile(filepath.Join(f.Root, p), []byte(data), 0o644)
	}
	if _, _, err := f.claudeCode(Options{Yes: true}); err != nil { // f.Fetch fails, so the key is not fetched
		t.Fatal(err)
	}
	for p, data := range own {
		if got := f.read(t, p); got != data {
			t.Errorf("%s was rewritten: %q", p, got)
		}
	}
	if _, err := os.Stat(filepath.Join(f.Root, NodeSourceKeyPath)); err == nil {
		t.Error("the key was written")
	}
	if !slices.Contains(f.cmds, "apt-get install -y nodejs") {
		t.Fatalf("commands %q", f.cmds)
	}
}

func TestClaudeCodeKeepsAnExistingKey(t *testing.T) {
	f := withoutClaude(t, "apt-get")
	f.replies["apt-cache policy nodejs"] = "nodejs:\n  Candidate: (none)\n"
	os.MkdirAll(filepath.Join(f.Root, "etc/apt/keyrings"), 0o755)
	os.WriteFile(filepath.Join(f.Root, NodeSourceKeyPath), []byte("the host's key\n"), 0o644)
	if _, _, err := f.claudeCode(Options{Yes: true}); err != nil { // f.Fetch fails, so the key is not fetched
		t.Fatal(err)
	}
	if got := f.read(t, NodeSourceKeyPath); got != "the host's key\n" {
		t.Fatalf("key %q", got)
	}
	if _, err := os.Stat(filepath.Join(f.Root, NodeSourceKeyMarkPath)); err == nil {
		t.Fatal("the host's key was marked as setup's")
	}
	if !strings.HasPrefix(f.read(t, NodeSourceSourcesPath), AddedMarker+"\n") {
		t.Fatal("the sources file was not written")
	}
}

func TestClaudeCodeRefusesTheHostsOldNodeSource(t *testing.T) {
	for _, tc := range []struct {
		pm, query, reply, path, data, want string
	}{
		{"apt-get", "apt-cache policy nodejs", "  Candidate: 20.18.0-1nodesource1\n", NodeSourceSourcesPath,
			"Types: deb\nURIs: https://deb.nodesource.com/node_20.x\nSuites: nodistro\n", "point it at node_22.x"},
		{"dnf", `dnf -q repoquery --latest-limit 1 --qf %{version}\n nodejs`, "20.18.0\n", NodeSourceRepoPath,
			"[nodesource-nodejs]\nbaseurl=https://rpm.nodesource.com/pub_20.x/nodistro/nodejs/x86_64\n", "point it at pub_22.x"},
	} {
		t.Run(tc.pm, func(t *testing.T) {
			f := withoutClaude(t, tc.pm)
			f.replies[tc.query] = tc.reply
			os.MkdirAll(filepath.Dir(filepath.Join(f.Root, tc.path)), 0o755)
			os.WriteFile(filepath.Join(f.Root, tc.path), []byte(tc.data), 0o644)
			if did, ok, err := f.claudeCode(Options{Yes: true}); did || ok || err != nil {
				t.Fatalf("got %v %v %v", did, ok, err)
			}
			if out := f.out.String(); !strings.Contains(out, "! Cannot install Claude Code: "+tc.path+" is the host's own NodeSource repository") || !strings.Contains(out, tc.want) {
				t.Fatalf("output:\n%s", out)
			}
			if f.read(t, tc.path) != tc.data || slices.ContainsFunc(f.cmds, func(c string) bool { return strings.Contains(c, "install") }) {
				t.Fatalf("changed something: %q", f.cmds)
			}
		})
	}
}

func TestClaudeCodeBadKey(t *testing.T) {
	for name, fetch := range map[string]func(string) ([]byte, error){
		"fetch fails": func(string) ([]byte, error) { return nil, errors.New("connection refused") },
		"not armored": func(string) ([]byte, error) { return []byte("<html>"), nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := withoutClaude(t, "apt-get")
			f.replies["apt-cache policy nodejs"] = "  Candidate: (none)\n"
			f.Fetch = fetch
			_, _, err := f.claudeCode(Options{Yes: true})
			if err == nil || !strings.Contains(err.Error(), "downloading NodeSource's key: connection refused") && !strings.Contains(err.Error(), "is not an ASCII-armored key") {
				t.Fatalf("got %v", err)
			}
			if _, err := os.Stat(filepath.Join(f.Root, "etc/apt/sources.list.d")); err == nil || slices.Contains(f.cmds, "apt-get install -y nodejs") {
				t.Fatalf("installed something: %q", f.cmds)
			}
		})
	}
}

func TestClaudeCodeDnfWarnings(t *testing.T) {
	f := withoutClaude(t, "dnf")
	f.replies[`dnf -q repoquery --latest-limit 1 --qf %{version}\n nodejs`] = "Updating Subscription Management repositories.\n22.11.0\n"
	if _, _, err := f.claudeCode(Options{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.cmds, "dnf install -y nodejs npm") {
		t.Fatalf("commands %q", f.cmds)
	}
}

func TestClaudeCodeNoWhenNodeIsMissing(t *testing.T) {
	f := withoutClaude(t, "apt-get")
	f.replies["apt-cache policy nodejs"] = "  Candidate: 22.11.0+dfsg-1\n"
	f.In = strings.NewReader("no\n")
	did, installed, err := f.claudeCode(Options{})
	if err != nil || did || installed {
		t.Fatal(did, installed, err)
	}
	if !slices.Equal(f.cmds, []string{"apt-get update", "apt-cache policy nodejs"}) {
		t.Fatalf("commands %q", f.cmds)
	}
	if !strings.Contains(f.out.String(), "Install Node.js 22 (apt-get) and Claude Code (npm)? yes or no [yes]: ! Skipped installing Claude Code.\n") {
		t.Fatalf("output:\n%s", f.out.String())
	}
}

func TestClaudeCodeCannotInstall(t *testing.T) {
	for _, tc := range []struct {
		name, pm, want string
		prepare        func(*fakeHost)
	}{
		{"apk too old", "apk", "Alpine's nodejs is too old (20.15.1-r0): Claude Code needs Node.js 22 (Alpine 3.21 or later)", func(f *fakeHost) {
			f.replies["apk search -x nodejs"] = "nodejs-20.15.1-r0\n"
		}},
		{"apk no package", "apk", "no nodejs package was found; run apk update first, then run setup again", func(*fakeHost) {}},
		{"pacman too old", "pacman", "pacman's nodejs is too old (20.1.0-1)", func(f *fakeHost) {
			f.replies["pacman -Si nodejs"] = "Name            : nodejs\nVersion         : 20.1.0-1\n"
		}},
		{"pacman no package", "pacman", "no nodejs package was found; run pacman -Syu first, then run setup again", func(f *fakeHost) {
			f.fail["pacman -Si"] = true
			f.replies["pacman -Si nodejs"] = "error: package 'nodejs' was not found\n"
		}},
		{"apt-get update fails", "apt-get", "apt-get update: exit status 3:\nE: Could not resolve", func(f *fakeHost) {
			f.fail["apt-get update"] = true
			f.replies["apt-get update"] = "E: Could not resolve 'deb.debian.org'\n"
		}},
		{"no package manager", "", "this host has none of apk, pacman, dnf or apt-get; install Node.js 22 or later and npm, then npm install -g --allow-scripts=@anthropic-ai/claude-code @anthropic-ai/claude-code", func(*fakeHost) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := withoutClaude(t, tc.pm)
			tc.prepare(f)
			if _, err := f.Setup(Options{Agent: "claude", Yes: true}); err != nil {
				t.Fatal(err)
			}
			out := f.out.String()
			if !strings.Contains(out, "! Cannot install Claude Code: ") || !strings.Contains(out, tc.want) || !strings.Contains(out, "✓ Installed and started the tripcoil service.") ||
				!strings.Contains(out, "  1. Install Claude Code system-wide") {
				t.Fatalf("output:\n%s", out)
			}
			if slices.ContainsFunc(f.cmds, func(c string) bool { return strings.Contains(c, "nodejs npm") || strings.HasPrefix(c, "npm") }) {
				t.Fatalf("commands %q", f.cmds)
			}
		})
	}
}

func TestClaudeCodeInstallFails(t *testing.T) {
	f := withoutClaude(t, "apt-get")
	f.replies["apt-cache policy nodejs"] = "  Candidate: 22.11.0+dfsg-1\n"
	f.replies["node --version"] = "v20.0.0\n"
	if _, _, err := f.claudeCode(Options{Yes: true}); err == nil || !strings.Contains(err.Error(), "Node.js is v20.0.0 after apt-get install -y nodejs npm") {
		t.Fatalf("node held back: %v", err)
	}

	f = withoutClaude(t, "pacman")
	f.replies["pacman -Si nodejs"] = "Version         : 23.1.0-1\n"
	f.fail["pacman -S "] = true
	f.replies["pacman -S --noconfirm --needed nodejs npm"] = "error: failed to prepare transaction (could not satisfy dependencies)\n"
	if _, _, err := f.claudeCode(Options{Yes: true}); err == nil ||
		!strings.HasSuffix(err.Error(), "could not satisfy dependencies)\nBring the system up to date with pacman -Syu first, then run setup again.") {
		t.Fatalf("pacman: %v", err)
	}
}

func TestClaudeCodeNpmFails(t *testing.T) {
	f := withoutClaude(t, "")
	f.tools["node"], f.tools["npm"] = true, true
	f.replies["node --version"] = "v22.11.0\n"
	var lines []string
	for i := 1; i <= 30; i++ {
		lines = append(lines, fmt.Sprintf("npm error line %d", i))
	}
	f.replies[npmInstall] = strings.Join(lines, "\n") + "\n"
	f.fail["npm install"] = true
	_, _, err := f.claudeCode(Options{Yes: true})
	if err == nil || !strings.HasPrefix(err.Error(), npmInstall+": exit status 3:\nnpm error line 11\n") || !strings.HasSuffix(err.Error(), "npm error line 30") {
		t.Fatalf("got %v", err)
	}

	for _, tc := range []struct{ prefix, findErr, want string }{
		{"/opt/npm\n", "claude is not executable", "npm installed Claude Code under /opt/npm/bin, but claude is not executable; set review.command to its path, then run setup again"},
		{"", "claude is not installed on /usr/bin; install it system-wide, or set review.command", "npm installed Claude Code, but claude is not installed on /usr/bin; install it system-wide, or set review.command"},
	} {
		f = withoutClaude(t, "")
		f.tools["node"], f.tools["npm"] = true, true
		f.replies["node --version"] = "v22.11.0\n"
		f.replies["npm prefix -g"] = tc.prefix
		f.FindCLI = func(string, string) (string, error) { return "", errors.New(tc.findErr) }
		if _, _, err := f.claudeCode(Options{Yes: true}); err == nil || err.Error() != tc.want {
			t.Fatalf("got %v", err)
		}
	}
}

func TestNodeMajor(t *testing.T) {
	for v, want := range map[string]int{
		"v22.11.0": 22, "22.11.0-r0": 22, "1:22.11.0+dfsg-1": 22, "23.1.0-1": 23, "  v18.19.0\n": 18,
		"(none)": 0, "": 0, "v": 0, "x22": 0, "99999999999999999999999": 0, "a:22": 0,
	} {
		if got := nodeMajor(v); got != want {
			t.Errorf("nodeMajor(%q) = %d, want %d", v, got, want)
		}
	}
}
