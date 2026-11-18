package setup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// AddedMarker is the first line of every repository file setup adds; tripcoil uninstall removes
// the files that carry it.
const AddedMarker = "# Added by tripcoil setup; tripcoil uninstall removes it."

// Files setup may add for NodeSource's Node.js 22 repository.
const (
	NodeSourceKeyPath     = "/etc/apt/keyrings/nodesource.asc"
	NodeSourceKeyMarkPath = "/etc/apt/keyrings/nodesource.asc.tripcoil"
	NodeSourceSourcesPath = "/etc/apt/sources.list.d/nodesource.sources"
	NodeSourcePinPath     = "/etc/apt/preferences.d/nodejs"
	NodeSourceRepoPath    = "/etc/yum.repos.d/nodesource-nodejs.repo"
)

// NodeSourceFiles are those files. The key cannot carry the marker: setup writes it only when
// there is no key yet, and then writes the marked file NodeSourceKeyMarkPath beside it, so
// uninstall removes the key only together with that file.
var NodeSourceFiles = []string{NodeSourceKeyPath, NodeSourceSourcesPath, NodeSourceKeyMarkPath, NodeSourcePinPath, NodeSourceRepoPath}

const (
	nodeSourceKeyURL = "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
	armoredKey       = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	claudePackage    = "@anthropic-ai/claude-code"
	// claudeInstall allows the package's postinstall, which npm 12 blocks by default; without it
	// claude is a stub that only prints an error.
	claudeInstall = "npm install -g --allow-scripts=" + claudePackage + " " + claudePackage
)

// fetch downloads url.
func fetch(url string) ([]byte, error) {
	c := http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// claudeCode makes sure Claude Code is installed system-wide, installing Node.js 22 and the npm
// package after confirmation. It returns whether it installed it and whether it is installed.
func (h Host) claudeCode(o Options) (bool, bool, error) {
	p, err := h.FindCLI("", "claude")
	if err == nil {
		fmt.Fprintf(h.Out, "· Claude Code is installed (%s).\n", p)
		return false, true, nil
	}
	if _, lerr := h.LookPath("claude"); lerr == nil {
		return false, false, err // there, but not root-owned: installing over it would not help
	}
	_, npmErr := h.LookPath("npm")
	nodeOK := nodeMajor(h.nodeVersion()) >= 22 && npmErr == nil
	var plan nodePlan
	what := "Claude Code (npm)"
	if !nodeOK {
		if plan, err = h.planNode(); err != nil {
			fmt.Fprintf(h.Out, "! Cannot install Claude Code: %v\n", err)
			return false, false, nil
		}
		what = plan.what + " and Claude Code (npm)"
	}
	if !o.Yes {
		a, err := h.ask("Claude Code is not installed. Install "+what+"? yes or no", "yes", "yes", "no")
		if err != nil {
			return false, false, err
		}
		if a == "no" {
			fmt.Fprintln(h.Out, "! Skipped installing Claude Code.")
			return false, false, nil
		}
	}
	node := ""
	if !nodeOK {
		if node, err = h.installNode(plan); err != nil {
			return false, false, err
		}
	}
	fmt.Fprintln(h.Out, "… Installing Claude Code with npm.")
	if _, err := h.run(strings.Fields(claudeInstall)...); err != nil {
		return false, false, err
	}
	if p, err = h.FindCLI("", "claude"); err != nil {
		msg := "npm installed Claude Code"
		if prefix, perr := h.Run("npm", "prefix", "-g"); perr == nil && strings.TrimSpace(string(prefix)) != "" {
			msg += " under " + strings.TrimSpace(string(prefix)) + "/bin"
		}
		msg += ", but " + err.Error()
		if !strings.Contains(err.Error(), "review.command") {
			msg += "; set review.command to its path, then run setup again"
		}
		return false, false, errors.New(msg)
	}
	if nodeOK {
		fmt.Fprintf(h.Out, "✓ Installed Claude Code (%s).\n", p)
	} else {
		fmt.Fprintf(h.Out, "✓ Installed Node.js %s and Claude Code (%s).\n", strings.TrimPrefix(node, "v"), p)
	}
	return true, true, nil
}

// nodePlan is how to install Node.js 22.
type nodePlan struct {
	what       string // for the question
	manager    string
	nodeSource string // the architecture for NodeSource's repository, or "" when the distribution's nodejs will do
	cmds       [][]string
}

// planNode finds the package manager and whether its nodejs is new enough.
func (h Host) planNode() (nodePlan, error) {
	manager := ""
	for _, m := range []string{"apk", "pacman", "dnf", "apt-get"} {
		if _, err := h.LookPath(m); err == nil {
			manager = m
			break
		}
	}
	p := nodePlan{manager: manager}
	var candidate string
	switch manager {
	case "apk":
		fmt.Fprintln(h.Out, "… Checking which Node.js apk offers.")
		if _, err := h.run("apk", "update"); err != nil {
			return p, err
		}
		out, err := h.run("apk", "search", "-x", "nodejs")
		if err != nil {
			return p, err
		}
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "nodejs-"); ok {
				candidate = v
				break
			}
		}
		if nodeMajor(candidate) < 22 {
			return p, h.tooOld("Alpine's nodejs", candidate, "Alpine 3.21 or later", "apk update")
		}
		p.cmds = [][]string{{"apk", "add", "nodejs", "npm"}}
	case "pacman":
		out, _ := h.Run("pacman", "-Si", "nodejs") // fails when the sync database lacks nodejs
		candidate = field(out, "Version", ":")
		if nodeMajor(candidate) < 22 {
			return p, h.tooOld("pacman's nodejs", candidate, "an up-to-date system", "pacman -Syu")
		}
		p.cmds = [][]string{{"pacman", "-S", "--noconfirm", "--needed", "nodejs", "npm"}}
	case "apt-get":
		fmt.Fprintln(h.Out, "… Checking which Node.js apt-get offers.")
		if _, err := h.run("apt-get", "update"); err != nil {
			return p, err
		}
		out, err := h.run("apt-cache", "policy", "nodejs")
		if err != nil {
			return p, err
		}
		candidate = field(out, "Candidate", ":")
		if nodeMajor(candidate) >= 22 {
			p.cmds = [][]string{{"apt-get", "install", "-y", "nodejs", "npm"}}
		} else { // NodeSource's nodejs bundles npm and conflicts with the npm package
			if p.nodeSource, err = h.nodeSourceArch("amd64", "arm64"); err != nil {
				return p, err
			}
			if err := h.checkHostsNodeSource(NodeSourceSourcesPath, `node_(\d+)\.x`, "node_22.x"); err != nil {
				return p, err
			}
			p.cmds = [][]string{{"apt-get", "update"}, {"apt-get", "install", "-y", "nodejs"}}
		}
	case "dnf":
		fmt.Fprintln(h.Out, "… Checking which Node.js dnf offers.")
		out, err := h.run("dnf", "-q", "repoquery", "--latest-limit", "1", "--qf", `%{version}\n`, "nodejs")
		if err != nil {
			return p, err
		}
		for _, l := range strings.Split(string(out), "\n") { // warnings may come first
			if l = strings.TrimSpace(l); l != "" && l[0] >= '0' && l[0] <= '9' {
				candidate = l
				break
			}
		}
		if nodeMajor(candidate) >= 22 {
			p.cmds = [][]string{{"dnf", "install", "-y", "nodejs", "npm"}}
		} else {
			if p.nodeSource, err = h.nodeSourceArch("x86_64", "aarch64"); err != nil {
				return p, err
			}
			if err := h.checkHostsNodeSource(NodeSourceRepoPath, `pub_(\d+)\.x`, "pub_22.x"); err != nil {
				return p, err
			}
			p.cmds = [][]string{{"dnf", "install", "-y", "nodejs"}}
		}
	default:
		return p, fmt.Errorf("Claude Code needs Node.js 22, and this host has none of apk, pacman, dnf or apt-get; install Node.js 22 or later and npm, then %s%s, and run setup again", h.Sudo, claudeInstall)
	}
	if p.nodeSource != "" {
		p.what = fmt.Sprintf("Node.js 22 (NodeSource's %s repository)", strings.TrimSuffix(manager, "-get"))
	} else {
		p.what = fmt.Sprintf("Node.js %d (%s)", nodeMajor(candidate), manager)
	}
	return p, nil
}

// nodeSourceArch is NodeSource's name for this architecture: amd or arm.
func (h Host) nodeSourceArch(amd, arm string) (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return amd, nil
	case "arm64":
		return arm, nil
	}
	return "", fmt.Errorf("NodeSource has no Node.js 22 for %s; install Node.js 22 or later and npm, then %s%s", runtime.GOARCH, h.Sudo, claudeInstall)
}

// tooOld says the distribution's nodejs is too old, or that there is none, which an update
// command may fix.
func (h Host) tooOld(what, version, needs, update string) error {
	if version == "" {
		return fmt.Errorf("no nodejs package was found; run %s%s first, then run setup again", h.Sudo, update)
	}
	return fmt.Errorf("%s is too old (%s): Claude Code needs Node.js 22 (%s); install Node.js 22 or later and npm, then %s%s", what, version, needs, h.Sudo, claudeInstall)
}

// installNode adds NodeSource's repository when the plan needs it and installs Node.js. It
// returns the installed version.
func (h Host) installNode(p nodePlan) (string, error) {
	if p.nodeSource != "" {
		if err := h.addNodeSource(p.manager, p.nodeSource); err != nil {
			return "", err
		}
	}
	fmt.Fprintf(h.Out, "… Installing Node.js 22 with %s (this takes a minute).\n", p.manager)
	for _, c := range p.cmds {
		if _, err := h.run(c...); err != nil {
			if p.manager == "pacman" {
				return "", fmt.Errorf("%v\nBring the system up to date with %spacman -Syu first, then run setup again.", err, h.Sudo)
			}
			return "", err
		}
	}
	v := h.nodeVersion()
	if nodeMajor(v) < 22 {
		if v == "" {
			v = "missing"
		}
		return "", fmt.Errorf("Node.js is %s after %s; something on the host holds it back (an apt pin or a dnf module, for example)", v, strings.Join(p.cmds[len(p.cmds)-1], " "))
	}
	return v, nil
}

// addNodeSource writes NodeSource's repository for apt-get or dnf. A file that exists without
// the marker is the host's own and stays as it is.
func (h Host) addNodeSource(manager, arch string) error {
	if manager == "dnf" {
		return h.writeAdded(NodeSourceRepoPath, fmt.Sprintf(`[nodesource-nodejs]
name=Node.js Packages for Linux RPM based distros - %s
baseurl=https://rpm.nodesource.com/pub_22.x/nodistro/nodejs/%s
priority=9
enabled=1
gpgcheck=1
gpgkey=https://rpm.nodesource.com/gpgkey/ns-operations-public.key
module_hotfixes=1
`, arch, arch))
	}
	if certs, _ := os.ReadDir(h.path("/etc/ssl/certs")); len(certs) == 0 { // apt and the key's download need them for https
		fmt.Fprintln(h.Out, "… Installing ca-certificates for NodeSource's https repository.")
		if _, err := h.run("apt-get", "install", "-y", "ca-certificates"); err != nil {
			return err
		}
	}
	if !h.hostOwned(NodeSourceSourcesPath) && !h.exists(NodeSourceKeyPath) {
		key, err := h.Fetch(nodeSourceKeyURL)
		if err != nil {
			return fmt.Errorf("downloading NodeSource's key: %v", err)
		}
		if !bytes.HasPrefix(bytes.TrimSpace(key), []byte(armoredKey)) {
			return fmt.Errorf("%s is not an ASCII-armored key", nodeSourceKeyURL)
		}
		if err := h.writeFile(NodeSourceKeyMarkPath, []byte(AddedMarker+"\n")); err != nil {
			return err
		}
		if err := h.writeFile(NodeSourceKeyPath, key); err != nil {
			return err
		}
	}
	if err := h.writeAdded(NodeSourceSourcesPath, fmt.Sprintf(`Types: deb
URIs: https://deb.nodesource.com/node_22.x
Suites: nodistro
Components: main
Architectures: %s
Signed-By: %s
`, arch, NodeSourceKeyPath)); err != nil {
		return err
	}
	return h.writeAdded(NodeSourcePinPath, `Package: nodejs
Pin: origin deb.nodesource.com
Pin-Priority: 600
`)
}

// checkHostsNodeSource checks that the host's own NodeSource file p, if there is one, points at
// Node.js 22 or later: the first match of pattern holds the major.
func (h Host) checkHostsNodeSource(p, pattern, want string) error {
	if !h.hostOwned(p) {
		return nil
	}
	data, err := os.ReadFile(h.path(p))
	if err != nil {
		return err
	}
	if m := regexp.MustCompile(pattern).FindSubmatch(data); m != nil && nodeMajor(string(m[1])) >= 22 {
		return nil
	}
	return fmt.Errorf("%s is the host's own NodeSource repository, for an older Node.js; point it at %s (or remove it), then run setup again", p, want)
}

// hostOwned reports whether p exists without the marker.
func (h Host) hostOwned(p string) bool {
	data, err := os.ReadFile(h.path(p))
	return err == nil && !bytes.HasPrefix(data, []byte(AddedMarker+"\n"))
}

// writeAdded writes data after the marker to p, unless p is the host's own.
func (h Host) writeAdded(p, data string) error {
	if h.hostOwned(p) {
		return nil
	}
	return h.writeFile(p, []byte(AddedMarker+"\n"+data))
}

func (h Host) writeFile(p string, data []byte) error {
	p = h.path(p)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return err
	}
	return os.Chmod(p, 0o644)
}

// nodeVersion is node --version, or "" without node.
func (h Host) nodeVersion() string {
	if _, err := h.LookPath("node"); err != nil {
		return ""
	}
	out, err := h.Run("node", "--version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// nodeMajor is the major version in a version like v22.11.0, 22.11.0-r0 or 1:22.11.0+dfsg-1;
// 0 when there is none.
func nodeMajor(v string) int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, ':'); i > 0 && strings.Trim(v[:i], "0123456789") == "" {
		v = v[i+1:]
	}
	end := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if end < 0 {
		end = len(v)
	}
	n, err := strconv.Atoi(v[:end])
	if err != nil {
		return 0
	}
	return n
}

// field is the value after "name<sep>" on the first line that starts with name, trimmed.
func field(out []byte, name, sep string) string {
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), sep)
		if ok && strings.TrimSpace(k) == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// run runs a command and, when it fails, says which one with the end of its output.
func (h Host) run(args ...string) ([]byte, error) {
	out, err := h.Run(args[0], args[1:]...)
	if err != nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 20 {
			lines = lines[len(lines)-20:]
		}
		return out, fmt.Errorf("%s: %v:\n%s", strings.Join(args, " "), err, strings.Join(lines, "\n"))
	}
	return out, nil
}
