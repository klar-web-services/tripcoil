package setup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/agent"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/run"
	"github.com/klar-web-services/tripcoil/internal/sandbox"
)

// Host is the machine setup works on. Root prefixes every path, so tests can use a folder.
type Host struct {
	Root     string
	Exe      string // Tripcoil's own binary, links resolved
	Sudo     string // the prefix for a command in a hint (see Sudo)
	Run      func(name string, args ...string) ([]byte, error)
	LookPath func(name string) (string, error)
	// UserExists and GroupExists look up the agent's user and group.
	UserExists  func(name string) bool
	GroupExists func(name string) bool
	// CheckBinary checks that the binary is root-owned and writable only by root, with every
	// folder above it (the service runs it as root).
	CheckBinary func(path string) error
	Stat        config.StatFunc // checks review.envFile
	In          io.Reader       // answers to questions
	Out         io.Writer
}

// NewHost is this machine.
func NewHost(exe string, in io.Reader, out io.Writer) Host {
	return Host{
		Exe: exe, In: in, Out: out,
		Sudo: Sudo(os.Geteuid(), os.Getenv("SUDO_USER")),
		Run: func(name string, args ...string) ([]byte, error) {
			cmd := exec.Command(name, args...)
			cmd.Env = append(os.Environ(), "PATH="+sandbox.Path)
			return cmd.CombinedOutput()
		},
		LookPath:    agent.LookPath,
		UserExists:  func(n string) bool { _, err := user.Lookup(n); return err == nil },
		GroupExists: func(n string) bool { _, err := user.LookupGroup(n); return err == nil },
		CheckBinary: func(p string) error { _, err := agent.FindCLI(p, "tripcoil"); return err },
		Stat:        config.OSStat,
	}
}

// Sudo is the prefix for a command in a hint: "sudo " unless the user is root without sudo.
func Sudo(euid int, sudoUser string) string {
	if euid == 0 && sudoUser == "" {
		return ""
	}
	return "sudo "
}

func (h Host) path(p string) string { return filepath.Join(h.Root, p) }

func (h Host) exists(p string) bool {
	_, err := os.Lstat(h.path(p))
	return err == nil
}

// Manager detects the service manager: systemd when it booted the host, otherwise OpenRC.
func (h Host) Manager() (Manager, error) {
	switch {
	case h.exists("/run/systemd/system"):
		return Systemd, nil
	case h.exists("/sbin/openrc-run") || h.exists("/usr/sbin/openrc-run"):
		return OpenRC, nil
	}
	return "", errors.New("this host runs neither systemd nor OpenRC, so Tripcoil cannot install its service")
}

// Options are setup's flags.
type Options struct {
	Agent string // claude, codex, none, or "" to ask (or keep the config's)
	Yes   bool   // accept the defaults instead of asking
}

// Setup sets the host up (spec section 9). Every step leaves what is already in place alone, so
// a second run changes nothing (AC-15).
func (h Host) Setup(o Options) error {
	m, err := h.Manager()
	if err != nil {
		return err
	}
	if err := h.checkBinary(); err != nil {
		return err
	}
	changed := false
	note := func(did bool, done, kept string) {
		if did {
			changed = true
			fmt.Fprintf(h.Out, "✓ %s\n", done)
		} else {
			fmt.Fprintf(h.Out, "· %s\n", kept)
		}
	}
	if m == Systemd {
		h.warnOldSystemd()
	}
	did, err := h.agentUser()
	if err != nil {
		return err
	}
	note(did, "Created the user and group "+agent.UserName+".", "The user "+agent.UserName+" exists.")
	name, envFile, did, created, err := h.config(o)
	if err != nil {
		return err
	}
	wrote := fmt.Sprintf("Wrote %s (review.agent: %s).", config.DefaultPath, name)
	if created {
		wrote = fmt.Sprintf("Wrote %s (review.agent: %s) and %s.", config.DefaultPath, name, envFile)
	}
	note(did, wrote, fmt.Sprintf("%s exists (review.agent: %s).", config.DefaultPath, name))
	if m == OpenRC && name != "none" {
		did, err := h.bubblewrap(o)
		if err != nil {
			return err
		}
		note(did, "Installed bubblewrap.", "bubblewrap is installed.")
	}
	did, err = h.service(m)
	if err != nil {
		return err
	}
	note(did, "Installed and started the tripcoil service.", "The tripcoil service is installed and running.")
	if !changed {
		fmt.Fprintln(h.Out, "Nothing changed.")
	}
	fmt.Fprint(h.Out, nextSteps(name, envFile, h.Sudo))
	return nil
}

// pathPattern is what the binary's path may hold: it goes unquoted into the service files, and
// systemd reads % as a specifier and the OpenRC script runs in a shell.
var pathPattern = regexp.MustCompile(`^/[A-Za-z0-9/._+-]+$`)

func (h Host) checkBinary() error {
	exe := h.Exe
	if !pathPattern.MatchString(exe) {
		return fmt.Errorf("%q has characters the service files cannot hold; install Tripcoil to /usr/local/bin", exe)
	}
	if strings.HasPrefix(exe, "/home/") || exe == "/home" {
		return fmt.Errorf("%s is under /home; install Tripcoil system-wide first (curl -fsSL https://tools.klar.ws/tripcoil/install.sh | %ssh)", exe, h.Sudo)
	}
	if err := h.CheckBinary(exe); err != nil {
		return fmt.Errorf("the service would run %s as root, but %v", exe, err)
	}
	return nil
}

func (h Host) warnOldSystemd() {
	out, err := h.Run("systemctl", "--version")
	if err != nil {
		return
	}
	if v, err := sandbox.SystemdVersion(out); err == nil && v < sandbox.MinSystemd {
		fmt.Fprintf(h.Out, "! systemd %d is older than %d, which the review's sandbox needs: reports will be audit-only.\n", v, sandbox.MinSystemd)
	}
}

// agentUser creates the agent's system user and its group, without a home or a login shell.
func (h Host) agentUser() (bool, error) {
	u, g := h.UserExists(agent.UserName), h.GroupExists(run.AgentGroup)
	switch {
	case u && g:
		return false, nil
	case u || g:
		return false, fmt.Errorf("only one of the user and the group %s exists; remove it or create the other, then run setup again", agent.UserName)
	}
	shell := "/usr/sbin/nologin"
	if !h.exists(shell) {
		shell = "/sbin/nologin"
	}
	var cmds [][]string
	if _, err := h.LookPath("useradd"); err == nil {
		cmds = [][]string{{"useradd", "--system", "--user-group", "--no-create-home", "--shell", shell, agent.UserName}}
	} else { // BusyBox, as on Alpine
		cmds = [][]string{{"addgroup", "-S", run.AgentGroup}, {"adduser", "-S", "-D", "-H", "-s", shell, "-G", run.AgentGroup, agent.UserName}}
	}
	for _, c := range cmds {
		if out, err := h.Run(c[0], c[1:]...); err != nil {
			return false, fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, bytes.TrimSpace(out))
		}
	}
	return true, nil
}

// config writes the config file when there is none, with the chosen agent, and the empty token
// file it names, unless that exists. An existing config is kept as it is. Either way the config
// must be valid; it returns review.agent, review.envFile, and whether it wrote the config and
// created the token file.
func (h Host) config(o Options) (string, string, bool, bool, error) {
	path := h.path(config.DefaultPath)
	if _, err := os.Lstat(path); err == nil {
		c, err := h.loadConfig()
		if err != nil {
			return "", "", false, false, err
		}
		if o.Agent != "" && o.Agent != c.Review.Agent {
			fmt.Fprintf(h.Out, "! --agent %s: %s keeps review.agent: %s; edit it to change the agent.\n", o.Agent, config.DefaultPath, c.Review.Agent)
		}
		return c.Review.Agent, c.Review.EnvFile, false, false, nil
	}
	name := o.Agent
	if name == "" {
		name = "claude"
		if !o.Yes {
			a, err := h.ask("Which agent CLI should review the runs? claude, codex or none", "claude", "claude", "codex", "none")
			if err != nil {
				return "", "", false, false, err
			}
			name = a
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", "", false, false, err
	}
	// The token file comes first: should that fail, there is no config yet and a rerun starts over.
	created := false
	if f, err := os.OpenFile(h.path(EnvFilePath), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		f.Close()
		created = true
	} else if !errors.Is(err, fs.ErrExist) {
		return "", "", false, false, err
	}
	if err := os.WriteFile(path, []byte(DefaultConfig(name)), 0o644); err != nil {
		return "", "", false, false, err
	}
	c, err := h.loadConfig()
	if err != nil {
		return "", "", false, false, err
	}
	return name, c.Review.EnvFile, true, created, nil
}

// loadConfig reads and validates the config, with its paths under Root.
func (h Host) loadConfig() (config.Config, error) {
	path := h.path(config.DefaultPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return config.Config{}, err
	}
	return config.Parse(path, data, func(p string) (config.FileInfo, error) { return h.Stat(h.path(p)) })
}

// ask asks a question until the answer is one of choices; an empty answer is def.
func (h Host) ask(q, def string, choices ...string) (string, error) {
	for {
		fmt.Fprintf(h.Out, "%s [%s]: ", q, def)
		line, err := readLine(h.In)
		if err != nil {
			return "", errors.New("no answer; run setup with --yes, or with --agent")
		}
		a := strings.TrimSpace(line)
		if a == "" {
			return def, nil
		}
		for _, c := range choices {
			if a == c {
				return a, nil
			}
		}
	}
}

// readLine reads one line a byte at a time, so the next question finds the rest of the input.
func readLine(r io.Reader) (string, error) {
	var b []byte
	c := make([]byte, 1)
	for {
		n, err := r.Read(c)
		if n == 1 {
			if c[0] == '\n' {
				return string(b), nil
			}
			b = append(b, c[0])
		}
		if err != nil {
			if len(b) > 0 && errors.Is(err, io.EOF) {
				return string(b), nil
			}
			return "", err
		}
	}
}

// bubblewrap installs bubblewrap, the review's sandbox without systemd, after confirmation.
func (h Host) bubblewrap(o Options) (bool, error) {
	if _, err := h.LookPath("bwrap"); err == nil {
		return false, nil
	}
	if _, err := h.LookPath("apk"); err != nil {
		return false, errors.New("bubblewrap is not installed; install it with the host's package manager, then run setup again")
	}
	if !o.Yes {
		a, err := h.ask("The review's sandbox needs bubblewrap. Install it with apk add bubblewrap? yes or no", "yes", "yes", "no")
		if err != nil {
			return false, err
		}
		if a == "no" {
			return false, errors.New("bubblewrap is not installed; reviews cannot run without it (apk add bubblewrap)")
		}
	}
	if out, err := h.Run("apk", "add", "bubblewrap"); err != nil {
		return false, fmt.Errorf("apk add bubblewrap: %v: %s", err, bytes.TrimSpace(out))
	}
	return true, nil
}

// service writes the service files that differ, then enables and starts the service, restarting
// it when its files changed.
func (h Host) service(m Manager) (bool, error) {
	wrote := false
	for _, f := range ServiceFiles(m, h.Exe) {
		p := h.path(f.Path)
		if old, err := os.ReadFile(p); err == nil && string(old) == f.Data {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return false, err
		}
		if err := os.WriteFile(p, []byte(f.Data), fs.FileMode(f.Mode)); err != nil {
			return false, err
		}
		if err := os.Chmod(p, fs.FileMode(f.Mode)); err != nil {
			return false, err
		}
		wrote = true
	}
	var steps [][]string
	if m == Systemd {
		if wrote {
			steps = append(steps, []string{"systemctl", "daemon-reload"})
		}
		if _, err := h.Run("systemctl", "is-enabled", "--quiet", "tripcoil.service"); err != nil {
			steps = append(steps, []string{"systemctl", "enable", "--quiet", "tripcoil.service"})
		}
		_, err := h.Run("systemctl", "is-active", "--quiet", "tripcoil.service")
		switch {
		case err != nil:
			steps = append(steps, []string{"systemctl", "start", "tripcoil.service"})
		case wrote:
			steps = append(steps, []string{"systemctl", "restart", "tripcoil.service"})
		}
	} else {
		if out, _ := h.Run("rc-update", "show", "default"); !hasService(out) {
			steps = append(steps, []string{"rc-update", "add", "tripcoil", "default"})
		}
		_, err := h.Run("rc-service", "tripcoil", "status")
		switch {
		case err != nil:
			steps = append(steps, []string{"rc-service", "tripcoil", "start"})
		case wrote:
			steps = append(steps, []string{"rc-service", "tripcoil", "restart"})
		}
	}
	for _, s := range steps {
		if out, err := h.Run(s[0], s[1:]...); err != nil {
			return false, fmt.Errorf("%s: %v: %s", strings.Join(s, " "), err, bytes.TrimSpace(out))
		}
	}
	return wrote || len(steps) > 0, nil
}

// hasService reports whether rc-update show lists tripcoil.
func hasService(out []byte) bool {
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "tripcoil" {
			return true
		}
	}
	return false
}

// nextSteps says how to install the agent CLI system-wide and give it credentials in envFile
// (spec 8.3), and how each agent is billed.
func nextSteps(name, envFile, sudo string) string {
	edit := "sudoedit"
	if sudo == "" {
		edit = "vi"
	}
	var install, token, line string
	switch name {
	case "claude":
		install = "Claude Code system-wide (root-owned, outside /home), for example:\n       " + sudo + "npm install -g @anthropic-ai/claude-code"
		token = `Create a token with "claude setup-token" (as any user, on any machine). It uses your Claude
     subscription (Pro or Max), not API billing.`
		line = "CLAUDE_CODE_OAUTH_TOKEN=<token>"
	case "codex":
		install = "Codex system-wide (root-owned, outside /home), for example:\n       " + sudo + "npm install -g @openai/codex"
		token = `Create an OpenAI API key. Codex bills it per use through the OpenAI API (a ChatGPT login is
     not supported).`
		line = "CODEX_API_KEY=<key>"
	default:
		return fmt.Sprintf(`
review.agent is none, so reports are audit-only. Check the host: %stripcoil doctor
`, sudo)
	}
	store := fmt.Sprintf("Add it to %s as the line %s:\n       %s %s", envFile, line, edit, envFile)
	if envFile == "" {
		store = fmt.Sprintf(`Store it root-only as the line %s, and set review.envFile in
     %s to that file:
       %sinstall -m 600 /dev/null %s
       %s %s`, line, config.DefaultPath, sudo, EnvFilePath, edit, EnvFilePath)
	}
	return fmt.Sprintf(`
Next, give the review its credentials:
  1. Install %s
  2. %s
  3. %s
Then check the host: %stripcoil doctor
`, install, token, store, sudo)
}

// Service is the tripcoil service's state.
type Service struct {
	Manager   Manager
	Installed bool
	Running   bool
}

// Service reports whether the tripcoil service is installed and running.
func (h Host) Service() (Service, error) {
	m, err := h.Manager()
	if err != nil {
		return Service{}, err
	}
	s := Service{Manager: m}
	if m == Systemd {
		s.Installed = h.exists(UnitPath)
		_, err = h.Run("systemctl", "is-active", "--quiet", "tripcoil.service")
	} else {
		s.Installed = h.exists(InitScriptPath)
		_, err = h.Run("rc-service", "tripcoil", "status")
	}
	s.Running = s.Installed && err == nil
	return s, nil
}
