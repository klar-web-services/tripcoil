package setup

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/klar-web-services/tripcoil/internal/sandbox"
)

const (
	claudeTokenKey = "CLAUDE_CODE_OAUTH_TOKEN"
	tokenPrefix    = "sk-ant-oat01-"
)

var (
	tokenPattern = regexp.MustCompile(`^sk-ant-oat01-[A-Za-z0-9_-]{80,300}$`)
	pastePattern = regexp.MustCompile(`^sk-ant-[A-Za-z0-9_-]{33,}$`)
)

// claudeToken creates a token with claude setup-token and saves it to envFile, after
// confirmation; when setup-token prints none, it asks for it. It returns whether it saved one.
func (h Host) claudeToken(o Options, cli, envFile string) (bool, error) {
	if o.Yes || !h.Terminal() {
		return false, nil
	}
	a, err := h.ask("Create a token now with claude setup-token? It uses your Claude subscription (Pro or Max), not API billing. yes or no", "yes", "yes", "no")
	if err != nil || a == "no" {
		return false, err
	}
	fmt.Fprintln(h.Out, "… Running claude setup-token. Sign in when it asks; setup saves the token it prints.")
	out, err := h.SetupToken(cli)
	token, ok := extractToken(out)
	switch {
	case err != nil:
		fmt.Fprintf(h.Out, "! claude setup-token failed: %v.\n", err)
		ok = false
	case !ok:
		fmt.Fprintln(h.Out, "! Setup found no token in what claude setup-token printed.")
	}
	if !ok {
		if token, err = h.pasteToken(); err != nil || token == "" {
			return false, err
		}
	}
	if err := h.writeToken(envFile, claudeTokenKey, token); err != nil {
		return false, err
	}
	fmt.Fprintf(h.Out, "✓ Saved the token ending in …%s to %s.\n", token[len(token)-8:], envFile)
	return true, nil
}

// pasteToken asks for the token with the input hidden; "" skips.
func (h Host) pasteToken() (string, error) {
	for {
		fmt.Fprint(h.Out, "Paste the token claude setup-token printed (input hidden, Enter skips): ")
		line, err := h.readHidden()
		fmt.Fprintln(h.Out)
		t := strings.TrimSpace(strings.NewReplacer("\x1b[200~", "", "\x1b[201~", "").Replace(line)) // bracketed paste
		if err != nil || t == "" {
			return "", nil
		}
		if pastePattern.MatchString(t) {
			return t, nil
		}
		fmt.Fprintln(h.Out, "! That does not look like a token from claude setup-token.")
	}
}

// readHidden reads a line with echo off. Ctrl-C or SIGTERM meanwhile turns echo back on before
// Tripcoil exits.
func (h Host) readHidden() (string, error) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	restore, err := h.NoEcho()
	if err != nil {
		return "", err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case s := <-sig:
			restore()
			fmt.Fprintln(h.Out)
			os.Exit(128 + int(s.(syscall.Signal)))
		case <-done:
		}
	}()
	defer restore()
	return readLine(h.In)
}

// hasToken reports whether envFile sets key to a value.
func (h Host) hasToken(envFile, key string) (bool, error) {
	if envFile == "" {
		return false, nil
	}
	data, err := os.ReadFile(h.path(envFile))
	if err != nil {
		return false, err
	}
	env, err := sandbox.ParseEnvFile(data)
	if err != nil {
		return false, err
	}
	v := ""
	for _, e := range env {
		if k, val, _ := strings.Cut(e, "="); k == key {
			v = val
		}
	}
	return v != "", nil
}

// writeToken sets key to token in envFile, keeping its other lines, and replaces the file at
// once, root-only.
func (h Host) writeToken(envFile, key, token string) error {
	p, err := filepath.EvalSymlinks(h.path(envFile))
	if err != nil {
		return err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var lines []string
	found := false
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		k, _, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok && strings.TrimSpace(strings.TrimPrefix(k, "export ")) == key {
			l, found = key+"="+token, true
		}
		lines = append(lines, l)
	}
	if len(data) == 0 {
		lines = nil
	}
	if !found {
		lines = append(lines, key+"="+token)
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".agent.env-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}

// extractToken finds the token in what claude setup-token printed: the last one, since the
// terminal UI redraws, with a token that wraps over indented lines put back together.
func extractToken(out []byte) (string, bool) {
	s := string(stripEscapes(out))
	token := ""
	for i := 0; ; {
		j := strings.Index(s[i:], tokenPrefix)
		if j < 0 {
			break
		}
		i += j
		if t := scanToken(s[i:]); tokenPattern.MatchString(t) {
			token = t
		}
		i += len(tokenPrefix)
	}
	return token, token != ""
}

func isTokenChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// scanToken reads token characters from the start of s, continuing on each next line that,
// apart from spaces around it, holds only token characters, and not only dashes (a rule).
func scanToken(s string) string {
	var b strings.Builder
	i := 0
	for {
		for i < len(s) && isTokenChar(s[i]) {
			b.WriteByte(s[i])
			i++
		}
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) || s[i] != '\n' {
			return b.String()
		}
		line, _, _ := strings.Cut(s[i+1:], "\n")
		word := strings.TrimLeft(line, " ")
		rest := strings.TrimRight(word, " ")
		if strings.Trim(rest, "-") == "" || strings.IndexFunc(rest, func(r rune) bool { return r > 0x7f || !isTokenChar(byte(r)) }) >= 0 {
			return b.String()
		}
		i += 1 + len(line) - len(word)
	}
}

// stripEscapes drops terminal escape sequences. Cursor moves to another line and carriage
// returns without a newline become newlines, so text drawn on separate lines stays apart.
func stripEscapes(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '\r': // a pseudo-terminal turns "\r\n" into "\r\r\n"
			j := i
			for j < len(b) && b[j] == '\r' {
				j++
			}
			if j >= len(b) || b[j] != '\n' {
				out = append(out, '\n')
			}
			i = j - 1
		case b[i] != 0x1b:
			out = append(out, b[i])
		case i+1 >= len(b):
		case b[i+1] == '[':
			i += 2
			for i < len(b) && b[i] >= 0x20 && b[i] <= 0x3f { // parameters and intermediates
				i++
			}
			if i < len(b) && strings.IndexByte("BEHf", b[i]) >= 0 {
				out = append(out, '\n')
			}
		case b[i+1] == '(' || b[i+1] == ')' || b[i+1] == '#':
			i += 2
		case b[i+1] == ']' || b[i+1] == 'P': // OSC and DCS
			i += 2
			for i < len(b) && b[i] != 0x07 && !(b[i] == 0x1b && i+1 < len(b) && b[i+1] == '\\') {
				i++
			}
			if i < len(b) && b[i] == 0x1b {
				i++
			}
		default:
			i++
		}
	}
	return out
}
