package setup

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const testToken = "sk-ant-oat01-BrPERz" + "Ab3_-xCd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5ab6cd7ef8gh9ij0kl1mn2op3qr4st5uv6wx7yz8" + "AAA"

// setupTokenOutput is what claude setup-token prints at the end, with the token split at the
// given widths, each part on its own indented line.
func setupTokenOutput(widths ...int) string {
	parts, rest := []string{}, testToken
	for _, w := range widths {
		parts, rest = append(parts, rest[:w]), rest[w:]
	}
	parts = append(parts, rest)
	return "\x1b[32m✓\x1b[39m Long-lived authentication token created successfully!\r\n\r\n" +
		"   Your OAuth token (valid for 1 year):\r\n\r\n   \x1b[1m" + strings.Join(parts, "\r\n   ") + "\x1b[22m\r\n\r\n" +
		"   Store this token securely. You won't be able to see it again.\r\n\r\n" +
		"   Use this token by setting: export CLAUDE_CODE_OAUTH_TOKEN=<token>\r\n"
}

func TestExtractToken(t *testing.T) {
	for _, c := range []struct {
		name, out string
		ok        bool
	}{
		{"one line", setupTokenOutput(), true},
		{"two lines", setupTokenOutput(60), true},
		{"three lines", setupTokenOutput(40, 40), true},
		{"colours inside", strings.Replace(setupTokenOutput(), "BrPERz", "Br\x1b[31mPE\x1b[0mRz\x1b]8;;https://x\x07", 1), true},
		{"redrawn", "\x1b[2K\x1b[1A\x1b[2K\x1b[G" + strings.Replace(setupTokenOutput(50), testToken[:10], "sk-ant-oat01-zz", 1) +
			"\x1b[2K\x1b[1A\x1b[2K\x1b[1A\x1b[2K\x1b[G" + setupTokenOutput(50) + "\x1b[?25h", true},
		{"no blank line after", "   " + testToken[:50] + "\n   " + testToken[50:] + "\n   Store this token securely.\n", true},
		{"trailing spaces", "   " + testToken[:50] + "   \n   " + testToken[50:] + "  \n\n", true},
		{"cursor moves with padding", "   " + testToken[:50] + "      \x1b[1B\x1b[4G" + testToken[50:] + "\x1b[12;4H   Store this token securely.", true},
		{"cursor position wrap", "   " + testToken[:50] + "   \x1b[12;4H" + testToken[50:] + "\r\n\r\n", true},
		{"carriage return wrap", "   " + testToken[:50] + "\r   " + testToken[50:] + "\r\n\r\n", true},
		{"pseudo-terminal newlines", strings.ReplaceAll(setupTokenOutput(50), "\r\n", "\r\r\n"), true},
		{"charset after", "   " + testToken + "\x1b(B\x1b[m\r\n", true},
		{"DCS before", "\x1bPq#0;2;0;0;0\x1b\\   " + testToken + "\r\n", true},
		{"rule after", "   " + testToken + "\n   ---------------------\n", true},
		{"no token", "Error: sign-in was cancelled\r\n", false},
		{"truncated", "   sk-ant-oat01-BrPERzAb3\r\n\r\n   Store this token securely.\r\n", false},
		{"short fragment", "   " + testToken[:13+60] + "\r\n\r\n   Store this token securely.\r\n", false},
		{"cut by a carriage return", "   " + testToken[:70] + "\r Store this token securely.\r\n", false},
	} {
		got, ok := extractToken([]byte(c.out))
		if ok != c.ok || (ok && got != testToken) {
			t.Errorf("%s: got %q, %v", c.name, got, ok)
		}
	}
}

// tokenHost is a systemd host with Claude Code, on a terminal, whose claude setup-token prints out
// or fails with err.
func tokenHost(t *testing.T, input, out string, err error) *fakeHost {
	f := newFake(t, Systemd)
	f.Terminal = func() bool { return true }
	f.In = strings.NewReader(input)
	f.SetupToken = func(cli string) ([]byte, error) {
		if cli != "/usr/bin/claude" {
			t.Errorf("setup-token ran %s", cli)
		}
		fmt.Fprint(&f.out, "<setup-token>")
		return []byte(out), err
	}
	return f
}

func (f *fakeHost) token(t *testing.T) string {
	t.Helper()
	fi, err := os.Stat(filepath.Join(f.Root, EnvFilePath))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("agent.env: %v %v", fi, err)
	}
	return f.read(t, EnvFilePath)
}

func TestSetupCreatesTheToken(t *testing.T) {
	f := tokenHost(t, "\n", setupTokenOutput(60), nil)
	ready, err := f.Setup(Options{Agent: "claude"})
	if err != nil || !ready {
		t.Fatalf("ready %v, %v", ready, err)
	}
	if got := f.token(t); got != "CLAUDE_CODE_OAUTH_TOKEN="+testToken+"\n" {
		t.Fatalf("agent.env %q", got)
	}
	out := f.out.String()
	for _, l := range []string{"Create a token now with claude setup-token? It uses your Claude subscription (Pro or Max), not API billing. yes or no [yes]: ",
		"… Running claude setup-token. Sign in when it asks; setup saves the token it prints.\n<setup-token>",
		"✓ Saved the token ending in …" + testToken[len(testToken)-8:] + " to /etc/tripcoil/agent.env.\n"} {
		if !strings.Contains(out, l) {
			t.Errorf("output lacks %q:\n%s", l, out)
		}
	}
	if strings.Contains(out, testToken) || strings.Contains(out, "Next,") || strings.Contains(out, "Nothing changed") {
		t.Fatalf("output:\n%s", out)
	}

	f.out = bytes.Buffer{}
	f.SetupToken = func(string) ([]byte, error) { t.Fatal("a token exists"); return nil, nil }
	if ready, err := f.Setup(Options{}); err != nil || !ready || !strings.Contains(f.out.String(), "· /etc/tripcoil/agent.env has a token for Claude Code.\n") {
		t.Fatalf("ready %v, %v:\n%s", ready, err, f.out.String())
	}
}

func TestSetupKeepsTheEnvFilesOtherLines(t *testing.T) {
	f := tokenHost(t, "yes\n", setupTokenOutput(), nil)
	os.MkdirAll(filepath.Join(f.Root, "etc/tripcoil"), 0o755)
	os.WriteFile(filepath.Join(f.Root, EnvFilePath), []byte("# for Claude Code\nBASE=x\nexport CLAUDE_CODE_OAUTH_TOKEN=\nDEBUG=1"), 0o600)
	if _, err := f.Setup(Options{Agent: "claude"}); err != nil {
		t.Fatal(err)
	}
	if got := f.token(t); got != "# for Claude Code\nBASE=x\nCLAUDE_CODE_OAUTH_TOKEN="+testToken+"\nDEBUG=1\n" {
		t.Fatalf("agent.env %q", got)
	}
	if left, _ := filepath.Glob(filepath.Join(f.Root, "etc/tripcoil/.agent.env-*")); len(left) > 0 {
		t.Fatalf("left %q", left)
	}
}

func TestSetupSkipsTheToken(t *testing.T) {
	for _, c := range []struct {
		name  string
		o     Options
		term  bool
		input string
	}{
		{"--yes", Options{Agent: "claude", Yes: true}, true, ""},
		{"no terminal", Options{Agent: "claude"}, false, ""},
		{"no", Options{Agent: "claude"}, true, "no\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := tokenHost(t, c.input, "", nil)
			f.Terminal = func() bool { return c.term }
			f.SetupToken = func(string) ([]byte, error) { t.Fatal("setup-token must not run"); return nil, nil }
			ready, err := f.Setup(c.o)
			if err != nil || ready {
				t.Fatalf("ready %v, %v", ready, err)
			}
			if f.token(t) != "" || !strings.Contains(f.out.String(), "  1. Create a token with \"claude setup-token\"") {
				t.Fatalf("output:\n%s", f.out.String())
			}
		})
	}
}

func TestSetupAsksForTheToken(t *testing.T) {
	for _, c := range []struct {
		name, out string
		err       error
		said      string
	}{
		{"no token printed", "Error: sign-in was cancelled\r\n", nil, "! Setup found no token in what claude setup-token printed.\n"},
		{"setup-token failed", setupTokenOutput(), errors.New("exit status 1"), "! claude setup-token failed: exit status 1.\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := tokenHost(t, "\nsk-ant-short\n  "+testToken+"  \n", c.out, c.err)
			hidden := 0
			f.NoEcho = func() (func(), error) { hidden++; return func() { hidden-- }, nil }
			ready, err := f.Setup(Options{Agent: "claude"})
			if err != nil || !ready || hidden != 0 {
				t.Fatalf("ready %v, %v, hidden %d", ready, err, hidden)
			}
			if got := f.token(t); got != "CLAUDE_CODE_OAUTH_TOKEN="+testToken+"\n" {
				t.Fatalf("agent.env %q", got)
			}
			out := f.out.String()
			prompt := "Paste the token claude setup-token printed (input hidden, Enter skips): \n"
			if !strings.Contains(out, c.said+prompt+"! That does not look like a token from claude setup-token.\n"+prompt+"✓ Saved") {
				t.Fatalf("output:\n%s", out)
			}
		})
	}

	f := tokenHost(t, "\n\n", "nothing", nil)
	if ready, err := f.Setup(Options{Agent: "claude"}); err != nil || ready || f.token(t) != "" {
		t.Fatalf("an empty paste skips: %v %v", ready, err)
	}

	f = tokenHost(t, "\n\x1b[200~"+testToken+"\x1b[201~\n", "nothing", nil)
	if ready, err := f.Setup(Options{Agent: "claude"}); err != nil || !ready || f.token(t) != "CLAUDE_CODE_OAUTH_TOKEN="+testToken+"\n" {
		t.Fatalf("a bracketed paste: %v %v\n%s", ready, err, f.out.String())
	}
}

func TestSetupRefusesABrokenEnvFile(t *testing.T) {
	f := tokenHost(t, "\n", "", nil)
	f.SetupToken = func(string) ([]byte, error) { t.Fatal("setup-token must not run"); return nil, nil }
	os.MkdirAll(filepath.Join(f.Root, "etc/tripcoil"), 0o755)
	os.WriteFile(filepath.Join(f.Root, EnvFilePath), []byte("not a line\n"), 0o600)
	if ready, err := f.Setup(Options{Agent: "claude"}); err != nil || ready || !strings.Contains(f.out.String(), "! /etc/tripcoil/agent.env: line 1 is not KEY=value\n") {
		t.Fatalf("ready %v, %v\n%s", ready, err, f.out.String())
	}
	if f.read(t, EnvFilePath) != "not a line\n" {
		t.Fatal("agent.env changed")
	}
}

func TestSetupNamesARejectedCommand(t *testing.T) {
	f := tokenHost(t, "", "", nil)
	f.FindCLI = func(command, name string) (string, error) { return "", errors.New(command + " is not owned by root") }
	os.MkdirAll(filepath.Join(f.Root, "etc/tripcoil"), 0o755)
	os.WriteFile(filepath.Join(f.Root, EnvFilePath), []byte("CLAUDE_CODE_OAUTH_TOKEN=x\n"), 0o600)
	os.WriteFile(filepath.Join(f.Root, "etc/tripcoil/tripcoil.yaml"), []byte(strings.Replace(DefaultConfig("claude"), `command: ""`, "command: /opt/claude", 1)), 0o644)
	ready, err := f.Setup(Options{})
	out := f.out.String()
	if err != nil || ready || !strings.Contains(out, "! review.command: /opt/claude is not owned by root; correct it in /etc/tripcoil/tripcoil.yaml.\n") ||
		strings.Contains(out, "Install Claude Code") || !strings.HasSuffix(out, "\nThen check the host: tripcoil doctor\n") {
		t.Fatalf("ready %v, %v\n%s", ready, err, out)
	}
}

func TestWriteTokenFollowsALink(t *testing.T) {
	f := newFake(t, Systemd)
	dir := filepath.Join(f.Root, "etc/tripcoil")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "real.env"), []byte("BASE=x\n"), 0o600)
	os.Symlink("real.env", filepath.Join(dir, "agent.env"))
	if err := f.writeToken(EnvFilePath, claudeTokenKey, testToken); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "agent.env")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v %v", fi, err)
	}
	if got := f.read(t, "etc/tripcoil/real.env"); got != "BASE=x\nCLAUDE_CODE_OAUTH_TOKEN="+testToken+"\n" {
		t.Fatalf("real.env %q", got)
	}
}

func TestSetupReadiness(t *testing.T) {
	f := newFake(t, Systemd)
	if ready, err := f.Setup(Options{Agent: "none"}); err != nil || !ready || !strings.Contains(f.out.String(), "review.agent is none, so reports are audit-only.\n") ||
		strings.Contains(f.out.String(), "doctor") {
		t.Fatalf("none: %v %v\n%s", ready, err, f.out.String())
	}
	f = newFake(t, Systemd)
	os.MkdirAll(filepath.Join(f.Root, "etc/tripcoil"), 0o755)
	os.WriteFile(filepath.Join(f.Root, EnvFilePath), []byte("CODEX_API_KEY=k\n"), 0o600)
	if ready, err := f.Setup(Options{Agent: "codex"}); err != nil || ready || !strings.Contains(f.out.String(), "Next, install the agent CLI:\n  1. Install Codex") {
		t.Fatalf("codex missing: %v %v\n%s", ready, err, f.out.String())
	}
	f.tools["codex"] = true
	if ready, err := f.Setup(Options{}); err != nil || !ready {
		t.Fatalf("codex: %v %v", ready, err)
	}
}

// TestPTYChild is the child of the runInPTY tests: it prints the token and the line it reads,
// or its window size.
func TestPTYChild(t *testing.T) {
	switch os.Getenv("TRIPCOIL_PTY_CHILD") {
	case "read":
		fmt.Print(setupTokenOutput(50))
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Printf("got %s", line)
	case "size":
		ws, err := unix.IoctlGetWinsize(1, unix.TIOCGWINSZ)
		fmt.Printf("size %dx%d %v\n", ws.Row, ws.Col, err)
	default:
		t.Skip("the child of the runInPTY tests")
	}
	os.Exit(0)
}

func ptyChild(mode string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestPTYChild$")
	cmd.Env = append(os.Environ(), "TRIPCOIL_PTY_CHILD="+mode)
	return cmd
}

func TestRunInPTYOnATerminal(t *testing.T) {
	tm, _, ts, err := openPTY()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	defer ts.Close()
	fd := int(ts.Fd())
	unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 33, Col: 111})
	before, _ := unix.IoctlGetTermios(fd, unix.TCGETS)
	var out bytes.Buffer
	if _, err := runInPTY(ts, &out, ptyChild("size")); err != nil {
		t.Fatalf("%v:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "size 33x111 <nil>") || !strings.HasSuffix(out.String(), "\x1b[?2004l\x1b[?25h") {
		t.Fatalf("printed %q", out.String())
	}
	if after, _ := unix.IoctlGetTermios(fd, unix.TCGETS); *after != *before || after.Lflag&unix.ICANON == 0 {
		t.Fatal("the terminal was not restored")
	}
}

func TestRunInPTYDoesNotWaitForWhatTheChildLeft(t *testing.T) {
	cmd := exec.Command("sh", "-c", `(trap "" HUP; setsid sh -c "trap \"\" HUP; sleep 4; echo late") & echo hi`)
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	var out bytes.Buffer
	start := time.Now()
	if _, err := runInPTY(r, &out, cmd); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2500*time.Millisecond || !strings.Contains(out.String(), "hi") || strings.Contains(out.String(), "late") {
		t.Fatalf("%v, printed %q", d, out.String())
	}
}

func TestRunInPTY(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() { fmt.Fprint(w, "hello\n"); w.Close() }()
	var out bytes.Buffer
	captured, err := runInPTY(r, &out, ptyChild("read"))
	if err != nil {
		t.Fatalf("%v:\n%s", err, out.String())
	}
	if !bytes.Equal(captured, out.Bytes()) || !strings.Contains(out.String(), "got hello\r\n") {
		t.Fatalf("captured %q\nprinted %q", captured, out.String())
	}
	if tok, ok := extractToken(captured); !ok || tok != testToken {
		t.Fatalf("token %q", tok)
	}
}
