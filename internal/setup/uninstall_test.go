package setup

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// installed is a fake host that setup has set up, with userdel and nft, and a state folder.
func installed(t *testing.T, m Manager) (*fakeHost, UninstallOptions) {
	t.Helper()
	f := newFake(t, m)
	f.tools["nft"] = true
	if f.tools["useradd"] {
		f.tools["userdel"] = true
	}
	if _, err := f.Setup(Options{Agent: "none", Yes: true}); err != nil {
		t.Fatal(err)
	}
	f.started()
	f.replies["rc-update show default"] = " tripcoil | default\n"
	run := f.Host.Run
	f.Host.Run = func(name string, args ...string) ([]byte, error) {
		out, err := run(name, args...)
		if err == nil {
			switch name {
			case "userdel", "deluser":
				f.users["user"] = false
			case "groupdel", "delgroup":
				f.users["group"] = false
			case "rc-update":
				if len(args) > 0 && args[0] == "del" {
					f.replies["rc-update show default"] = ""
				}
			}
		}
		return out, err
	}
	o := UninstallOptions{Yes: true, StateDir: "/var/lib/tripcoil"}
	os.MkdirAll(filepath.Join(f.Root, "var/lib/tripcoil/runs"), 0o755)
	os.MkdirAll(filepath.Join(f.Root, "usr/local/bin"), 0o755)
	os.WriteFile(filepath.Join(f.Root, "usr/local/bin/tripcoil"), nil, 0o755)
	f.cmds = nil
	f.out.Reset()
	return f, o
}

func (f *fakeHost) gone(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(filepath.Join(f.Root, p)); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
}

func TestUninstallSystemdTwice(t *testing.T) {
	f, o := installed(t, Systemd)
	f.Sudo = "sudo "
	if err := f.Uninstall(o); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	want := []string{"systemctl disable --now tripcoil.service", "systemctl stop tripcoil-review-*", "systemctl daemon-reload",
		"nft delete table inet tripcoil", "userdel tripcoil-agent"}
	if !slices.Equal(f.cmds, want) {
		t.Errorf("commands %q, want %q", f.cmds, want)
	}
	f.gone(t, UnitPath, "/etc/tripcoil", "/var/lib/tripcoil", "/usr/local/bin/tripcoil")
	out := f.out.String()
	for _, s := range []string{"✓ Stopped and removed the tripcoil service.\n", "✓ Removed /etc/tripcoil.\n", "✓ Removed /var/lib/tripcoil.\n",
		"✓ Removed the user and group tripcoil-agent.\n", "✓ Removed /usr/local/bin/tripcoil.\n", "· Setup added no NodeSource repository.\n",
		"remove Claude Code with: sudo npm uninstall -g @anthropic-ai/claude-code\n"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}

	f.cmds = nil
	f.out.Reset()
	f.replies["systemctl disable --now tripcoil.service"] = "Failed to disable unit: Unit tripcoil.service does not exist\n"
	f.replies["nft delete table inet tripcoil"] = "Error: Could not process rule: No such file or directory\n"
	f.fail["systemctl disable"], f.fail["systemctl stop"], f.fail["nft delete"] = true, true, true
	if err := f.Uninstall(o); err != nil {
		t.Fatalf("second run: %v\n%s", err, f.out.String())
	}
	if out := f.out.String(); strings.Contains(out, "✓") || strings.Contains(out, "!") || strings.Count(out, "· ") != 7 {
		t.Errorf("second run:\n%s", out)
	}
}

func TestUninstallOpenRC(t *testing.T) {
	f, o := installed(t, OpenRC)
	os.MkdirAll(filepath.Join(f.Root, "var/log"), 0o755)
	os.WriteFile(filepath.Join(f.Root, logPath), nil, 0o644)
	if err := f.Uninstall(o); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	want := []string{"rc-update show default", "rc-service tripcoil stop", "rc-update del tripcoil default",
		"nft delete table inet tripcoil", "deluser tripcoil-agent", "delgroup tripcoil-agent"}
	if !slices.Equal(f.cmds, want) {
		t.Errorf("commands %q, want %q", f.cmds, want)
	}
	f.gone(t, InitScriptPath, ConfDPath, logPath, "/etc/tripcoil", "/var/lib/tripcoil", "/usr/local/bin/tripcoil")
	if out := f.out.String(); !strings.Contains(out, "✓ Stopped and removed the tripcoil service.\n") ||
		!strings.Contains(out, "with: npm uninstall -g @anthropic-ai/claude-code\n") {
		t.Errorf("output:\n%s", out)
	}

	f.cmds = nil
	f.out.Reset()
	f.replies["nft delete table inet tripcoil"] = "Error: Could not process rule: No such file or directory\n"
	f.fail["nft delete"] = true
	if err := f.Uninstall(o); err != nil || !slices.Equal(f.cmds, []string{"rc-update show default", "nft delete table inet tripcoil"}) ||
		strings.Contains(f.out.String(), "✓") {
		t.Errorf("second run: %v, commands %q\n%s", err, f.cmds, f.out.String())
	}
}

func TestUninstallWithoutAService(t *testing.T) {
	f := newFake(t, "")
	o := UninstallOptions{Yes: true, StateDir: "/var/lib/tripcoil"}
	if err := f.Uninstall(o); err != nil || len(f.cmds) != 0 ||
		!strings.Contains(f.out.String(), "· Neither systemd nor OpenRC runs this host") || !strings.Contains(f.out.String(), "· nft is not installed") {
		t.Errorf("%v, commands %q\n%s", err, f.cmds, f.out.String())
	}
}

func TestUninstallNodeSource(t *testing.T) {
	f, o := installed(t, Systemd)
	write := func(p, data string) {
		os.MkdirAll(filepath.Dir(filepath.Join(f.Root, p)), 0o755)
		os.WriteFile(filepath.Join(f.Root, p), []byte(data), 0o644)
	}
	write(NodeSourceKeyPath, armoredKey+"\n")
	write(NodeSourceKeyMarkPath, AddedMarker+"\n")
	write(NodeSourceSourcesPath, AddedMarker+"\nTypes: deb\n")
	write(NodeSourcePinPath, AddedMarker+"\nPackage: nodejs\n")
	write(NodeSourceRepoPath, "[nodesource-nodejs]\n")
	o.Yes = false
	f.In = strings.NewReader("yes\n")
	if err := f.Uninstall(o); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	f.gone(t, NodeSourceKeyPath, NodeSourceKeyMarkPath, NodeSourceSourcesPath, NodeSourcePinPath)
	if f.read(t, NodeSourceRepoPath) != "[nodesource-nodejs]\n" {
		t.Error("the host's own repository file changed")
	}
	out := f.out.String()
	for _, s := range []string{"the user tripcoil-agent, NodeSource's repository and /usr/local/bin/tripcoil? yes or no [no]: ",
		"✓ Removed NodeSource's repository: " + NodeSourceSourcesPath + ", " + NodeSourceKeyMarkPath + ", " + NodeSourceKeyPath + ", " + NodeSourcePinPath + ".\n",
		"· " + NodeSourceRepoPath + " is the host's own; it stays.\n"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
	if slices.Contains(f.cmds, "apt-get update") {
		t.Error("ran apt-get update")
	}

	// The host's own sources file keeps its key.
	f, o = installed(t, Systemd)
	write(NodeSourceKeyPath, armoredKey+"\n")
	write(NodeSourceSourcesPath, "Types: deb\n")
	write(NodeSourcePinPath, AddedMarker+"\nPackage: nodejs\n")
	if err := f.Uninstall(o); err != nil {
		t.Fatal(err)
	}
	f.gone(t, NodeSourcePinPath)
	f.read(t, NodeSourceKeyPath)
	f.read(t, NodeSourceSourcesPath)

	// A key that was there before setup wrote its sources file has no mark, and stays.
	f, o = installed(t, Systemd)
	write(NodeSourceKeyPath, armoredKey+"\n")
	write(NodeSourceSourcesPath, AddedMarker+"\nTypes: deb\n")
	if err := f.Uninstall(o); err != nil {
		t.Fatal(err)
	}
	f.gone(t, NodeSourceSourcesPath)
	f.read(t, NodeSourceKeyPath)
}

func TestUninstallAnsweredNo(t *testing.T) {
	f, o := installed(t, Systemd)
	o.Yes = false
	for _, in := range []string{"no\n", "\n"} {
		f.In = strings.NewReader(in)
		f.out.Reset()
		if err := f.Uninstall(o); err != nil || len(f.cmds) != 0 || !strings.HasSuffix(f.out.String(), "[no]: Nothing removed.\n") ||
			strings.Contains(f.out.String(), "NodeSource") {
			t.Errorf("%q: %v, commands %q\n%s", in, err, f.cmds, f.out.String())
		}
	}
	f.read(t, UnitPath)
	f.read(t, "/usr/local/bin/tripcoil")
	f.In = strings.NewReader("")
	if err := f.Uninstall(o); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("no answer: %v", err)
	}
}

func TestUninstallKeepsGoingAfterAFailure(t *testing.T) {
	f, o := installed(t, Systemd)
	f.replies["systemctl disable --now tripcoil.service"] = "Failed to connect to bus\n"
	f.fail["systemctl disable"] = true
	err := f.Uninstall(o)
	if err == nil || !strings.Contains(err.Error(), "some steps failed") {
		t.Fatalf("err %v", err)
	}
	if !strings.Contains(f.out.String(), "! systemctl disable --now tripcoil.service: exit status 3: Failed to connect to bus\n") {
		t.Errorf("output:\n%s", f.out.String())
	}
	f.read(t, UnitPath)
	f.gone(t, "/etc/tripcoil", "/var/lib/tripcoil", "/usr/local/bin/tripcoil")
	if !slices.Contains(f.cmds, "userdel tripcoil-agent") {
		t.Errorf("commands %q", f.cmds)
	}
}
