//go:build installsmoke

package setup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var smokeImages = []string{"debian:12", "ubuntu:24.04", "fedora:latest", "rockylinux:9", "alpine:3.21", "archlinux:latest"}

var smokePrep = map[string]string{
	"archlinux:latest": "pacman -Syu --noconfirm",
}

func TestInstallSmokeContainers(t *testing.T) {
	if os.Getenv("TRIPCOIL_SMOKE_INNER") != "" {
		t.Skip("inside a container")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	bin := filepath.Join(t.TempDir(), "smoke")
	build := exec.Command("go", "test", "-c", "-tags", "installsmoke", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the test binary: %v\n%s", err, out)
	}
	images := smokeImages
	if s := os.Getenv("TRIPCOIL_SMOKE_IMAGES"); s != "" {
		images = strings.Fields(s)
	}
	slots := make(chan struct{}, 3)
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			slots <- struct{}{}
			defer func() { <-slots }()
			name := fmt.Sprintf("tripcoil-smoke-%d-%s", os.Getpid(), strings.NewReplacer(":", "-", "/", "-").Replace(image))
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			defer exec.Command("docker", "rm", "-f", name).Run()
			start := time.Now()
			script := "exec /smoke -test.run '^TestInstallSmoke$' -test.v -test.timeout 15m"
			if prep := smokePrep[image]; prep != "" {
				script = prep + " >/dev/null && " + script
			}
			out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--name", name, "-v", bin+":/smoke:ro",
				"-e", "TRIPCOIL_SMOKE_INNER=1", image, "sh", "-c", script).CombinedOutput()
			t.Logf("%s in %s:\n%s", image, time.Since(start).Round(time.Second), out)
			if err != nil {
				t.Fatalf("%s: %v", image, err)
			}
		})
	}
}

func TestInstallSmoke(t *testing.T) {
	if os.Getenv("TRIPCOIL_SMOKE_INNER") == "" || os.Geteuid() != 0 {
		t.Skip("runs only as root in a container; see TestInstallSmokeContainers")
	}
	h := NewHost(os.Args[0], strings.NewReader(""), os.Stdout)
	var cmds []string
	run := h.Run
	h.Run = func(name string, args ...string) ([]byte, error) {
		cmds = append(cmds, strings.Join(append([]string{name}, args...), " "))
		return run(name, args...)
	}

	did, installed, err := h.claudeCode(Options{Yes: true})
	if err != nil || !did || !installed {
		t.Fatalf("install: did %v, installed %v, %v", did, installed, err)
	}
	claude, err := h.FindCLI("", "claude")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(claude, "--version").CombinedOutput()
	if err != nil || !strings.ContainsAny(string(out), "0123456789") {
		t.Fatalf("%s --version: %v: %s", claude, err, out)
	}
	t.Logf("claude --version: %s", strings.TrimSpace(string(out)))
	if v := h.nodeVersion(); nodeMajor(v) < 22 {
		t.Fatalf("node --version is %q", v)
	}

	cmds = nil
	did, installed, err = h.claudeCode(Options{Yes: true})
	if err != nil || did || !installed || len(cmds) > 0 {
		t.Fatalf("second install: did %v, installed %v, %v, commands %q", did, installed, err, cmds)
	}

	marked := h.markedNodeSource()
	var hosts []string
	for _, p := range NodeSourceFiles {
		if !h.exists(p) && p != NodeSourceKeyMarkPath {
			if err := h.writeFile(p, []byte("host's own\n")); err != nil {
				t.Fatal(err)
			}
			hosts = append(hosts, p)
		}
	}
	removed, err := h.removeNodeSource()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("marked %q, removed %q", marked, removed)
	for _, p := range marked {
		if h.exists(p) {
			t.Errorf("%s is still there", p)
		}
	}
	if slices.Contains(marked, NodeSourceKeyMarkPath) && h.exists(NodeSourceKeyPath) {
		t.Errorf("%s stayed with setup's mark gone", NodeSourceKeyPath)
	}
	for _, p := range hosts {
		if !h.exists(p) {
			t.Errorf("the host's own %s was removed", p)
		}
	}
}
