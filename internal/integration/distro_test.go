//go:build integration

// Package integration runs Tripcoil against real distributions and the real host.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// split separates inventory.json from audit.json in a container's output. The script prints it
// from "@@@$((6*7))@@@", so its own command line, which the Inventory lists, does not hold it.
const split = "@@@42@@@"

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tripcoil")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/klar-web-services/tripcoil/cmd/tripcoil")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// isSleep600 matches exactly "sleep 600". Rocky's multicall coreutils shows it as
// "/usr/bin/coreutils --coreutils-prog-shebang=sleep /usr/bin/sleep 600".
func isSleep600(cmdline []string) bool {
	if len(cmdline) == 4 {
		if filepath.Base(cmdline[0]) != "coreutils" || cmdline[1] != "--coreutils-prog-shebang=sleep" {
			return false
		}
		cmdline = cmdline[2:]
	}
	return len(cmdline) == 2 && filepath.Base(cmdline[0]) == "sleep" && cmdline[1] == "600"
}

func TestDistros(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	bin := buildBinary(t)
	cache := preparedCache(t)
	cases := []struct{ image, family, pkgType, sleepExe, sleepPkg, libc string }{
		{"debian:12", "debian", "deb", "/usr/bin/sleep", "coreutils", "libc6"},
		{"debian:13", "debian", "deb", "/usr/bin/sleep", "coreutils", "libc6"},
		{"ubuntu:24.04", "ubuntu", "deb", "/usr/bin/sleep", "coreutils", "libc6"},
		// Rocky's coreutils-single is one multicall binary: sleep runs as /usr/bin/coreutils.
		{"rockylinux/rockylinux:9", "rhel", "rpm", "/usr/bin/coreutils", "coreutils", "glibc"},
		{"alpine:3.21", "alpine", "apk", "/bin/busybox", "busybox", "musl"},
		{"archlinux:latest", "arch", "alpm", "/usr/bin/sleep", "coreutils", "glibc"},
	}
	for _, tc := range cases {
		t.Run(tc.image, func(t *testing.T) {
			// The cache is shared with the host (the pinned Grype, its database and the kernel CNA
			// data); what the run adds to it is given back to the host's user.
			script := "sleep 600 & sleep 1; /usr/local/bin/tripcoil run >/tmp/run.out 2>&1; code=$?; " +
				"chown -R " + fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()) + " /var/lib/tripcoil/cache; " +
				"cat /var/lib/tripcoil/runs/latest/inventory.json || cat /tmp/run.out; echo; echo @@@$((6*7))@@@; " +
				"cat /var/lib/tripcoil/runs/latest/audit.json; exit $code"
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-v", bin+":/usr/local/bin/tripcoil:ro",
				"-v", cache+":/var/lib/tripcoil/cache", tc.image, "sh", "-c", script)
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			invOut, audOut, _ := bytes.Cut(stdout.Bytes(), []byte(split))
			var inv inventory.Inventory
			if err := json.Unmarshal(invOut, &inv); err != nil {
				t.Fatalf("no inventory.json (run: %v): %v\nstdout: %s\nstderr: %s", runErr, err, stdout.Bytes(), stderr.Bytes())
			}
			var aud audit.Audit
			if err := json.Unmarshal(audOut, &aud); err != nil {
				t.Fatalf("no audit.json (run: %v): %v\nstdout: %s", runErr, err, audOut)
			}
			if runErr != nil {
				t.Fatalf("tripcoil run failed: %v; errors %+v %+v\nstderr: %s", runErr, inv.Errors, aud.Errors, stderr.Bytes())
			}
			if len(inv.Items) == 0 || inv.Items[0].Kind != inventory.KindKernel || inv.Items[0].Release == "" {
				t.Fatalf("first item is not a kernel item with a release: %+v", inv.Items)
			}
			if inv.Host.Distro.Family != tc.family {
				t.Fatalf("family %q, want %q", inv.Host.Distro.Family, tc.family)
			}
			origins := map[string]inventory.Origin{}
			for _, o := range inv.Origins {
				origins[o.ID] = o
			}
			var sleep *inventory.Item
			for i := range inv.Items {
				it := &inv.Items[i]
				for _, p := range it.Processes {
					if it.Exe == tc.sleepExe && isSleep600(p.Cmdline) {
						sleep = it
					}
				}
			}
			if sleep == nil {
				t.Fatalf("no item runs sleep from %s: %+v", tc.sleepExe, inv.Items)
			}
			var sleepPkg, libc bool
			for _, id := range sleep.Origins {
				o := origins[id]
				if o.Kind != inventory.OriginPackage || o.Type != tc.pkgType {
					continue
				}
				sleepPkg = sleepPkg || o.Name == tc.sleepPkg || o.Name == tc.sleepPkg+"-single"
				libc = libc || o.Name == tc.libc
			}
			if !sleepPkg || !libc {
				t.Fatalf("sleep's origins miss %s or %s: %v", tc.sleepPkg, tc.libc, sleep.Origins)
			}
			// The Audit read this distribution's package database: each of sleep's packages is
			// one package of the staged database.
			results := map[string]audit.OriginResult{}
			for _, r := range aud.Origins {
				results[r.ID] = r
			}
			for _, id := range sleep.Origins {
				if r := results[id]; origins[id].Kind == inventory.OriginPackage && (r.Status != audit.Scanned || r.Packages != 1) {
					t.Errorf("origin %s: %+v", id, r)
				}
			}
			if aud.Status != audit.Complete || aud.Grype.DBBuilt.IsZero() || aud.KernelData == nil {
				t.Fatalf("audit %s, errors %+v", aud.Status, aud.Errors)
			}
			self := false
			for _, it := range inv.Items {
				for _, id := range it.Origins {
					if it.Exe == "/usr/local/bin/tripcoil" && origins[id].Kind == inventory.OriginBinary {
						self = true
						if r := results[id]; r.Status != audit.Scanned || r.Packages == 0 {
							t.Errorf("tripcoil's own binary: %+v", r) // Grype reads a Go binary's modules
						}
					}
				}
			}
			if !self {
				t.Fatal("tripcoil itself must show up as an unpackaged binary")
			}
		})
	}
}
