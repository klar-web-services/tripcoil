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
	"slices"
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

// isSleep600 matches the script's "/bin/sleep 600". Rocky's multicall coreutils shows it as
// "/usr/bin/coreutils --coreutils-prog-shebang=sleep /bin/sleep 600".
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
	// The old point releases hold a libc with a long-known vulnerability, cve, fixed in version
	// fix: the Audit matches the distribution's packages with the distribution's data.
	cases := []struct{ image, family, pkgType, sleepExe, sleepPkg, libc, cve, fix string }{
		{"debian:12", "debian", "deb", "/usr/bin/sleep", "coreutils", "libc6", "", ""},
		{"debian:12.0", "debian", "deb", "/usr/bin/sleep", "coreutils", "libc6", "CVE-2023-4911", "2.36-9+deb12u3"},
		{"debian:13", "debian", "deb", "/usr/bin/sleep", "coreutils", "libc6", "", ""},
		{"ubuntu:24.04", "ubuntu", "deb", "/usr/bin/sleep", "coreutils", "libc6", "", ""},
		{"ubuntu:jammy-20230126", "ubuntu", "deb", "/usr/bin/sleep", "coreutils", "libc6", "CVE-2023-4911", "2.35-0ubuntu3.4"},
		// Rocky's coreutils-single is one multicall binary: sleep runs as /usr/bin/coreutils.
		{"rockylinux/rockylinux:9", "rhel", "rpm", "/usr/bin/coreutils", "coreutils", "glibc", "", ""},
		{"rockylinux/rockylinux:9.0", "rhel", "rpm", "/usr/bin/coreutils", "coreutils", "glibc", "CVE-2023-4911", "0:2.34-60.el9_2.7"},
		{"alpine:3.21", "alpine", "apk", "/bin/busybox", "busybox", "musl", "", ""},
		{"alpine:3.18.0", "alpine", "apk", "/bin/busybox", "busybox", "musl", "CVE-2025-26519", "1.2.4-r3"},
		{"archlinux:latest", "arch", "alpm", "/usr/bin/sleep", "coreutils", "glibc", "", ""},
		// Arch Linux's data names the group AVG-1621, with CVE-2021-33574 among its aliases.
		{"archlinux:base-20211121.0.39613", "arch", "alpm", "/usr/bin/sleep", "coreutils", "glibc", "CVE-2021-33574", "2.34-1"},
	}
	for i, tc := range cases {
		t.Run(tc.image, func(t *testing.T) {
			// The cache is shared with the host (the pinned Grype, its database and the kernel CNA
			// data). The container is removed however the test ends, before what the run added to
			// the cache is given to the cache's owner.
			name := fmt.Sprintf("tripcoil-it-%d-%d", os.Getpid(), i)
			t.Cleanup(func() {
				if out, err := exec.Command("docker", "rm", "-f", name).CombinedOutput(); err != nil {
					t.Errorf("docker rm: %v\n%s", err, out)
				}
				chown := `chown -R "$(stat -c %u:%g /var/lib/tripcoil/cache)" /var/lib/tripcoil/cache`
				if out, err := exec.Command("docker", "run", "--rm", "-v", cache+":/var/lib/tripcoil/cache", tc.image,
					"sh", "-c", chown).CombinedOutput(); err != nil {
					t.Errorf("give the cache back: %v\n%s", err, out)
				}
			})
			// Alpine 3.18's busybox runs a plain "sleep" in a fork of the shell, under the shell's
			// command line; one with a path it executes.
			script := "/bin/sleep 600 & sleep 1; /usr/local/bin/tripcoil run >/tmp/run.out 2>&1; code=$?; cat /tmp/run.out >&2; " +
				"cat /var/lib/tripcoil/runs/latest/inventory.json; echo; echo @@@$((6*7))@@@; " +
				"cat /var/lib/tripcoil/runs/latest/audit.json; exit $code"
			ctx, cancel := context.WithTimeout(interrupt, 5*time.Minute)
			defer cancel()
			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--name", name, "-v", bin+":/usr/local/bin/tripcoil:ro",
				"-v", cache+":/var/lib/tripcoil/cache", tc.image, "sh", "-c", script)
			// Killing the docker client would leave the container running.
			cmd.Cancel = func() error { return exec.Command("docker", "rm", "-f", name).Run() }
			cmd.WaitDelay = time.Minute
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			invOut, audOut, _ := bytes.Cut(stdout.Bytes(), []byte(split))
			var inv inventory.Inventory
			if err := json.Unmarshal(invOut, &inv); err != nil {
				t.Fatalf("no inventory.json (run: %v): %v\nstdout: %s\nstderr: %s", runErr, err, stdout.Bytes(), stderr.Bytes())
			}
			var aud audit.Audit
			if err := json.Unmarshal(audOut, &aud); err != nil {
				t.Fatalf("no audit.json (run: %v): %v\nstdout: %s\nstderr: %s", runErr, err, audOut, stderr.Bytes())
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
			var sleepPkg bool
			var libc string
			for _, id := range sleep.Origins {
				o := origins[id]
				if o.Kind != inventory.OriginPackage || o.Type != tc.pkgType {
					continue
				}
				sleepPkg = sleepPkg || o.Name == tc.sleepPkg || o.Name == tc.sleepPkg+"-single"
				if o.Name == tc.libc {
					libc = id
				}
			}
			if !sleepPkg || libc == "" {
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
			if tc.cve != "" {
				matched := false
				var libcFindings []string
				for _, f := range aud.Findings {
					if f.Origin != libc {
						continue
					}
					v := f.Vulnerability
					matched = matched || (v.ID == tc.cve || slices.Contains(v.Aliases, tc.cve)) && slices.Contains(f.Fix.Versions, tc.fix)
					libcFindings = append(libcFindings, fmt.Sprintf("%s%v %s %v", v.ID, v.Aliases, f.Package.Version, f.Fix.Versions))
				}
				if !matched {
					t.Errorf("no finding of %s fixed in %s on %s; its findings: %v", tc.cve, tc.fix, libc, libcFindings)
				}
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
