package report

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/run"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const (
	libssl = "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12"
	kernel = "pkg:deb/debian/linux-image-6.1.0-28-amd64@6.1.119-1?arch=amd64&distro=debian-12"
	shop   = "appdir:/srv/shop"
	img    = "image:sha256:1111"
	api    = "binary:9f2c"
	snap   = "unresolved:5e1f"
)

var started = time.Date(2026, 11, 14, 6, 15, 0, 0, time.UTC)

func record(stages map[string]string, errs ...problem.Problem) *run.Record {
	r := run.NewRecord("20261114T061500Z-3fa2", started, "manual", map[string]string{"tripcoil": "dev"})
	for k, v := range stages {
		r.Stages[k] = v
	}
	r.Add(errs...)
	r.Finish(started.Add(3 * time.Minute))
	return r
}

func hostInventory() *inventory.Inventory {
	yes := true
	return &inventory.Inventory{
		Host: inventory.Host{Hostname: "web-1", Distro: inventory.Distro{ID: "debian", VersionID: "12"}},
		Items: []inventory.Item{
			{ID: "kernel", Kind: inventory.KindKernel, Name: "kernel", Release: "6.1.0-28-amd64", RebootPending: &yes,
				RebootReasons: []string{"a newer kernel package is installed: linux-image-6.1.0-31-amd64 6.1.128-1"}, Origins: []string{kernel}},
			{ID: "proc:nginx", Kind: inventory.KindProcess, Name: "nginx", Units: []string{"nginx.service"},
				RestartNeeded: []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"}, Origins: []string{libssl}},
			{ID: "proc:shop", Kind: inventory.KindProcess, Name: "node", Exe: "/usr/bin/node", Units: []string{"shop.service"}, Origins: []string{libssl, shop}},
			{ID: "proc:worker", Kind: inventory.KindProcess, Name: "python3.11", Exe: "/usr/bin/python3.11", Notes: []string{problem.AppDirNotFound}, Origins: []string{libssl}},
			{ID: "proc:api", Kind: inventory.KindProcess, Name: "api", Exe: "/opt/api/api", Origins: []string{api}},
			{ID: "proc:lxd", Kind: inventory.KindProcess, Name: "lxd", Exe: "/snap/lxd/123/bin/lxd", Origins: []string{snap}},
			{ID: "container:shop-web-1", Kind: inventory.KindContainer, Name: "shop-web-1", Notes: []string{problem.ImageOnly}, Origins: []string{img}},
		},
		Origins: []inventory.Origin{
			{ID: kernel, Kind: inventory.OriginPackage, Name: "linux-image-6.1.0-28-amd64", Version: "6.1.119-1"},
			{ID: libssl, Kind: inventory.OriginPackage, Name: "libssl3", Version: "3.0.15-1~deb12u1"},
			{ID: shop, Kind: inventory.OriginAppDir, Path: "/srv/shop"},
			{ID: api, Kind: inventory.OriginBinary, Paths: []string{"/opt/api/api"}},
			{ID: snap, Kind: inventory.OriginUnresolved, Reason: "it runs from a snap, and snaps are not audited in v1", Paths: []string{"/snap/lxd/123/bin/lxd"}},
			{ID: img, Kind: inventory.OriginImage, ImageID: "sha256:1111", Ref: "ghcr.io/acme/shop:2026.11.3"},
		},
	}
}

func hostAudit() *audit.Audit {
	f := func(id, origin, vuln, sev string, epss float64, kev bool, risk, pkg, version, remediation string, items ...string) audit.Finding {
		return audit.Finding{ID: id, Origin: origin, Risk: risk, Items: items, Remediation: remediation, Source: "debian:distro:debian:12",
			Package:       audit.Package{Name: pkg, Version: version, Type: "deb"},
			Vulnerability: audit.Vulnerability{ID: vuln, Severity: sev, EPSS: epss, KnownExploited: kev, URLs: []string{"https://security-tracker.debian.org/tracker/" + vuln}}}
	}
	return &audit.Audit{
		SchemaVersion: "1", Status: audit.Complete,
		Grype:      audit.GrypeInfo{Version: "0.121.2", DBBuilt: time.Date(2026, 11, 14, 3, 12, 0, 0, time.UTC)},
		KernelData: nil,
		Origins: []audit.OriginResult{
			{ID: kernel, Kind: inventory.OriginPackage, Status: audit.Scanned},
			{ID: libssl, Kind: inventory.OriginPackage, Status: audit.Scanned},
			{ID: shop, Kind: inventory.OriginAppDir, Status: audit.Scanned, Packages: 120},
			{ID: api, Kind: inventory.OriginBinary, Status: audit.Unidentified},
			{ID: snap, Kind: inventory.OriginUnresolved, Status: audit.Unresolved, Reason: "it runs from a snap, and snaps are not audited in v1"},
			{ID: img, Kind: inventory.OriginImage, Status: audit.Scanned, Packages: 98},
		},
		Findings: []audit.Finding{
			f("f:0000000000000001", libssl, "CVE-2026-1234", "High", 0.41, false, audit.RiskHigh, "libssl3", "3.0.15-1~deb12u1",
				"Upgrade libssl3 to 3.0.16-1~deb12u1 (apt-get install --only-upgrade libssl3), then restart nginx.service, shop.service, python3.11.", "proc:nginx", "proc:shop", "proc:worker"),
			f("f:0000000000000002", kernel, "CVE-2026-2000", "High", 0, true, audit.RiskCritical, "linux-image-6.1.0-28-amd64", "6.1.119-1",
				"Upgrade the kernel to 6.1.123-1 or later (apt-get dist-upgrade), then reboot.", "kernel"),
			f("f:0000000000000003", shop, "GHSA-35jh-r3h4-6jhm", "High", 0.002, false, audit.RiskMedium, "lodash", "4.17.20",
				"Upgrade lodash in /srv/shop to 4.17.21, then restart shop.service.", "proc:shop"),
			f("f:0000000000000004", img, "CVE-2026-3000", "Low", 0, false, audit.RiskLow, "zlib1g", "1:1.2.13.dfsg-1",
				"No fix is known for zlib1g 1:1.2.13.dfsg-1 yet.", "container:shop-web-1"),
		},
		Upgrades: []audit.Upgrade{{Origin: shop, Path: "/srv/shop", Package: "lodash", Type: "npm", Version: "4.18.0", Findings: 4}},
		Errors:   []problem.Problem{}, Warnings: []problem.Problem{},
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".md")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s differs from the golden file (run with -update to rewrite it):\n%s", name, got)
	}
}

func TestRenderAuditOnly(t *testing.T) {
	r := record(map[string]string{"inventory": run.StageOK, "audit": run.StageOK})
	golden(t, "audit-only", Render(Input{Run: r, Inventory: hostInventory(), Audit: hostAudit(), NoReview: "the AI review is not part of this build"}))
}

func TestRenderPartial(t *testing.T) {
	aud := hostAudit()
	aud.Status = audit.Partial
	aud.Origins[5] = audit.OriginResult{ID: img, Kind: inventory.OriginImage, Status: audit.ScanFailed, Error: "Grype failed: no such image"}
	aud.Findings = aud.Findings[:3]
	aud.KernelData = &audit.KernelData{Commit: "84a53c896276bc79eb2c0b9864fc2a53afe270b8", Checked: time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC)}
	r := record(map[string]string{"inventory": run.StagePartial, "audit": run.StagePartial},
		problem.New(problem.Error, problem.DockerUnavailable, "inventory", "the Docker socket did not answer"),
		problem.New(problem.Error, problem.OriginScanFailed, "audit", "image ghcr.io/acme/shop:2026.11.3: Grype failed: no such image"))
	golden(t, "partial", Render(Input{Run: r, Inventory: hostInventory(), Audit: aud, NoReview: "the AI review is not part of this build"}))
}

func TestRenderAuditFailed(t *testing.T) {
	aud := &audit.Audit{SchemaVersion: "1", Status: audit.Failed, Grype: audit.GrypeInfo{Version: "0.121.2", DBBuilt: started.Add(-73 * time.Hour)},
		Origins: []audit.OriginResult{{ID: libssl, Kind: inventory.OriginPackage, Status: audit.ScanFailed, Error: "the vulnerability database was built 73 hours ago"}}}
	r := record(map[string]string{"inventory": run.StageOK, "audit": run.StageFailed},
		problem.New(problem.Error, problem.DBStale, "audit", "the vulnerability database was built 73 hours ago, which is older than audit.maxDatabaseAgeHours (48)"))
	got := Render(Input{Run: r, Inventory: hostInventory(), Audit: aud, NoReview: "the AI review is not part of this build"})
	golden(t, "audit-failed", got)
	if strings.Contains(got, "No exploitable") || strings.Contains(got, "0 critical") || strings.Contains(got, "Not audited") {
		t.Fatal("a failed audit must never read as no findings")
	}
}

func TestRenderInterruptedWithoutInventory(t *testing.T) {
	r := run.NewRecord("20261114T061500Z-3fa2", started, "manual", map[string]string{"tripcoil": "dev"})
	r.Interrupt(started.Add(time.Minute), "inventory")
	golden(t, "interrupted", Render(Input{Run: r, NoReview: "the AI review is not part of this build"}))
}

func TestRenderEscapesUntrustedText(t *testing.T) {
	inv := hostInventory()
	aud := hostAudit()
	aud.Findings[0].Package.Name = "evil|*pkg*\x1b[31m<script>"
	aud.Findings[0].Remediation = "Upgrade [x](javascript:alert(1))"
	aud.Findings[0].Vulnerability.URLs = []string{"https://example.com/a)b"}
	aud.Findings[1].Vulnerability.ID = "# CVE-1"
	aud.Findings[1].Vulnerability.URLs = nil
	aud.Findings[2].Vulnerability.ID = "1. GHSA"
	aud.Findings[2].Vulnerability.URLs = []string{"http://insecure.example"}
	aud.Findings[3].Package.Name = "a~b~c"
	aud.Findings[3].Package.Version = "ev\u202eil\u200bx"
	got := Render(Input{Run: record(map[string]string{"inventory": run.StageOK, "audit": run.StageOK}), Inventory: inv, Audit: aud, NoReview: "x"})
	for _, bad := range []string{"\x1b", "<script>", "|*pkg*", "[x](javascript", "](https://example.com/a)b)", "- # CVE-1", "- 1. GHSA", "a~b~c", "\u202e", "\u200b"} {
		if strings.Contains(got, bad) {
			t.Errorf("report contains %q", bad)
		}
	}
	for _, want := range []string{`evil\|\*pkg\*`, `- \# CVE-1`, `- 1\. GHSA`, `a\~b\~c`, "ev il x"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q missing:\n%s", want, got)
		}
	}
}

func TestRestartsNeverNameUserManagerUnits(t *testing.T) {
	inv := hostInventory()
	inv.Items = []inventory.Item{
		{ID: "a", Kind: inventory.KindProcess, Name: "systemd", Units: []string{"user@1000.service"}, RestartNeeded: []string{"/lib/x"}},
		{ID: "b", Kind: inventory.KindProcess, Name: "systemd", Units: []string{"user@1000.service"}, RestartNeeded: []string{"/lib/x"}},
		{ID: "c", Kind: inventory.KindProcess, Name: "sshd", Units: []string{"user@1000.service", "ssh.service"}, RestartNeeded: []string{"/lib/y"}},
	}
	got := Render(Input{Run: record(map[string]string{"inventory": run.StageOK}), Inventory: inv, NoReview: "x"})
	if strings.Contains(got, "user@") {
		t.Fatalf("a user's manager unit is named:\n%s", got)
	}
	if n := strings.Count(got, "- Restart systemd:"); n != 1 {
		t.Fatalf("%d lines for systemd, want 1:\n%s", n, got)
	}
	if !strings.Contains(got, "- Restart ssh.service:") {
		t.Fatalf("system unit missing:\n%s", got)
	}
}

func TestDescribeNamesAtMostFiveItems(t *testing.T) {
	o := inventory.Origin{Kind: inventory.OriginAppDir, Path: "/srv/x"}
	got := describe(o, []string{"a", "b", "c", "d", "e", "f", "g"})
	if got != "a, b, c, d, e, and 2 more: /srv/x" {
		t.Fatal(got)
	}
}

func TestEPSSBelowRoundingPrintsAsLessThan(t *testing.T) {
	for epss, want := range map[float64]string{0.0002: "EPSS <0.1%", 0.002: "EPSS 0.2%", 0: ""} {
		got := signals(audit.Finding{Vulnerability: audit.Vulnerability{Severity: "High", EPSS: epss}})
		if strings.Contains(got, "EPSS") != (want != "") || (want != "" && !strings.Contains(got, want)) {
			t.Errorf("EPSS %v: %q, want %q", epss, got, want)
		}
	}
}

func TestRenderNamesAtMostFiveItems(t *testing.T) {
	inv := hostInventory()
	aud := hostAudit()
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		inv.Items = append(inv.Items, inventory.Item{ID: "proc:" + n, Kind: inventory.KindProcess, Name: n})
		aud.Findings[0].Items = append(aud.Findings[0].Items, "proc:"+n)
	}
	got := Render(Input{Run: record(map[string]string{"inventory": run.StageOK, "audit": run.StageOK}), Inventory: inv, Audit: aud, NoReview: "x"})
	if !strings.Contains(got, "(a, b, c, d, e, and 5 more)") {
		t.Fatalf("%s", got)
	}
}

func TestGaps(t *testing.T) {
	gaps := Gaps(hostInventory(), hostAudit())
	var codes []string
	for _, g := range gaps {
		codes = append(codes, g.Code)
	}
	if strings.Join(codes, " ") != "ORIGIN_UNRESOLVED ORIGIN_UNIDENTIFIED APPDIR_NOT_FOUND IMAGE_ONLY" {
		t.Fatalf("gaps %v", gaps)
	}
	// Without an audit, the Inventory's unresolved origins are still gaps.
	if gaps := Gaps(hostInventory(), nil); len(gaps) != 3 || gaps[0].Code != problem.OriginUnresolved {
		t.Fatalf("gaps without an audit %v", gaps)
	}
}
