package report

import (
	"flag"
	"fmt"
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
			f("f:0000000000000005", img, "CVE-2026-1234", "High", 0.41, false, audit.RiskHigh, "libssl3", "3.0.11-1~deb12u2",
				"Rebuild ghcr.io/acme/shop:2026.11.3 or pull a newer image with libssl3 3.0.16-1~deb12u1 or later, then recreate the container shop-web-1.", "container:shop-web-1"),
			f("f:0000000000000006", img, "CVE-2026-3100", "High", 0.001, false, audit.RiskMedium, "libssl3", "3.0.11-1~deb12u2",
				"Rebuild ghcr.io/acme/shop:2026.11.3 or pull a newer image with libssl3 3.0.17-1~deb12u1 or later, then recreate the container shop-web-1.", "container:shop-web-1"),
			f("f:0000000000000007", libssl, "CVE-2026-3200", "Critical", 0.003, false, audit.RiskMedium, "libssl3", "3.0.15-1~deb12u1",
				"Upgrade libssl3 to 3.0.17-1~deb12u1 (apt-get install --only-upgrade libssl3), then restart nginx.service, shop.service, python3.11.", "proc:nginx", "proc:shop", "proc:worker"),
		},
		Upgrades: []audit.Upgrade{{Origin: shop, Path: "/srv/shop", Package: "lodash", Type: "npm", Installed: []string{"4.17.20"}, Version: "4.18.0", Findings: 4}},
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
	aud.Findings[2].Risk = audit.RiskHigh
	aud.Findings[3].Package.Name = "a~b~c"
	aud.Findings[3].Package.Version = "ev\u202eil\u200bx"
	aud.Findings[3].Vulnerability.ID = "\n# Heading" // clean makes the newline a space
	aud.Findings[3].Vulnerability.URLs = nil
	aud.Findings[3].Risk = audit.RiskHigh
	aud.Findings[4].Package.Name = "# deep"
	aud.Findings[5].Package.Name = "*sum*|pkg"
	inv.Items[6].Name = "shop_web*1"
	inv.Origins[5].Ref = "ghcr.io/acme/[shop]:1"
	aud.Upgrades[0].Installed = []string{"4.17.20", "*4.17.21*"}
	got := Render(Input{Run: record(map[string]string{"inventory": run.StageOK, "audit": run.StageOK}), Inventory: inv, Audit: aud, NoReview: "x"})
	for _, bad := range []string{"\x1b", "<script>", "|*pkg*", "[x](javascript", "](https://example.com/a)b)", "- # CVE-1", "- 1. GHSA", "-  # Heading", "a~b~c", "\u202e", "\u200b", "*4.17.21*",
		"  - # deep", "*sum*|pkg", "shop_web*1", "[shop]"} {
		if strings.Contains(got, bad) {
			t.Errorf("report contains %q", bad)
		}
	}
	for _, want := range []string{`evil\|\*pkg\*`, `- \# CVE-1`, `- 1\. GHSA`, `- \# Heading`, `a\~b\~c`, "ev il x", `- Upgrade lodash 4.17.20, \*4.17.21\* in /srv/shop to 4.18.0`,
		`  - \# deep`, `\*sum\*\|pkg (1)`, `the container shop\_web\*1 (ghcr.io/acme/\[shop\]:1)`} {
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
		got := signals(audit.Vulnerability{Severity: "High", EPSS: epss})
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
	if !strings.Contains(got, " in a, b, c, d, e, and 5 more: ") {
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

func TestRenderSaysWhenARunWithAuditResultsFailed(t *testing.T) {
	r := record(map[string]string{"inventory": run.StageOK, "audit": run.StageOK},
		problem.New(problem.Error, problem.RunFolderUnwritable, "audit", "audit.json could not be written"))
	r.Status = run.Failed
	got := Render(Input{Run: r, Inventory: hostInventory(), Audit: hostAudit(), NoReview: "x"})
	if !strings.Contains(got, "(run failed: RUN_FOLDER_UNWRITABLE)") || strings.Contains(got, "run partial") {
		t.Fatal(got)
	}
}

// The verdict of a run without audit results names the error that failed the audit, whatever else
// went wrong before or besides it.
func TestVerdictNamesTheErrorThatFailedTheAudit(t *testing.T) {
	docker := problem.New(problem.Error, problem.DockerUnavailable, "inventory", "the Docker socket did not answer")
	kernel := problem.New(problem.Error, problem.KernelDataStale, "audit", "the kernel CNA data is too old")
	for _, tc := range []struct {
		errs []problem.Problem
		want string
	}{
		{[]problem.Problem{docker, problem.New(problem.Error, problem.RunFolderUnwritable, "", "cannot create the raw/ folder")}, "(RUN_FOLDER_UNWRITABLE)"},
		{[]problem.Problem{docker, kernel, problem.New(problem.Error, problem.GrypeUnavailable, "audit", "Grype is not available")}, "(GRYPE_UNAVAILABLE)"},
		{[]problem.Problem{docker, kernel, problem.New(problem.Error, problem.DBStale, "audit", "the database is too old")}, "(DB_STALE)"},
		{[]problem.Problem{docker, kernel}, "(KERNEL_DATA_STALE)"},
		{[]problem.Problem{docker}, "(DOCKER_UNAVAILABLE)"},
	} {
		r := record(map[string]string{"inventory": run.StagePartial, "audit": run.StageFailed}, tc.errs...)
		verdict, _, _ := strings.Cut(Render(Input{Run: r, Inventory: hostInventory(), Audit: &audit.Audit{Status: audit.Failed}, NoReview: "x"}), "\n")
		if !strings.HasPrefix(verdict, "⛔ Run incomplete: ") || !strings.Contains(verdict, tc.want) {
			t.Errorf("verdict %q, want %s", verdict, tc.want)
		}
	}
}

func TestRenderGroupsCriticalAndHighByVulnerability(t *testing.T) {
	up := inventory.KernelUpstreamOriginID("7.3.3")
	inv := &inventory.Inventory{
		Items: []inventory.Item{
			{ID: "kernel", Kind: inventory.KindKernel, Name: "kernel", Origins: []string{up}},
			{ID: "container:b-web", Kind: inventory.KindContainer, Name: "b-web", Origins: []string{"image:b"}},
			{ID: "container:a-api", Kind: inventory.KindContainer, Name: "a-api", Origins: []string{"image:a"}},
		},
		Origins: []inventory.Origin{
			{ID: up, Kind: inventory.OriginKernelUpstream, UpstreamVersion: "7.3.3"},
			{ID: "image:a", Kind: inventory.OriginImage, Ref: "acme/api:1"},
			{ID: "image:b", Kind: inventory.OriginImage, Ref: "acme/web:1"},
		},
	}
	f := func(id, origin, vuln, sev string, epss float64, risk, pkg, item string, urls ...string) audit.Finding {
		return audit.Finding{ID: id, Origin: origin, Risk: risk, Items: []string{item}, Remediation: "Fix " + id + ".", Package: audit.Package{Name: pkg, Version: "1.2"},
			Vulnerability: audit.Vulnerability{ID: vuln, Severity: sev, EPSS: epss, KnownExploited: risk == audit.RiskCritical, URLs: urls}}
	}
	kernelCNA := f("f:6", up, "CVE-2026-7000", "High", 0.2, audit.RiskHigh, "linux", "kernel")
	kernelCNA.Source = "kernel-cna"
	aud := &audit.Audit{Status: audit.Complete, Findings: []audit.Finding{
		f("f:1", "image:b", "CVE-2026-1000", "Critical", 0.5, audit.RiskCritical, "zlib", "container:b-web", "http://insecure.example", "https://example.com/1000"),
		f("f:2", "image:a", "CVE-2026-1000", "High", 0.5, audit.RiskCritical, "zlib", "container:a-api"),
		f("f:3", "image:a", "CVE-2026-1000", "Critical", 0.5, audit.RiskCritical, "libz", "container:a-api"),
		f("f:4", "image:a", "CVE-2026-2000", "High", 0.9, audit.RiskCritical, "openssl", "container:a-api"),
		f("f:5", "image:b", "CVE-2026-3000", "Medium", 0.2, audit.RiskHigh, "curl", "container:b-web"),
		kernelCNA,
	}}
	got := Render(Input{Run: record(map[string]string{"inventory": run.StageOK, "audit": run.StageOK}), Inventory: inv, Audit: aud, NoReview: "x"})
	want := `## Critical risk (4)

- CVE-2026-2000: severity High, known exploited (CISA KEV), EPSS 90.0%.
  - openssl 1.2 in a-api: Fix f:4.
- [CVE-2026-1000](https://example.com/1000): severity Critical or High, known exploited (CISA KEV), EPSS 50.0%.
  - libz 1.2 in a-api: Fix f:3.
  - zlib 1.2 in a-api: Fix f:2.
  - zlib 1.2 in b-web: Fix f:1.

## High risk (2)

- CVE-2026-3000: severity Medium, EPSS 20.0%.
  - curl 1.2 in b-web: Fix f:5.
- CVE-2026-7000: severity High, EPSS 20.0%.
  - linux 1.2 in kernel (matched by upstream kernel version): Fix f:6.

`
	if !strings.Contains(got, want) {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderSummarizesMediumAndLow(t *testing.T) {
	up := inventory.KernelUpstreamOriginID("7.3.3")
	inv := &inventory.Inventory{
		Items: []inventory.Item{
			{ID: "kernel", Kind: inventory.KindKernel, Name: "kernel", Origins: []string{up}},
			{ID: "container:web-2", Kind: inventory.KindContainer, Name: "web-2", Origins: []string{img}},
			{ID: "container:web-1", Kind: inventory.KindContainer, Name: "web-1", Origins: []string{img}},
			{ID: "proc:java", Kind: inventory.KindProcess, Name: "java", Origins: []string{"appdir:/srv/app.jar", libssl}},
		},
		Origins: []inventory.Origin{
			{ID: up, Kind: inventory.OriginKernelUpstream, UpstreamVersion: "7.3.3"},
			{ID: img, Kind: inventory.OriginImage, ImageID: "sha256:1111", Ref: "ghcr.io/acme/web:1"},
			{ID: "appdir:/srv/app.jar", Kind: inventory.OriginAppDir, Path: "/srv/app.jar", Jar: true},
			{ID: libssl, Kind: inventory.OriginPackage, Name: "libssl3"},
			{ID: "pkg:zlib", Kind: inventory.OriginPackage, Name: "zlib1g"},
		},
	}
	aud := &audit.Audit{Status: audit.Complete}
	add := func(origin, risk, pkg string, n int) {
		for range n {
			id := fmt.Sprintf("f:%d", len(aud.Findings))
			aud.Findings = append(aud.Findings, audit.Finding{ID: id, Origin: origin, Risk: risk, Package: audit.Package{Name: pkg}, Remediation: "Fix " + id + ".",
				Vulnerability: audit.Vulnerability{ID: "CVE-" + id, Severity: "High"}})
		}
	}
	add(img, audit.RiskMedium, "chromium", 3)
	add(img, audit.RiskMedium, "zlib", 1)
	add(img, audit.RiskMedium, "openssl", 1)
	add(img, audit.RiskMedium, "libxml2", 2)
	add(libssl, audit.RiskMedium, "libssl3", 2)
	add("pkg:zlib", audit.RiskMedium, "zlib1g", 1)
	add("appdir:/srv/app.jar", audit.RiskMedium, "log4j-core", 2)
	add(up, audit.RiskMedium, "linux", 2)
	for i := range 25 {
		b := fmt.Sprintf("binary:%02d", i)
		inv.Origins = append(inv.Origins, inventory.Origin{ID: b, Kind: inventory.OriginBinary, Paths: []string{fmt.Sprintf("/opt/bin/b%02d", i)}})
		add(b, audit.RiskMedium, "stdlib", 1)
	}
	add(img, audit.RiskLow, "zlib", 1)
	got := Render(Input{Run: record(map[string]string{"inventory": run.StageOK, "audit": run.StageOK}), Inventory: inv, Audit: aud, NoReview: "x"})
	want := `## Medium risk (39)

- 7 in the containers web-1, web-2 (ghcr.io/acme/web:1); most in chromium (3), libxml2 (2), openssl (1)
- 3 in this host's packages (2 packages); all in libssl3 (2), zlib1g (1)
- 2 in the jar /srv/app.jar (java); all in log4j-core (2)
- 2 in the kernel (Linux 7.3.3); all in linux (2)
- 1 in the binary /opt/bin/b00; all in stdlib (1)
`
	if !strings.Contains(got, want) {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	want = `- 1 in the binary /opt/bin/b20; all in stdlib (1)
- … and 4 more with 4 findings.

Every medium risk finding, with its remediation, is in audit.json.

## Low risk (1)

- 1 in the containers web-1, web-2 (ghcr.io/acme/web:1); all in zlib (1)

Every low risk finding, with its remediation, is in audit.json.
`
	if !strings.Contains(got, want) || strings.Contains(got, "/opt/bin/b21") || strings.Contains(got, "Fix f:") {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderGroupsCoverageGaps(t *testing.T) {
	inv := &inventory.Inventory{}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		id := "unresolved:" + n
		inv.Items = append(inv.Items, inventory.Item{ID: "proc:" + n, Kind: inventory.KindProcess, Name: n, Origins: []string{id}})
		inv.Origins = append(inv.Origins, inventory.Origin{ID: id, Kind: inventory.OriginUnresolved, Reason: "it runs in another root file system", Paths: []string{"/lib/" + n + "_x.so"}})
	}
	inv.Items = append(inv.Items,
		inventory.Item{ID: "proc:lxd", Kind: inventory.KindProcess, Name: "lxd", Origins: []string{snap}},
		inventory.Item{ID: "proc:p", Kind: inventory.KindProcess, Name: "p", Exe: "/usr/bin/python3", Notes: []string{problem.AppDirNotFound}},
		inventory.Item{ID: "proc:q", Kind: inventory.KindProcess, Name: "q", Exe: "/usr/bin/python3", Notes: []string{problem.AppDirNotFound}})
	inv.Origins = append(inv.Origins, inventory.Origin{ID: snap, Kind: inventory.OriginUnresolved, Reason: "it runs from a snap", Paths: []string{"/snap/lxd/1/bin/lxd"}})
	got := Render(Input{Run: record(map[string]string{"inventory": run.StageOK}), Inventory: inv, NoReview: "x"})
	want := "## Coverage gaps\n\n" +
		"- 5 × `ORIGIN_UNRESOLVED`: it runs in another root file system (a: /lib/a\\_x.so; b: /lib/b\\_x.so; c: /lib/c\\_x.so; and 2 more)\n" +
		"- 2 × `APPDIR_NOT_FOUND`: no app directory was found, so only the interpreter is audited (p (/usr/bin/python3); q (/usr/bin/python3))\n" +
		"- `ORIGIN_UNRESOLVED` lxd: /snap/lxd/1/bin/lxd: it runs from a snap\n"
	if !strings.Contains(got, want) || !strings.Contains(got, "(8 coverage gaps)") {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}
