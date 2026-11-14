package audit

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

// On Debian the running kernel's package is changed in the package SBOM at every run. When matching
// the SBOM does not give what the scan gave, the findings are still the scan's, except the kernel
// package's: only matching the changed SBOM gives its matches at the running version.
func TestAuditDebianSBOMThatDoesNotVerify(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.matching = func(r *grype.Report) { // matching an SBOM loses a match of the scan
		r.Matches = slices.DeleteFunc(r.Matches, func(m grype.Match) bool { return m.Artifact.Name == "libssl3" })
	}
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	f := byVuln(a)
	if a.Status != Complete || len(a.Errors) != 0 || statuses(a)[libsslO] != Scanned || f["CVE-2026-1234"].Origin != libsslO {
		t.Fatalf("audit %s, errors %+v, statuses %v: libssl3's finding is the scan's", a.Status, a.Errors, statuses(a))
	}
	if k := f["CVE-2026-2000"]; k.Origin != kernelO || k.Package.Version != "6.1.119-1" {
		t.Errorf("kernel finding %+v: it is matched at the running version", k)
	}
	if _, ok := f["CVE-2026-2999"]; ok {
		t.Errorf("findings %+v: the scan matched the kernel package as installed", a.Findings)
	}
	if slices.Contains(cachedKinds(cache), "packages") {
		t.Errorf("cached %v", cachedKinds(cache))
	}
}

// When matching the changed SBOM loses the distribution the scan recognised, the other packages are
// still the scan's, and the kernel's package, which nothing else matches at its running version, is
// a coverage gap.
func TestAuditDebianSBOMMatchedWithoutTheDistribution(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.matching = func(r *grype.Report) { r.Distro, r.DistroVersion, r.Matches = "", "", nil }
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	f := byVuln(a)
	st := statuses(a)
	if a.Status != Complete || len(a.Errors) != 0 || st[libsslO] != Scanned || f["CVE-2026-1234"].Origin != libsslO {
		t.Fatalf("audit %s, errors %+v, statuses %v", a.Status, a.Errors, st)
	}
	for _, o := range a.Origins {
		if o.ID == kernelO && (o.Status != Unidentified || !strings.Contains(o.Reason, "running version")) {
			t.Errorf("kernel origin %+v", o)
		}
	}
	for _, id := range []string{"CVE-2026-2000", "CVE-2026-2999"} {
		if _, ok := f[id]; ok {
			t.Errorf("findings %+v: the kernel package has no matches at its running version", a.Findings)
		}
	}
}

// A finding's purl is the same whether the SBOM was cataloged or matched from the cache, where
// StripSBOM dropped its distro qualifier: audit.json changes only when the host does.
func TestAuditPURLWithoutTheDistroQualifier(t *testing.T) {
	root, cache, inv := host(t)
	inv.Items[0].RunningVersion = "6.1.123-1" // no package SBOM is changed: the scan's report is used
	g := hostScanner(root, cache)
	d := deps(root, cache, t.TempDir(), g, fakeKernel{})
	d.Family = osrel.Ubuntu
	purls := func(a *Audit) map[string]string {
		m := map[string]string{}
		for _, f := range a.Findings {
			m[f.ID] = f.Package.PURL
		}
		return m
	}
	miss := purls(Run(context.Background(), d, inv))
	d.RunDir = t.TempDir()
	hit := purls(Run(context.Background(), d, inv))
	if !maps.Equal(miss, hit) {
		t.Fatalf("purls on a cache miss %v, on a hit %v", miss, hit)
	}
	for _, p := range miss {
		if strings.Contains(p, "distro=") {
			t.Errorf("purl %q", p)
		}
	}
	if len(miss) != 8 {
		t.Errorf("%d findings", len(miss))
	}
}

// A package upgraded or removed between the Inventory and the Audit fails its origin, as the
// kernel's does: it is audited at the next run. Only a package that Grype holds by name but does
// not tell apart, here without its architecture, is unidentified.
func TestAuditPackageChangedSinceTheInventory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]grype.Component) []grype.Component
		error  string
	}{
		{"upgraded", func(c []grype.Component) []grype.Component {
			c[0].Version = "3.0.16-1~deb12u1"
			c[0].PURL = "pkg:deb/debian/libssl3@3.0.16-1~deb12u1?arch=amd64&distro=debian-12"
			return c
		}, "libssl3 3.0.15-1~deb12u1: the package changed since the inventory, so it is audited at the next run"},
		{"removed", func(c []grype.Component) []grype.Component { return c[1:] },
			"libssl3 3.0.15-1~deb12u1: the package was removed since the inventory"},
		{"read without its architecture", func(c []grype.Component) []grype.Component {
			c[0].PURL = "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?distro=debian-12"
			return c
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, cache, inv := host(t)
			g := hostScanner(root, cache)
			staging := "dir:" + filepath.Join(cache, "staging")
			g.sboms[staging] = tc.change(slices.Clone(g.sboms[staging]))
			a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
			st := statuses(a)
			if st[kernelO] != Scanned || st[apiO] != Scanned {
				t.Fatalf("statuses %v", st)
			}
			if tc.error == "" {
				if a.Status != Complete || len(a.Errors) != 0 || st[libsslO] != Unidentified {
					t.Fatalf("audit %s, errors %+v, statuses %v", a.Status, a.Errors, st)
				}
				return
			}
			if a.Status != Partial || len(a.Errors) != 1 || a.Errors[0].Message != tc.error || st[libsslO] != ScanFailed {
				t.Fatalf("audit %s, errors %+v, statuses %v", a.Status, a.Errors, st)
			}
		})
	}
}

// What a killed run left in the scan folder, such as the copy of a user's file, is removed when the
// next run starts, even when that run then fails.
func TestAuditRemovesWhatAKilledRunLeft(t *testing.T) {
	root, cache, inv := host(t)
	left := filepath.Join(cache, "scan", sumOf("killed"), "copy")
	leave := func() {
		os.MkdirAll(filepath.Dir(left), 0o700)
		os.WriteFile(left, []byte("a user's file"), 0o600)
	}
	leave()
	g := hostScanner(root, cache)
	var seen []string
	g.scanning = func(source string) {
		if _, err := os.Stat(left); err == nil {
			seen = append(seen, source)
		}
	}
	if a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv); a.Status != Complete || len(seen) != 0 {
		t.Fatalf("audit %s; the copy was still there when Grype scanned %q", a.Status, seen)
	}
	leave()
	g.prepareErr = errors.New("cannot download Grype")
	if a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv); a.Status != Failed {
		t.Fatalf("audit %s", a.Status)
	}
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Fatalf("the copy is still there: %v", err)
	}
}

// A failed check of the kernel CNA data while the data is still within maxAge is a warning, as for
// Grype's database: the kernel is audited with the data there is.
func TestAuditKernelDataUpdateFailed(t *testing.T) {
	up := inventory.KernelUpstreamOriginID("6.1.119")
	root := files(t, map[string]string{"etc/os-release": "ID=arch\n"})
	inv := &inventory.Inventory{
		Items:   []inventory.Item{{ID: "kernel", Kind: inventory.KindKernel, RunningVersion: "6.1.119-1", Origins: []string{up}}},
		Origins: []inventory.Origin{{ID: up, Kind: inventory.OriginKernelUpstream, UpstreamVersion: "6.1.119"}},
	}
	data := kernelTestData(t)
	data.RefreshErr = errors.New("https://git.kernel.org/pub/scm/linux/security/vulns.git/info/refs returned 503 Service Unavailable")
	g := &fakeScanner{status: grype.DBStatus{Built: built, Valid: true}}
	d := deps(root, t.TempDir(), t.TempDir(), g, fakeKernel{data: data})
	d.Family = osrel.Arch
	a := Run(context.Background(), d, inv)
	if a.Status != Complete || len(a.Errors) != 0 || statuses(a)[up] != Scanned || len(a.Findings) != 8 {
		t.Fatalf("audit %s, errors %+v, statuses %v, %d findings", a.Status, a.Errors, statuses(a), len(a.Findings))
	}
	if len(a.Warnings) != 1 || a.Warnings[0].Code != problem.KernelDataUpdateFailed || a.Warnings[0].Kind != problem.Warning ||
		a.Warnings[0].Message != "checking the kernel CNA data for news failed, so the data last checked at 2026-11-14T05:15:00Z is used: https://git.kernel.org/pub/scm/linux/security/vulns.git/info/refs returned 503 Service Unavailable" {
		t.Fatalf("warnings %+v", a.Warnings)
	}
	data.RefreshErr = nil
	if a := Run(context.Background(), d, inv); len(a.Warnings) != 0 {
		t.Fatalf("warnings %+v", a.Warnings)
	}
}
