package audit

import (
	"context"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/osrel"
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
