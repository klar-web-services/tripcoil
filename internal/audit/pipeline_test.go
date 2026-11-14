package audit

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/grype"
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
