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
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

func TestAuditDebianSBOMThatDoesNotVerify(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.matching = func(r *grype.Report) {
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

func TestAuditDebianKernelEvidenceWhenTheSBOMDoesNotVerify(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.matching = func(r *grype.Report) {
		r.Matches = slices.DeleteFunc(r.Matches, func(m grype.Match) bool { return m.Artifact.Name == "libssl3" })
	}
	runDir := t.TempDir()
	a := Run(context.Background(), deps(root, cache, runDir, g, fakeKernel{}), inv)
	f, scanned, matched := byVuln(a), "raw/"+rawName(packagesID, ".grype.json"), "raw/"+rawName(packagesID, ".kernel.grype.json")
	if f["CVE-2026-2000"].Raw != matched || f["CVE-2026-1234"].Raw != scanned {
		t.Fatalf("the kernel's finding names %q, libssl3's %q", f["CVE-2026-2000"].Raw, f["CVE-2026-1234"].Raw)
	}
	for _, o := range a.Origins {
		if want := map[string]string{kernelO: matched, libsslO: scanned}[o.ID]; want != "" && (o.Raw == nil || o.Raw.Grype != want) {
			t.Errorf("origin %s names %+v, want %s", o.ID, o.Raw, want)
		}
	}
	if fi, err := os.Stat(filepath.Join(runDir, matched)); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("the kernel's report in the run folder: %v %v", fi, err)
	}
	root, cache, inv = host(t)
	a = Run(context.Background(), deps(root, cache, t.TempDir(), hostScanner(root, cache), fakeKernel{}), inv)
	if k := byVuln(a)["CVE-2026-2000"]; k.Raw != scanned {
		t.Errorf("verified: the kernel's finding names %q", k.Raw)
	}
}

func TestAuditKernelMatchThatFailsFailsOnlyTheKernel(t *testing.T) {
	old := cacheSpace
	defer func() { cacheSpace = old }()
	for _, tc := range []struct {
		name  string
		fail  func(g *fakeScanner, runDir string)
		error string
	}{
		{"match", func(g *fakeScanner, _ string) {
			g.matchErr = map[string]error{"packages-match.cdx.json": errors.New("Grype failed: boom")}
		}, "Grype failed: boom"},
		{"run folder at its floor", func(_ *fakeScanner, runDir string) {
			first := true
			cacheSpace = func(dir string) (uint64, uint64, error) {
				if strings.HasPrefix(dir, runDir) && first {
					first = false
					return 1000, 10000, nil
				}
				return 1 << 40, 1 << 41, nil
			}
		}, errRunFolderFull.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cacheSpace = old
			root, cache, inv := host(t)
			g := hostScanner(root, cache)
			g.matching = func(r *grype.Report) {
				r.Matches = slices.DeleteFunc(r.Matches, func(m grype.Match) bool { return m.Artifact.Name == "libssl3" })
			}
			runDir := t.TempDir()
			tc.fail(g, runDir)
			a := Run(context.Background(), deps(root, cache, runDir, g, fakeKernel{}), inv)
			f, st := byVuln(a), statuses(a)
			want := "linux-image-6.1.0-28-amd64 6.1.123-1: matching the kernel package at its running version failed: " + tc.error
			if a.Status != Partial || len(a.Errors) != 1 || a.Errors[0].Message != want || st[kernelO] != ScanFailed || st[libsslO] != Scanned {
				t.Fatalf("audit %s, errors %+v, statuses %v", a.Status, a.Errors, st)
			}
			if f["CVE-2026-1234"].Origin != libsslO {
				t.Errorf("findings %+v: libssl3's is the scan's", a.Findings)
			}
			for _, id := range []string{"CVE-2026-2000", "CVE-2026-2999"} {
				if _, ok := f[id]; ok {
					t.Errorf("a finding of the failed kernel package: %+v", f[id])
				}
			}
			if _, err := os.Stat(filepath.Join(runDir, "raw", rawName(packagesID, ".kernel.grype.json"))); !os.IsNotExist(err) {
				t.Errorf("the failed match's report is left: %v", err)
			}
		})
	}
}

func TestAuditVerifiedKernelMatchThatFailsFailsOnlyTheKernel(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.matchErr = map[string]error{"packages-match.cdx.json": errors.New("Grype failed: boom")}
	runDir := t.TempDir()
	a := Run(context.Background(), deps(root, cache, runDir, g, fakeKernel{}), inv)
	f, st := byVuln(a), statuses(a)
	if a.Status != Partial || len(a.Errors) != 1 || st[kernelO] != ScanFailed || st[libsslO] != Scanned ||
		a.Errors[0].Message != "linux-image-6.1.0-28-amd64 6.1.123-1: matching the kernel package at its running version failed: Grype failed: boom" {
		t.Fatalf("audit %s, errors %+v, statuses %v", a.Status, a.Errors, st)
	}
	scanned := "raw/" + rawName(packagesID, ".grype.json")
	if s := f["CVE-2026-1234"]; s.Origin != libsslO || s.Raw != scanned {
		t.Errorf("libssl3's finding %+v: it is the scan's", s)
	}
	for _, id := range []string{"CVE-2026-2000", "CVE-2026-2999"} {
		if _, ok := f[id]; ok {
			t.Errorf("a finding of the failed kernel package: %+v", f[id])
		}
	}
	if fi, err := os.Stat(filepath.Join(runDir, scanned)); err != nil || fi.Size() == 0 {
		t.Errorf("the scan's report in the run folder: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "raw", rawName(packagesID, ".kernel.grype.json"))); !os.IsNotExist(err) {
		t.Errorf("the failed match's report is left: %v", err)
	}
	if !slices.Contains(cachedKinds(cache), "packages") {
		t.Fatalf("cached %v", cachedKinds(cache))
	}
	a = Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if st := statuses(a); st[kernelO] != ScanFailed || st[libsslO] != ScanFailed {
		t.Fatalf("matched from the cache: audit %s, errors %+v, statuses %v", a.Status, a.Errors, st)
	}
}

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

func TestAuditPURLWithoutTheDistroQualifier(t *testing.T) {
	root, cache, inv := host(t)
	inv.Items[0].RunningVersion = "6.1.123-1"
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

func TestAuditMultiarchPackageRemovedSinceTheInventory(t *testing.T) {
	root, cache, inv := host(t)
	i386 := pkgtool.Package{Name: "libssl3", Version: "3.0.15-1~deb12u1", Arch: "i386", Type: "deb"}
	i386O := inventory.PackageOriginID(debian, i386)
	inv.Origins = append(inv.Origins, inventory.Origin{ID: i386O, Kind: inventory.OriginPackage, Name: i386.Name, Version: i386.Version, Arch: "i386", Type: "deb"})
	inv.Items = append(inv.Items, inventory.Item{ID: "proc:wine", Kind: inventory.KindProcess, Name: "wine", Origins: []string{i386O}})
	a := Run(context.Background(), deps(root, cache, t.TempDir(), hostScanner(root, cache), fakeKernel{}), inv)
	st := statuses(a)
	if a.Status != Partial || len(a.Errors) != 1 || a.Errors[0].Message != "libssl3 3.0.15-1~deb12u1: the package was removed since the inventory" ||
		st[i386O] != ScanFailed || st[libsslO] != Scanned {
		t.Fatalf("audit %s, errors %+v, statuses %v", a.Status, a.Errors, st)
	}
}

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

func TestStagePackageDBRPMLeavesOutWhatReadersChange(t *testing.T) {
	for _, tc := range []struct {
		name               string
		database, readers  []string
		staged, keyChanges []string
	}{
		{"sqlite", []string{"rpmdb.sqlite", "rpmdb.sqlite-wal"}, []string{"rpmdb.sqlite-shm"},
			[]string{"etc/os-release", "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite-wal"}, []string{"rpmdb.sqlite-wal"}},
		{"berkeley db", []string{"Packages", "Name"}, []string{"__db.001", "__db.002", "__db.003"},
			[]string{"etc/os-release", "var/lib/rpm/Name", "var/lib/rpm/Packages"}, []string{"Packages"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree0 := map[string]string{"etc/os-release": "ID=rocky\n"}
			for _, f := range slices.Concat(tc.database, tc.readers) {
				tree0["var/lib/rpm/"+f] = "v1"
			}
			root := files(t, tree0)
			dst := t.TempDir()
			key, err := stagePackageDB(budget(), root, osrel.RHEL, dst)
			if err != nil {
				t.Fatal(err)
			}
			if got := tree(t, dst); !slices.Equal(got, tc.staged) {
				t.Fatalf("staged %v, want %v", got, tc.staged)
			}
			for _, f := range tc.readers {
				os.WriteFile(filepath.Join(root, "var/lib/rpm", f), []byte("v2, after a query"), 0o644)
			}
			if again, _ := stagePackageDB(budget(), root, osrel.RHEL, t.TempDir()); again != key {
				t.Fatal("a query changed the key")
			}
			for _, f := range tc.keyChanges {
				os.WriteFile(filepath.Join(root, "var/lib/rpm", f), []byte("v2, after a transaction"), 0o644)
			}
			if again, _ := stagePackageDB(budget(), root, osrel.RHEL, t.TempDir()); again == key {
				t.Fatal("a transaction kept the key")
			}
		})
	}
}
