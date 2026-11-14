package audit

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/kernelcna"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/procfs"
)

var (
	now    = time.Date(2026, 11, 14, 6, 15, 0, 0, time.UTC)
	built  = time.Date(2026, 11, 14, 3, 12, 0, 0, time.UTC)
	debian = inventory.Distro{ID: "debian", VersionID: "12", Family: "debian"}

	libsslPkg = pkgtool.Package{Name: "libssl3", Version: "3.0.15-1~deb12u1", Arch: "amd64", Type: "deb"}
	kernelPkg = pkgtool.Package{Name: "linux-image-6.1.0-28-amd64", Version: "6.1.123-1", Arch: "amd64", Type: "deb"}
	libsslO   = inventory.PackageOriginID(debian, libsslPkg)
	kernelO   = inventory.PackageOriginID(debian, kernelPkg)
	apiO      = inventory.BinaryOriginID(sumOf("go binary v1"))
	oldO      = inventory.BinaryOriginID(sumOf("go binary v0"))
	toolO     = inventory.BinaryOriginID(sumOf("stripped"))
	jarO      = inventory.AppDirOriginID("/srv/app.jar")
	imageO    = inventory.ImageOriginID("sha256:1111")
	snapO     = inventory.UnresolvedOriginID("snap")
)

// host is a Debian host whose kernel package was upgraded in place: installed 6.1.123-1, running
// 6.1.119-1.
func host(t *testing.T) (root, cache string, inv *inventory.Inventory) {
	root = files(t, map[string]string{
		"etc/os-release":             "ID=debian\nVERSION_ID=12\n",
		"var/lib/dpkg/status":        "Package: libssl3\n",
		"opt/api/api":                "go binary v1",
		"opt/api/old":                "go binary v1, installed while v0 runs",
		"usr/local/bin/tool":         "stripped",
		"srv/shop/package.json":      `{"name":"shop"}`,
		"srv/shop/package-lock.json": `{"lockfileVersion":3}`,
		"srv/venv/pyvenv.cfg":        "home = /usr/bin\n",
		"srv/app.jar":                "jar v1",
	})
	cache = t.TempDir()
	replaced := filepath.Join(cache, "replaced", sumOf("go binary v0"))
	os.MkdirAll(filepath.Dir(replaced), 0o700)
	os.WriteFile(replaced, []byte("go binary v0"), 0o600)
	inv = &inventory.Inventory{
		Host: inventory.Host{Distro: debian},
		Items: []inventory.Item{
			{ID: "kernel", Kind: inventory.KindKernel, Name: "kernel", RunningVersion: "6.1.119-1", Origins: []string{kernelO}},
			{ID: "proc:nginx", Kind: inventory.KindProcess, Name: "nginx", Units: []string{"nginx.service"}, Origins: []string{libsslO}},
			{ID: "proc:api", Kind: inventory.KindProcess, Name: "api", Units: []string{"api.service"}, Origins: []string{apiO, libsslO}},
			{ID: "proc:old", Kind: inventory.KindProcess, Name: "old", Origins: []string{oldO}},
			{ID: "proc:tool", Kind: inventory.KindProcess, Name: "tool", Origins: []string{toolO}},
			{ID: "proc:shop", Kind: inventory.KindProcess, Name: "node", Units: []string{"shop.service"}, Origins: []string{"appdir:/srv/shop"}},
			{ID: "proc:venv", Kind: inventory.KindProcess, Name: "python3.11", Origins: []string{"appdir:/srv/venv"}},
			{ID: "proc:java", Kind: inventory.KindProcess, Name: "java", Origins: []string{jarO}},
			{ID: "proc:lxd", Kind: inventory.KindProcess, Name: "lxd", Origins: []string{snapO}},
			{ID: "container:web", Kind: inventory.KindContainer, Name: "web", Origins: []string{imageO}},
		},
		Origins: []inventory.Origin{
			{ID: kernelO, Kind: inventory.OriginPackage, Name: kernelPkg.Name, Version: kernelPkg.Version, Arch: "amd64", Type: "deb"},
			{ID: libsslO, Kind: inventory.OriginPackage, Name: libsslPkg.Name, Version: libsslPkg.Version, Arch: "amd64", Type: "deb"},
			{ID: apiO, Kind: inventory.OriginBinary, SHA256: sumOf("go binary v1"), Paths: []string{"/opt/api/api"}},
			{ID: oldO, Kind: inventory.OriginBinary, SHA256: sumOf("go binary v0"), Paths: []string{"/opt/api/old"}, Copy: replaced},
			{ID: toolO, Kind: inventory.OriginBinary, SHA256: sumOf("stripped"), Paths: []string{"/usr/local/bin/tool"}},
			{ID: "appdir:/srv/shop", Kind: inventory.OriginAppDir, Path: "/srv/shop"},
			{ID: "appdir:/srv/venv", Kind: inventory.OriginAppDir, Path: "/srv/venv"},
			{ID: jarO, Kind: inventory.OriginAppDir, Path: "/srv/app.jar", Jar: true},
			{ID: imageO, Kind: inventory.OriginImage, ImageID: "sha256:1111", Ref: "ghcr.io/acme/shop:2026.11.3"},
			{ID: snapO, Kind: inventory.OriginUnresolved, Reason: "it runs from a snap, and snaps are not audited in v1", Paths: []string{"/snap/lxd/1/bin/lxd"}},
		},
	}
	return root, cache, inv
}

func vuln(id, severity, state string, fixes ...string) grype.Vulnerability {
	return grype.Vulnerability{ID: id, Severity: severity, FixState: state, FixVersions: fixes, Namespace: "test:" + id}
}

func hostScanner(root, cache string) *fakeScanner {
	kev := vuln("CVE-2026-2000", "High", "fixed", "6.1.123-1")
	kev.KnownExploited = true
	epss := vuln("CVE-2026-1234", "High", "fixed", "3.0.16-1~deb12u1")
	epss.EPSS = 0.41
	xnet := vuln("GHSA-4374-p667-p6c8", "High", "fixed", "v0.17.0")
	log4j := vuln("CVE-2021-44228", "Critical", "fixed", "2.15.0")
	log4j.KnownExploited = true
	return &fakeScanner{
		status:    grype.DBStatus{Built: built, SchemaVersion: "v6.1.10", Valid: true},
		osVersion: "12.15",
		distro:    "debian",
		locations: map[string]string{"lodash": "/package-lock.json"},
		sboms: map[string][]grype.Component{
			"dir:" + filepath.Join(cache, "staging"): {
				{Name: "libssl3", Version: "3.0.15-1~deb12u1", PURL: "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12"},
				{Name: "linux-image-6.1.0-28-amd64", Version: "6.1.123-1", PURL: "pkg:deb/debian/linux-image-6.1.0-28-amd64@6.1.123-1?arch=amd64&distro=debian-12"},
				{Name: "vim", Version: "2:9.0.1378-2", PURL: "pkg:deb/debian/vim@2:9.0.1378-2?arch=amd64&distro=debian-12"},
			},
			"file:" + filepath.Join(cache, "scan", sumOf("go binary v1"), "api"): {{Name: "golang.org/x/net", Version: "v0.1.0", PURL: "pkg:golang/golang.org/x/net@v0.1.0"}},
			"file:" + filepath.Join(cache, "scan", sumOf("go binary v0"), "old"): {{Name: "golang.org/x/text", Version: "v0.3.5", PURL: "pkg:golang/golang.org/x/text@v0.3.5"}},
			"file:" + filepath.Join(cache, "scan", sumOf("stripped"), "tool"):    {},
			"dir:" + filepath.Join(root, "srv/shop"):                             {{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"}},
			"dir:" + filepath.Join(root, "srv/venv"):                             {{Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0"}},
			"file:" + filepath.Join(cache, "scan", sumOf("jar v1"), "app.jar"):   {{Name: "log4j-core", Version: "2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}},
			"docker:sha256:1111": {{Name: "zlib1g", Version: "1:1.2.13.dfsg-1", PURL: "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=amd64&distro=debian-12"}},
		},
		vulns: map[string][]grype.Vulnerability{
			"libssl3@3.0.15-1~deb12u1":             {epss},
			"vim@2:9.0.1378-2":                     {vuln("CVE-2026-0009", "High", "fixed", "2:9.0.1378-3")}, // not running
			"linux-image-6.1.0-28-amd64@6.1.119-1": {kev},
			"linux-image-6.1.0-28-amd64@6.1.123-1": {vuln("CVE-2026-2999", "High", "not-fixed")}, // installed, not running
			"golang.org/x/net@v0.1.0":              {xnet},
			"golang.org/x/text@v0.3.5":             {vuln("CVE-2021-38561", "High", "fixed", "v0.3.7")},
			"lodash@4.17.20":                       {vuln("GHSA-35jh-r3h4-6jhm", "High", "fixed", "4.17.21"), vuln("GHSA-29mw-wpgm-hmr9", "Medium", "fixed", "4.17.21")},
			"log4j-core@2.14.1":                    {log4j},
			"zlib1g@1:1.2.13.dfsg-1":               {vuln("CVE-2026-3000", "Low", "not-fixed")},
		},
	}
}

func deps(root, cache, runDir string, g Scanner, k KernelSource) Deps {
	return Deps{Root: root, CacheDir: cache, RunDir: runDir, Family: osrel.Debian, MaxAge: 48 * time.Hour,
		Now: func() time.Time { return now }, Grype: g, Kernel: k}
}

func byVuln(a *Audit) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range a.Findings {
		m[f.Vulnerability.ID] = f
	}
	return m
}

func statuses(a *Audit) map[string]string {
	m := map[string]string{}
	for _, o := range a.Origins {
		m[o.ID] = o.Status
	}
	return m
}

func TestAudit(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	runDir := t.TempDir()
	a := Run(context.Background(), deps(root, cache, runDir, g, fakeKernel{}), inv)
	if a.Status != Complete || len(a.Errors) != 0 || !a.Grype.DBBuilt.Equal(built) || a.Grype.Version != grype.Version {
		t.Fatalf("audit %+v", a)
	}
	if empty := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), &inventory.Inventory{}); empty.Upgrades == nil || empty.Findings == nil {
		t.Fatalf("audit.json has [] for no upgrades or findings, never null: %+v", empty)
	}
	f := byVuln(a)
	var ids []string
	for id := range f {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	want := []string{"CVE-2021-38561", "CVE-2021-44228", "CVE-2026-1234", "CVE-2026-2000", "CVE-2026-3000", "GHSA-29mw-wpgm-hmr9", "GHSA-35jh-r3h4-6jhm", "GHSA-4374-p667-p6c8"}
	if !slices.Equal(ids, want) {
		t.Fatalf("findings %v, want %v (packages that do not run, and the installed kernel, are left out)", ids, want)
	}
	if k := f["CVE-2026-2000"]; k.Origin != kernelO || k.Package.Version != "6.1.119-1" || k.Risk != RiskCritical ||
		k.Remediation != "Upgrade the kernel to 6.1.123-1 or later (apt-get update && apt-get dist-upgrade), then reboot." || !slices.Equal(k.Items, []string{"kernel"}) {
		t.Errorf("kernel finding %+v: it must be for the running version", k)
	}
	if s := f["CVE-2026-1234"]; s.Origin != libsslO || s.Risk != RiskHigh || !slices.Equal(s.Items, []string{"proc:nginx", "proc:api"}) ||
		s.Source != "test:CVE-2026-1234" || s.Package.Location != "/where/libssl3" || s.Raw != "raw/"+rawName(packagesID, ".grype.json") {
		t.Errorf("libssl3 finding %+v", s)
	}
	if x := f["GHSA-4374-p667-p6c8"]; x.Origin != apiO || x.Risk != RiskMedium || !strings.HasPrefix(x.Remediation, "Replace or rebuild /opt/api/api with golang.org/x/net v0.17.0") {
		t.Errorf("binary finding %+v", x)
	}
	if x := f["CVE-2021-38561"]; x.Origin != oldO {
		t.Errorf("the replaced binary's copy is scanned: %+v", x)
	}
	if l := f["CVE-2021-44228"]; l.Origin != jarO || l.Risk != RiskCritical {
		t.Errorf("jar finding %+v", l)
	}
	if a.Findings[0].Risk != RiskCritical || a.Findings[len(a.Findings)-1].Risk != RiskLow {
		t.Errorf("findings are not sorted by risk: %+v", a.Findings)
	}
	if l := f["GHSA-35jh-r3h4-6jhm"]; l.Package.PURL != "pkg:npm/lodash@4.17.20" {
		t.Errorf("app directory finding %+v: the purl is Grype's", l)
	}
	if len(a.Upgrades) != 2 || a.Upgrades[0].Package != "lodash" || a.Upgrades[0].Version != "4.17.21" || a.Upgrades[0].Findings != 2 ||
		!slices.Equal(a.Upgrades[0].Installed, []string{"4.17.20"}) || a.Upgrades[1].Path != "/srv/app.jar" || a.Upgrades[1].Version != "2.15.0" {
		t.Errorf("upgrades %+v", a.Upgrades)
	}
	if !slices.Contains(g.matched, "upgrades.cdx.json") {
		t.Errorf("the upgrade lines were not checked: %v", g.matched)
	}
	st := statuses(a)
	for id, want := range map[string]string{libsslO: Scanned, kernelO: Scanned, apiO: Scanned, oldO: Scanned, toolO: Unidentified,
		"appdir:/srv/shop": Scanned, "appdir:/srv/venv": Scanned, jarO: Scanned, imageO: Scanned, snapO: Unresolved} {
		if st[id] != want {
			t.Errorf("origin %s: %q, want %q", id, st[id], want)
		}
	}
	if len(a.Origins) != len(inv.Origins) {
		t.Errorf("%d origin results for %d origins", len(a.Origins), len(inv.Origins))
	}
	for _, o := range a.Origins {
		if o.Raw == nil {
			continue
		}
		for _, p := range []string{o.Raw.Grype, o.Raw.SBOM} {
			if fi, err := os.Stat(filepath.Join(runDir, p)); err != nil || fi.Mode().Perm() != 0o640 {
				t.Errorf("%s: %v %v", p, fi, err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(cache, "scan")); !os.IsNotExist(err) || len(g.copiesLeft) != 0 {
		t.Errorf("verified copies are removed after each scan: %v %q", err, g.copiesLeft)
	}

	// The cache holds stripped SBOMs, but none with Go modules.
	sboms, _ := filepath.Glob(filepath.Join(cache, "sbom", grype.Version, "*.cdx.json"))
	var kinds []string
	for _, p := range sboms {
		kinds = append(kinds, strings.SplitN(filepath.Base(p), "-", 2)[0])
		if data, _ := os.ReadFile(p); strings.Contains(string(data), "vulnerabilities") || strings.Contains(string(data), `"file"`) {
			t.Errorf("%s is not stripped: %s", p, data)
		}
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []string{"appdir", "binary", "image", "jar", "packages"}) { // the binary is the stripped one
		t.Errorf("cached SBOMs %v", kinds)
	}
	// A second run matches the cached SBOMs. It scans again only what has no lockfile, and the Go
	// binaries, whose matches depend on the code linked into them.
	g.catalogs = nil
	a2 := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	want = []string{"file:" + filepath.Join(cache, "scan", sumOf("go binary v1"), "api"), "file:" + filepath.Join(cache, "scan", sumOf("go binary v0"), "old"), "dir:" + filepath.Join(root, "srv/venv")}
	if slices.Sort(g.catalogs); !slices.Equal(g.catalogs, slices.Sorted(slices.Values(want))) || len(a2.Findings) != len(a.Findings) {
		t.Fatalf("second run scanned %q and found %d findings", g.catalogs, len(a2.Findings))
	}
}

func TestAuditChecksUpgradeLines(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.vulns["lodash@4.17.21"] = []grype.Vulnerability{vuln("GHSA-0000-0000-0000", "High", "fixed", "4.17.22")}
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if len(a.Upgrades) != 1 || a.Upgrades[0].Package != "org.apache.logging.log4j:log4j-core" || len(a.Warnings) != 0 {
		t.Fatalf("upgrades %+v, warnings %+v: lodash 4.17.21 is still vulnerable", a.Upgrades, a.Warnings)
	}
	g.matchErr = map[string]error{"upgrades.cdx.json": errors.New("Grype failed: boom")}
	a = Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if a.Status != Complete || len(a.Errors) != 0 || a.Upgrades == nil || len(a.Upgrades) != 0 || len(a.Warnings) != 1 || a.Warnings[0].Code != problem.UpgradeCheckFailed {
		t.Fatalf("audit %s, upgrades %+v, errors %+v, warnings %+v", a.Status, a.Upgrades, a.Errors, a.Warnings)
	}
}

// A binary in an app directory that Grype matched by its CPE gets a line only when matching its CPE
// at the version finds nothing: its purl alone never matches.
func TestAuditChecksUpgradeLinesByCPE(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	shop := "dir:" + filepath.Join(root, "srv/shop")
	g.sboms[shop] = append(g.sboms[shop], grype.Component{Name: "curl", Version: "7.80.0", PURL: "pkg:generic/curl@7.80.0"})
	g.cpes = map[string]string{"curl": "cpe:2.3:a:haxx:curl:7.80.0:*:*:*:*:*:*:*"}
	cve := vuln("CVE-2022-32221", "Critical", "fixed", "7.86.0")
	cve.Namespace = "nvd:cpe"
	g.vulns["cpe:2.3:a:haxx:curl:7.80.0:*:*:*:*:*:*:*"] = []grype.Vulnerability{cve}
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if f := byVuln(a)["CVE-2022-32221"]; !slices.Equal(f.Package.CPEs, []string{"cpe:2.3:a:haxx:curl:7.80.0:*:*:*:*:*:*:*"}) {
		t.Fatalf("finding %+v: it keeps the CPEs Grype reported", f)
	}
	if !slices.Contains(names(a.Upgrades), "curl 7.86.0") {
		t.Fatalf("upgrades %+v: no match for the CPE at 7.86.0", a.Upgrades)
	}
	g.vulns["cpe:2.3:a:haxx:curl:7.86.0:*:*:*:*:*:*:*"] = []grype.Vulnerability{vuln("CVE-2023-38545", "Critical", "fixed", "8.4.0")}
	a = Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if slices.Contains(names(a.Upgrades), "curl 7.86.0") || !slices.Contains(names(a.Upgrades), "lodash 4.17.21") {
		t.Fatalf("upgrades %+v: 7.86.0 is still vulnerable by its CPE", a.Upgrades)
	}
}

func TestAuditScansWhatAnSBOMCannotMatchEveryRun(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.osVersion = "" // as on Arch Linux, whose os-release has no VERSION_ID
	Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	g.catalogs = nil
	if a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv); len(a.Findings) != 8 || len(g.catalogs) != 8 { // every origin Grype scans
		t.Fatalf("second run: %d findings, scanned %q", len(a.Findings), g.catalogs)
	}
}

// cachedKinds lists the kinds of the cached SBOMs, such as appdir, sorted.
func cachedKinds(cache string) []string {
	sboms, _ := filepath.Glob(filepath.Join(cache, "sbom", grype.Version, "*.cdx.json"))
	var kinds []string
	for _, p := range sboms {
		kinds = append(kinds, strings.SplitN(filepath.Base(p), "-", 2)[0])
	}
	slices.Sort(kinds)
	return kinds
}

// An SBOM is cached only when matching it, as it would be cached, gives what scanning its origin
// gave: the same distribution and the same matches. Otherwise the origin is scanned every run.
// Either way the findings are the scan's, and a failed match fails nothing.
func TestAuditVerifiesSBOMsBeforeCaching(t *testing.T) {
	setuptools := grype.Match{Vulnerability: vuln("CVE-2026-5000", "High", "fixed", "40.0.0"),
		Artifact: grype.Artifact{Name: "setuptools", Version: "39.2.0", Type: "python"}}
	for _, tc := range []struct {
		name   string
		setup  func(*fakeScanner, *inventory.Inventory)
		cached []string
	}{
		// The package database's SBOM is compared as Grype wrote it, before the running kernel's
		// package is changed in it, as with the scan: the changed one matches otherwise.
		{"the same", func(*fakeScanner, *inventory.Inventory) {}, []string{"appdir", "binary", "image", "jar", "packages"}},
		{"another distribution", func(g *fakeScanner, _ *inventory.Inventory) {
			g.matching = func(r *grype.Report) { r.Distro = "archlinux" }
		}, nil},
		{"another distribution version", func(g *fakeScanner, _ *inventory.Inventory) {
			g.matching = func(r *grype.Report) { r.DistroVersion = "12" }
		}, nil},
		{"an extra match", func(g *fakeScanner, _ *inventory.Inventory) {
			g.matching = func(r *grype.Report) { r.Matches = append(r.Matches, setuptools) }
		}, nil},
		{"another fix version", func(g *fakeScanner, _ *inventory.Inventory) {
			g.matching = func(r *grype.Report) {
				for i := range r.Matches {
					if v := &r.Matches[i].Vulnerability; len(v.FixVersions) > 0 {
						v.FixVersions = []string{"0:" + v.FixVersions[0]}
					}
				}
			}
		}, []string{"binary", "image"}}, // the stripped binary has no matches, the image's no fix version
		{"a failed match", func(g *fakeScanner, inv *inventory.Inventory) {
			g.matchErr = map[string]error{packagesID + ".verify.cdx.json": errors.New("Grype timed out after 15m0s")}
			for _, o := range inv.Origins {
				g.matchErr[rawName(o.ID, ".verify.cdx.json")] = errors.New("Grype timed out after 15m0s")
			}
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, cache, inv := host(t)
			g := hostScanner(root, cache)
			tc.setup(g, inv)
			runDir := t.TempDir()
			a := Run(context.Background(), deps(root, cache, runDir, g, fakeKernel{}), inv)
			if a.Status != Complete || len(a.Errors) != 0 || len(a.Findings) != 8 {
				t.Fatalf("audit %s, errors %+v, %d findings", a.Status, a.Errors, len(a.Findings))
			}
			f := byVuln(a)
			if _, ok := f["CVE-2026-5000"]; ok || !slices.Equal(f["GHSA-35jh-r3h4-6jhm"].Fix.Versions, []string{"4.17.21"}) {
				t.Errorf("findings %+v: they are the scan's", a.Findings)
			}
			if got := cachedKinds(cache); !slices.Equal(got, tc.cached) {
				t.Errorf("cached SBOMs %v, want %v", got, tc.cached)
			}
			want := map[string]bool{}
			for _, o := range a.Origins {
				if o.Raw != nil {
					want[filepath.Base(o.Raw.Grype)], want[filepath.Base(o.Raw.SBOM)] = true, true
				}
			}
			if raw, _ := os.ReadDir(filepath.Join(runDir, "raw")); len(raw) != len(want) {
				t.Errorf("raw/ holds %v: the match's report is not the origin's", raw)
			}
			g.catalogs = nil
			Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
			if len(g.catalogs) != 8-len(tc.cached) {
				t.Errorf("second run scanned %q", g.catalogs)
			}
		})
	}
}

func TestAuditOriginFailuresArePartial(t *testing.T) {
	root, cache, inv := host(t)
	os.WriteFile(filepath.Join(root, "opt/api/api"), []byte("go binary v2"), 0o755) // upgraded since the inventory
	g := hostScanner(root, cache)
	g.catalogErr = map[string]error{"docker:": errors.New("Grype failed: could not fetch image")}
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if a.Status != Partial || len(a.Errors) != 2 {
		t.Fatalf("audit %s, errors %+v", a.Status, a.Errors)
	}
	for _, e := range a.Errors {
		if e.Code != problem.OriginScanFailed || e.Stage != "audit" {
			t.Errorf("error %+v", e)
		}
	}
	if !strings.Contains(a.Errors[0].Message, "/opt/api/api: cannot read the file that ran: the file changed since the inventory") ||
		!strings.Contains(a.Errors[1].Message, "image ghcr.io/acme/shop:2026.11.3: Grype failed: could not fetch image") {
		t.Errorf("messages %+v", a.Errors)
	}
	if st := statuses(a); st[apiO] != ScanFailed || st[imageO] != ScanFailed || st[libsslO] != Scanned {
		t.Errorf("statuses %v", st)
	}
}

// An image removed after the Inventory is never handed to Grype, for which the Docker daemon would
// try a pull from Docker Hub, nor matched from its cached SBOM.
func TestAuditImageRemovedSinceTheInventory(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	d := deps(root, cache, t.TempDir(), g, fakeKernel{})
	d.Images = fakeImages{ids: map[string]bool{"sha256:1111": true}}
	if a := Run(context.Background(), d, inv); statuses(a)[imageO] != Scanned {
		t.Fatalf("statuses %v", statuses(a))
	}
	for _, tc := range []struct {
		images fakeImages
		msg    string
	}{
		{fakeImages{}, "image ghcr.io/acme/shop:2026.11.3: the image was removed after the inventory"},
		{fakeImages{err: errors.New("dial unix /var/run/docker.sock: connect: connection refused")},
			"image ghcr.io/acme/shop:2026.11.3: cannot check that the Docker daemon still has the image: dial unix /var/run/docker.sock: connect: connection refused"},
	} {
		g.catalogs, g.matched = nil, nil
		d.Images, d.RunDir = tc.images, t.TempDir()
		a := Run(context.Background(), d, inv)
		if statuses(a)[imageO] != ScanFailed || a.Status != Partial || len(a.Errors) != 1 || a.Errors[0].Message != tc.msg {
			t.Fatalf("audit %s, statuses %v, errors %+v", a.Status, statuses(a), a.Errors)
		}
		if slices.Contains(g.matched, keyOf("image", "sha256:1111")+".cdx.json") || slices.Contains(g.catalogs, "docker:sha256:1111") {
			t.Fatalf("Grype was asked: scanned %q, matched %q", g.catalogs, g.matched)
		}
		os.RemoveAll(filepath.Join(cache, "sbom")) // the next one would catalog the image
	}
}

func TestAuditPackageScanFailure(t *testing.T) {
	root, cache, inv := host(t)
	os.Remove(filepath.Join(root, "var/lib/dpkg/status"))
	a := Run(context.Background(), deps(root, cache, t.TempDir(), hostScanner(root, cache), fakeKernel{}), inv)
	if a.Status != Partial || len(a.Errors) != 1 || !strings.HasPrefix(a.Errors[0].Message, "packages: the installed packages: no package database was found") {
		t.Fatalf("audit %s, errors %+v", a.Status, a.Errors)
	}
	if st := statuses(a); st[libsslO] != ScanFailed || st[kernelO] != ScanFailed || st[apiO] != Scanned {
		t.Errorf("statuses %v", st)
	}
}

// The kernel package was upgraded in place, under the same name, after the Inventory: only the
// kernel's origin fails, and the other packages are audited. The package database is scanned
// first, which keeps that window short.
func TestAuditKernelPackageUpgradedSinceTheInventory(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	staging := "dir:" + filepath.Join(cache, "staging")
	comps := slices.Clone(g.sboms[staging])
	comps[1].Version = "6.1.124-1"
	comps[1].PURL = "pkg:deb/debian/linux-image-6.1.0-28-amd64@6.1.124-1?arch=amd64&distro=debian-12"
	g.sboms[staging] = comps
	for range 2 { // cataloged, then matched from the cached SBOM
		a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
		st := statuses(a)
		if st[libsslO] != Scanned || st[kernelO] != ScanFailed || a.Status != Partial || len(a.Errors) != 1 ||
			!strings.Contains(a.Errors[0].Message, "the kernel package linux-image-6.1.0-28-amd64 6.1.123-1 changed since the inventory") {
			t.Fatalf("audit %s, statuses %v, errors %+v", a.Status, st, a.Errors)
		}
		if f := byVuln(a)["CVE-2026-1234"]; f.Origin != libsslO {
			t.Fatalf("libssl3 is audited: %+v", a.Findings)
		}
	}
	if g.catalogs[0] != staging {
		t.Errorf("scanned %q: the package database comes first", g.catalogs)
	}
}

func TestAuditCannotMatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		g    func(*fakeScanner)
		code string
		msg  string
	}{
		{"no Grype", func(g *fakeScanner) { g.prepareErr = errors.New("download Grype 0.121.2: no network") }, problem.GrypeUnavailable, "no network"},
		{"invalid database", func(g *fakeScanner) { g.status.Valid = false }, problem.GrypeUnavailable, "not valid"},
		{"stale database", func(g *fakeScanner) {
			g.status.Built = now.Add(-73 * time.Hour)
			g.updateErr = errors.New("dial tcp: no route to host")
		}, problem.DBStale, "built 73 hours ago, which is older than audit.maxDatabaseAgeHours (48); updating it failed: dial tcp: no route to host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, cache, inv := host(t)
			g := hostScanner(root, cache)
			tc.g(g)
			a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
			if a.Status != Failed || len(a.Errors) != 1 || a.Errors[0].Code != tc.code || !strings.Contains(a.Errors[0].Message, tc.msg) || len(a.Findings) != 0 {
				t.Fatalf("audit %+v", a)
			}
			if st := statuses(a); st[snapO] != Unresolved || st[libsslO] != ScanFailed || len(st) != len(inv.Origins) {
				t.Fatalf("statuses %v", st)
			}
			if len(g.catalogs) != 0 {
				t.Fatalf("cataloged %v", g.catalogs)
			}
		})
	}
}

func TestAuditFreshDatabaseAfterAFailedUpdate(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.updateErr = errors.New("dial tcp: no route to host")
	g.status.Built = now.Add(-47 * time.Hour)
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if a.Status != Complete || len(a.Warnings) != 1 || a.Warnings[0].Code != problem.DBUpdateFailed || !strings.Contains(a.Warnings[0].Message, "no route to host") {
		t.Fatalf("audit %s %+v %+v", a.Status, a.Errors, a.Warnings)
	}
}

func TestAuditUnknownDistribution(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.distro = "" // Grype did not recognise the os-release
	image := "docker:sha256:1111"
	g.sboms[image] = append(g.sboms[image], grype.Component{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"})
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	for _, o := range a.Origins {
		if (o.Kind == inventory.OriginPackage || o.ID == imageO) && (o.Status != Unidentified || !strings.Contains(o.Reason, "did not recognise the distribution")) {
			t.Errorf("origin %+v: a scan without a distribution is a gap, never clean", o)
		}
	}
	if o := a.Origins[slices.IndexFunc(a.Origins, func(o OriginResult) bool { return o.ID == imageO })]; o.Packages != 2 || !strings.Contains(o.Reason, "its 1 operating system packages") {
		t.Errorf("image %+v", o)
	}
	if !slices.ContainsFunc(a.Findings, func(f Finding) bool { return f.Origin == imageO && f.Package.Name == "lodash" }) {
		t.Error("the image's language packages are matched all the same")
	}
	if st := statuses(a); st[jarO] != Scanned || st[apiO] != Scanned || a.Status != Complete {
		t.Errorf("audit %s, statuses %v: origins without operating system packages are scanned", a.Status, st)
	}
}

// Syft 1.57 reads Gentoo's packages as type portage and the Nix store's as type nix.
func TestAuditUnknownDistributionGentooAndNix(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.distro = ""
	g.sboms["docker:sha256:1111"] = []grype.Component{
		{Name: "dev-libs/openssl", Version: "3.0.0", PURL: "pkg:ebuild/dev-libs%2Fopenssl@3.0.0"},
		{Name: "zlib", Version: "1.2.11", PURL: "pkg:nix/zlib@1.2.11?outputhash=0c9qkzwg8a6d7k2a1rv4n8slf6drrhdm"},
	}
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if o := a.Origins[slices.IndexFunc(a.Origins, func(o OriginResult) bool { return o.ID == imageO })]; o.Status != Unidentified || !strings.Contains(o.Reason, "its 2 operating system packages") {
		t.Errorf("image %+v: a scan without a distribution is a gap, never clean", o)
	}
}

func TestAuditHealsBrokenCacheEntries(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	first := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	entries, _ := filepath.Glob(filepath.Join(cache, "sbom", grype.Version, "*.cdx.json"))
	for _, e := range entries {
		os.WriteFile(e, nil, 0o600) // as a power loss can leave them
	}
	g.catalogs = nil
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if a.Status != Complete || len(a.Findings) != len(first.Findings) || len(g.catalogs) != 8 {
		t.Fatalf("audit %s, %d findings, scanned %q", a.Status, len(a.Findings), g.catalogs)
	}
	g.catalogs = nil
	Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if len(g.catalogs) != 3 {
		t.Fatalf("the rebuilt entries are not used: scanned %q", g.catalogs)
	}
}

// Copies of jars and binaries used to be named by their SHA-256 alone, so Syft found nothing in
// a jar or in a binary it identifies by name, and the empty SBOMs were cached. They are never
// used, and age out of the cache.
func TestAuditDoesNotUseSBOMsCachedWithoutTheFileName(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	g.sboms["file:"+filepath.Join(cache, "scan", sumOf("stripped"), "tool")] = []grype.Component{{Name: "python", Version: "3.12.0", PURL: "pkg:generic/python@3.12.0"}}
	g.vulns["python@3.12.0"] = []grype.Vulnerability{vuln("CVE-2026-4000", "High", "fixed", "3.12.9")}
	var old []string
	for _, key := range []string{"jar-" + sumOf("jar v1"), "binary-" + sumOf("stripped")} {
		p := filepath.Join(cache, "sbom", grype.Version, key+".cdx.json")
		write(t, p, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)
		os.Chtimes(p, now.Add(-8*24*time.Hour), now.Add(-8*24*time.Hour))
		old = append(old, p)
	}
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	f := byVuln(a)
	if st := statuses(a); st[jarO] != Scanned || st[toolO] != Scanned || f["CVE-2021-44228"].Origin != jarO || f["CVE-2026-4000"].Origin != toolO {
		t.Fatalf("statuses %v: an empty SBOM cached under the old key was used", st)
	}
	for _, p := range old {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// A cached SBOM is dropped only when it is at fault: a disk-full run folder, a Grype timeout or
// an interruption never wipes the cache.
func TestAuditDropsCachedSBOMsOnlyWhenTheyAreAtFault(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	entries, _ := filepath.Glob(filepath.Join(cache, "sbom", grype.Version, "*.cdx.json"))
	if len(entries) != 5 {
		t.Fatalf("cached %v", entries)
	}
	kept := func(when string) {
		t.Helper()
		for _, e := range entries {
			if _, err := os.Stat(e); err != nil {
				t.Errorf("%s: %v", when, err)
			}
		}
	}
	timeout := errors.New("Grype timed out after 15m0s")
	g.matchErr = map[string]error{"packages-match.cdx.json": timeout}
	for _, e := range entries {
		g.matchErr[filepath.Base(e)] = timeout
	}
	g.catalogs = nil
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if a.Status != Partial || len(g.catalogs) != 3 { // the Go binaries and the app directory without a lockfile
		t.Fatalf("audit %s, scanned %q: a cached SBOM that timed out is scanned again", a.Status, g.catalogs)
	}
	kept("after a timeout")

	g.matchErr, g.catalogs = nil, nil
	runDir := t.TempDir()
	os.MkdirAll(filepath.Join(runDir, "raw", rawName(imageO, ".cdx.json")), 0o750) // the SBOM's copy cannot be written
	a = Run(context.Background(), deps(root, cache, runDir, g, fakeKernel{}), inv)
	if st := statuses(a); st[imageO] != ScanFailed || slices.Contains(g.catalogs, "docker:sha256:1111") {
		t.Fatalf("statuses %v, scanned %q", st, g.catalogs)
	}
	kept("after a run folder failure")

	g.matchErr, g.catalogs = map[string]error{}, nil
	for _, e := range entries {
		g.matchErr[filepath.Base(e)] = errors.New("Grype failed: [0002] ERROR failed to catalog: unable to decode sbom: sbom format not recognized")
	}
	a = Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if a.Status != Complete || len(g.catalogs) != 7 { // the package database's is matched as packages-match.cdx.json
		t.Fatalf("audit %s, scanned %q: an SBOM Grype rejects is cataloged again", a.Status, g.catalogs)
	}
}

func TestAuditAppDirCachedOnlyFromItsOwnLockfiles(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	shop := "dir:" + filepath.Join(root, "srv/shop")
	g.sboms[shop] = append(g.sboms[shop], grype.Component{Name: "minimist", Version: "1.2.5", PURL: "pkg:npm/minimist@1.2.5"})
	for _, where := range []string{"/worker/package-lock.json", ""} { // a nested app the key does not hash; no file at all
		g.locations["minimist"] = where
		if where == "" {
			delete(g.locations, "minimist")
		}
		os.RemoveAll(filepath.Join(cache, "sbom"))
		Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
		g.catalogs = nil
		Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
		if !slices.Contains(g.catalogs, shop) {
			t.Fatalf("minimist at %q: the app directory was matched from a cached SBOM: %q", where, g.catalogs)
		}
	}
}

// A package source added anywhere below an app directory after its SBOM was cached, such as a
// nested lockfile, is scanned at the next run.
func TestAuditAppDirNewPackageSource(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	write(t, filepath.Join(root, "srv/shop/worker/package-lock.json"), `{"lockfileVersion":3}`)
	g.catalogs = nil
	Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if shop := "dir:" + filepath.Join(root, "srv/shop"); !slices.Contains(g.catalogs, shop) {
		t.Fatalf("scanned %q: the app directory was matched from its cached SBOM", g.catalogs)
	}
}

// An app directory whose lockfile changed while Grype read it is not cached: the SBOM may be of
// the new lockfile, and the key of the old one, to which an app's owner could change it back.
func TestAuditAppDirChangedDuringTheScan(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	shop := "dir:" + filepath.Join(root, "srv/shop")
	g.scanning = func(source string) {
		if source == shop {
			write(t, filepath.Join(root, "srv/shop/package-lock.json"), `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`)
		}
	}
	Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if kinds := cachedKinds(cache); slices.Contains(kinds, "appdir") {
		t.Fatalf("cached %v", kinds)
	}
	g.scanning = nil
	Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if kinds := cachedKinds(cache); !slices.Contains(kinds, "appdir") {
		t.Fatalf("cached %v: an app directory that holds still is cached", kinds)
	}
}

// Every app directory is cataloged at least once per UTC day.
func TestAuditAppDirEachDay(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	d := deps(root, cache, t.TempDir(), g, fakeKernel{})
	Run(context.Background(), d, inv)
	for _, tc := range []struct {
		at      time.Time
		scanned bool
	}{
		{time.Date(2026, 11, 15, 0, 30, 0, 0, time.FixedZone("CET", 3600)), false}, // 23:30 UTC
		{now.Add(24 * time.Hour), true},
	} {
		g.catalogs = nil
		d.Now, d.RunDir = func() time.Time { return tc.at }, t.TempDir()
		Run(context.Background(), d, inv)
		if shop := "dir:" + filepath.Join(root, "srv/shop"); slices.Contains(g.catalogs, shop) != tc.scanned {
			t.Errorf("at %s scanned %q", tc.at, g.catalogs)
		}
	}
}

func TestAuditReadsBinariesThroughTheProcess(t *testing.T) {
	// A service with PrivateTmp extracted a native library into its own /tmp, and runs an
	// executable from it: the host's /tmp has neither.
	root, cache, inv := host(t)
	running := files(t, map[string]string{"lib": "netty v1", "exe": "tool v1"})
	libO := inventory.BinaryOriginID(sumOf("netty v1"))
	exeO := inventory.BinaryOriginID(sumOf("tool v1"))
	inv.Items = append(inv.Items, inventory.Item{ID: "proc:java", Kind: inventory.KindProcess, Name: "tool", Exe: "/tmp/tool",
		Processes: []inventory.Process{{PID: 42}}, Origins: []string{libO, exeO}})
	inv.Origins = append(inv.Origins,
		inventory.Origin{ID: libO, Kind: inventory.OriginBinary, SHA256: sumOf("netty v1"), Paths: []string{"/tmp/libnetty.so"}},
		inventory.Origin{ID: exeO, Kind: inventory.OriginBinary, SHA256: sumOf("tool v1"), Paths: []string{"/tmp/tool"}})
	g := hostScanner(root, cache)
	g.sboms["file:"+filepath.Join(cache, "scan", sumOf("netty v1"), "libnetty.so")] = []grype.Component{{Name: "netty", Version: "4.1.0", PURL: "pkg:maven/io.netty/netty@4.1.0"}}
	g.sboms["file:"+filepath.Join(cache, "scan", sumOf("tool v1"), "tool")] = []grype.Component{{Name: "tool", Version: "1", PURL: "pkg:generic/tool@1"}}
	d := deps(root, cache, t.TempDir(), g, fakeKernel{})
	d.Proc = fakeProc{exes: map[int]string{42: filepath.Join(running, "exe")},
		maps:   map[int][]procfs.Mapping{42: {{Start: "1000", End: "2000", Path: "/tmp/libnetty.so"}}},
		mapped: map[string]string{"/tmp/libnetty.so": filepath.Join(running, "lib")}}
	a := Run(context.Background(), d, inv)
	if st := statuses(a); st[libO] != Scanned || st[exeO] != Scanned || a.Status != Complete {
		t.Fatalf("audit %s %+v: %v", a.Status, a.Errors, st)
	}
}

// A library replaced on disk after the Inventory is still mapped, as deleted, by the process: its
// map_files entry holds the content the Inventory identified.
func TestAuditReadsDeletedMappings(t *testing.T) {
	root, cache, inv := host(t)
	running := files(t, map[string]string{"lib": "netty v1"})
	libO := inventory.BinaryOriginID(sumOf("netty v1"))
	inv.Items = append(inv.Items, inventory.Item{ID: "proc:java2", Kind: inventory.KindProcess, Name: "java", Exe: "/usr/bin/java",
		Processes: []inventory.Process{{PID: 42}}, Origins: []string{libO}})
	inv.Origins = append(inv.Origins, inventory.Origin{ID: libO, Kind: inventory.OriginBinary, SHA256: sumOf("netty v1"), Paths: []string{"/opt/lib/libnetty.so"}})
	g := hostScanner(root, cache)
	g.sboms["file:"+filepath.Join(cache, "scan", sumOf("netty v1"), "libnetty.so")] = []grype.Component{{Name: "netty", Version: "4.1.0", PURL: "pkg:maven/io.netty/netty@4.1.0"}}
	d := deps(root, cache, t.TempDir(), g, fakeKernel{})
	d.Proc = fakeProc{maps: map[int][]procfs.Mapping{42: {{Start: "1000", End: "2000", Path: "/opt/lib/libnetty.so", Deleted: true}}},
		mapped: map[string]string{"/opt/lib/libnetty.so": filepath.Join(running, "lib")}}
	a := Run(context.Background(), d, inv)
	if st := statuses(a); st[libO] != Scanned || a.Status != Complete {
		t.Fatalf("audit %s %+v: %v", a.Status, a.Errors, st)
	}
}

func TestAuditKernelVersionThatDoesNotParse(t *testing.T) {
	up := inventory.KernelUpstreamOriginID("5.15.0-91-generic~custom")
	inv := &inventory.Inventory{
		Items:   []inventory.Item{{ID: "kernel", Kind: inventory.KindKernel, Origins: []string{up}}},
		Origins: []inventory.Origin{{ID: up, Kind: inventory.OriginKernelUpstream, UpstreamVersion: "5.15.0-91-generic~custom"}},
	}
	d := deps(files(t, map[string]string{"etc/os-release": "ID=arch\n"}), t.TempDir(), t.TempDir(), &fakeScanner{status: grype.DBStatus{Built: built, Valid: true}}, fakeKernel{data: kernelTestData(t)})
	d.Family = osrel.Arch
	if a := Run(context.Background(), d, inv); a.Status != Partial || statuses(a)[up] != ScanFailed {
		t.Fatalf("audit %+v: a kernel that cannot be matched is never clean", a)
	}
}

func TestAuditRPMEpochAndArchitecture(t *testing.T) {
	root := files(t, map[string]string{"etc/os-release": "ID=rocky\n", "var/lib/rpm/rpmdb.sqlite": "db"})
	cache := t.TempDir()
	rocky := inventory.Distro{ID: "rocky", VersionID: "9.5", Family: "rhel"}
	bind := pkgtool.Package{Name: "bind-libs", Version: "9.16.23-24.el9_5", Epoch: "32", Arch: "x86_64", Type: "rpm"}
	glibc := pkgtool.Package{Name: "glibc", Version: "2.34-125.el9_5.1", Arch: "x86_64", Type: "rpm"}
	inv := &inventory.Inventory{
		Items: []inventory.Item{{ID: "proc:named", Kind: inventory.KindProcess, Name: "named", Origins: []string{inventory.PackageOriginID(rocky, bind), inventory.PackageOriginID(rocky, glibc)}}},
		Origins: []inventory.Origin{
			{ID: inventory.PackageOriginID(rocky, bind), Kind: inventory.OriginPackage, Name: bind.Name, Version: bind.Version, Epoch: "32", Arch: "x86_64"},
			{ID: inventory.PackageOriginID(rocky, glibc), Kind: inventory.OriginPackage, Name: glibc.Name, Version: glibc.Version, Arch: "x86_64"},
		},
	}
	g := &fakeScanner{
		status: grype.DBStatus{Built: built, Valid: true}, osVersion: "9.5", distro: "rockylinux",
		sboms: map[string][]grype.Component{"dir:" + filepath.Join(cache, "staging"): {
			{Name: "bind-libs", Version: "32:9.16.23-24.el9_5", PURL: "pkg:rpm/rocky/bind-libs@9.16.23-24.el9_5?arch=x86_64&epoch=32&distro=rocky-9.5"},
			{Name: "glibc", Version: "2.34-125.el9_5.1", PURL: "pkg:rpm/rocky/glibc@2.34-125.el9_5.1?arch=x86_64&distro=rocky-9.5"},
			{Name: "glibc", Version: "2.34-125.el9_5.1", PURL: "pkg:rpm/rocky/glibc@2.34-125.el9_5.1?arch=i686&distro=rocky-9.5"},
		}},
		vulns: map[string][]grype.Vulnerability{
			"bind-libs@32:9.16.23-24.el9_5": {vuln("CVE-2025-40775", "High", "fixed", "32:9.16.23-29.el9_6")},
			"glibc@2.34-125.el9_5.1":        {vuln("CVE-2025-4802", "High", "fixed", "0:2.34-168.el9_6.14")},
		},
	}
	d := deps(root, cache, t.TempDir(), g, fakeKernel{})
	d.Family = osrel.RHEL
	a := Run(context.Background(), d, inv)
	if len(a.Findings) != 2 {
		t.Fatalf("findings %+v: one per package, and none for the i686 glibc that does not run", a.Findings)
	}
	for _, o := range a.Origins {
		if o.Packages != 1 || o.Status != Scanned {
			t.Errorf("origin %+v", o)
		}
	}
}

func TestAuditDebianKernelByUpstreamVersion(t *testing.T) {
	// A third-party kernel on Debian, or Debian in a container: the kernel is matched by its
	// upstream version, so no package is rewritten.
	root, cache, inv := host(t)
	up := inventory.KernelUpstreamOriginID("7.3.3")
	inv.Items[0].Origins = []string{up}
	inv.Origins[0] = inventory.Origin{ID: up, Kind: inventory.OriginKernelUpstream, UpstreamVersion: "7.3.3"}
	g := hostScanner(root, cache)
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{data: kernelTestData(t)}), inv)
	if a.Status != Complete || len(a.Errors) != 0 {
		t.Fatalf("audit %s %+v", a.Status, a.Errors)
	}
	if _, ok := byVuln(a)["CVE-2026-2999"]; ok {
		t.Fatal("the installed kernel package does not run, so it has no findings")
	}
}

func TestAuditKernelDataStale(t *testing.T) {
	up := inventory.KernelUpstreamOriginID("7.3.3")
	root := files(t, map[string]string{"etc/os-release": "ID=cachyos\n"})
	inv := &inventory.Inventory{
		Items:   []inventory.Item{{ID: "kernel", Kind: inventory.KindKernel, Origins: []string{up}}},
		Origins: []inventory.Origin{{ID: up, Kind: inventory.OriginKernelUpstream, UpstreamVersion: "7.3.3"}},
	}
	g := &fakeScanner{status: grype.DBStatus{Built: built, Valid: true}}
	d := deps(root, t.TempDir(), t.TempDir(), g, fakeKernel{err: errors.New("the kernel CNA data is 50 hours old, and fetching it failed: 503 Service Unavailable")})
	d.Family = osrel.Arch
	a := Run(context.Background(), d, inv)
	if a.Status != Partial || len(a.Errors) != 1 || a.Errors[0].Code != problem.KernelDataStale || !strings.Contains(a.Errors[0].Message, "503") {
		t.Fatalf("audit %+v", a)
	}
	if st := statuses(a); st[up] != ScanFailed {
		t.Fatalf("statuses %v", st)
	}
}

func TestAuditInterrupted(t *testing.T) {
	root, cache, inv := host(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := Run(ctx, deps(root, cache, t.TempDir(), hostScanner(root, cache), fakeKernel{}), inv)
	if a.Status == Complete || len(a.Errors) != 1 || a.Errors[0].Code != problem.Interrupted {
		t.Fatalf("audit %s %+v: an interrupted audit never reads as complete, and is no scan failure", a.Status, a.Errors)
	}
	if st := statuses(a); len(st) != len(inv.Origins) || st[libsslO] != ScanFailed || st[snapO] != Unresolved {
		t.Fatalf("statuses %v: every origin is listed, and a gap stays a gap", st)
	}
	// Interrupted while Grype is prepared: not GRYPE_UNAVAILABLE either.
	g := hostScanner(root, cache)
	g.prepareErr = context.Canceled
	if a := Run(ctx, deps(root, cache, t.TempDir(), g, fakeKernel{}), inv); a.Errors[0].Code != problem.Interrupted || a.Status != Failed {
		t.Fatalf("audit %s %+v", a.Status, a.Errors)
	}
}

// Interrupted while the origins are scanned: what was found is sorted as ever, and no upgrade line
// is checked with Grype or given.
func TestAuditInterruptedWhileScanning(t *testing.T) {
	for _, tc := range []struct{ name, at string }{
		{"in the middle", "/app.jar"},
		{"at the last origin", "docker:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, cache, inv := host(t)
			inv.Origins = slices.DeleteFunc(inv.Origins, func(o inventory.Origin) bool { return o.ID == snapO }) // the image is the last
			g := hostScanner(root, cache)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g.scanning = func(source string) {
				if strings.Contains(source, tc.at) {
					cancel()
				}
			}
			a := Run(ctx, deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
			byRisk := func(x, y Finding) int { return cmp.Compare(slices.Index(Tiers, x.Risk), slices.Index(Tiers, y.Risk)) }
			if len(a.Findings) < 2 || !slices.IsSortedFunc(a.Findings, byRisk) || !slices.IsSortedFunc(a.Origins, func(x, y OriginResult) int { return cmp.Compare(x.ID, y.ID) }) {
				t.Errorf("findings %+v: not sorted", a.Findings)
			}
			if a.Upgrades == nil || len(a.Upgrades) != 0 || len(a.Warnings) != 0 || slices.Contains(g.matched, "upgrades.cdx.json") {
				t.Errorf("upgrades %+v, warnings %+v, matched %v", a.Upgrades, a.Warnings, g.matched)
			}
			if len(a.Errors) != 1 || a.Errors[0].Code != problem.Interrupted || len(a.Origins) != len(inv.Origins) || statuses(a)[imageO] != ScanFailed {
				t.Errorf("errors %+v, statuses %v", a.Errors, statuses(a))
			}
		})
	}
}

// Grype lists a package's locations in another order when it matches the cached SBOM than when it
// scans, as for every package of a Debian image: the findings keep their IDs.
func TestAuditFindingIDsDoNotDependOnLocationOrder(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	image := "docker:sha256:1111"
	g.sboms[image] = append(g.sboms[image], grype.Component{Name: "setuptools", Version: "39.2.0", PURL: "pkg:pypi/setuptools@39.2.0"})
	g.vulns["setuptools@39.2.0"] = []grype.Vulnerability{vuln("GHSA-r9hx-vwmv-q579", "High", "fixed", "65.5.1")}
	dist := "/usr/lib/python3.6/site-packages/setuptools-39.2.0.dist-info/"
	g.found = map[string][]string{
		"zlib1g":     {"/var/lib/dpkg/status", "/usr/share/doc/zlib1g/copyright", "/var/lib/dpkg/info/zlib1g:amd64.md5sums"},
		"setuptools": {dist + "top_level.txt", dist + "METADATA", dist + "RECORD"},
	}
	g.matching = func(r *grype.Report) { // as Grype 0.121.2 lists them for an SBOM: sorted
		for i := range r.Matches {
			slices.Sort(r.Matches[i].Artifact.Locations)
		}
	}
	locations := func(a *Audit) map[string]string {
		m := map[string]string{}
		for _, f := range a.Findings {
			if f.Origin == imageO {
				m[f.ID] = f.Package.Location
			}
		}
		return m
	}
	first := locations(Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv))
	g.catalogs = nil
	second := locations(Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv))
	if slices.Contains(g.catalogs, image) {
		t.Fatalf("the image was scanned again: %q", g.catalogs)
	}
	want := []string{"/var/lib/dpkg/status", dist + "METADATA"}
	if got := slices.Sorted(maps.Values(first)); !maps.Equal(first, second) || !slices.Equal(got, slices.Sorted(slices.Values(want))) {
		t.Fatalf("first run %v, second run %v: the package database, else the first path in sort order", first, second)
	}
}

// Grype can report a vulnerability of a package twice, such as by two matchers: it is one finding.
func TestAuditOneFindingPerID(t *testing.T) {
	root, cache, inv := host(t)
	g := hostScanner(root, cache)
	l := g.vulns["lodash@4.17.20"]
	g.vulns["lodash@4.17.20"] = append(l, l...)
	a := Run(context.Background(), deps(root, cache, t.TempDir(), g, fakeKernel{}), inv)
	if n := len(slices.DeleteFunc(slices.Clone(a.Findings), func(f Finding) bool { return f.Package.Name != "lodash" })); n != 2 {
		t.Fatalf("%d lodash findings for its 2 vulnerabilities", n)
	}
}

func TestAuditRunFolderUnwritable(t *testing.T) {
	root, cache, inv := host(t)
	runDir := filepath.Join(t.TempDir(), "run")
	write(t, runDir, "a file, not a folder")
	a := Run(context.Background(), deps(root, cache, runDir, hostScanner(root, cache), fakeKernel{}), inv)
	if a.Status != Failed || len(a.Errors) != 1 || a.Errors[0].Code != problem.RunFolderUnwritable || a.Errors[0].Stage != "" {
		t.Fatalf("audit %s %+v: a run folder error is of no stage (spec section 12)", a.Status, a.Errors)
	}
}

func kernelTestData(t *testing.T) *kernelcna.Data {
	t.Helper()
	paths, _ := filepath.Glob("../../testdata/kernelcna/cve/published/*/CVE-*.json")
	d := &kernelcna.Data{Commit: "84a53c896276bc79eb2c0b9864fc2a53afe270b8", Checked: now.Add(-time.Hour)}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		r, err := kernelcna.ParseRecord(data)
		if err != nil {
			t.Fatal(err)
		}
		d.Records = append(d.Records, r)
	}
	return d
}

func TestAuditKernelByUpstreamVersion(t *testing.T) {
	up := inventory.KernelUpstreamOriginID("6.1.119")
	root := files(t, map[string]string{"etc/os-release": "ID=arch\n"})
	inv := &inventory.Inventory{
		Items:   []inventory.Item{{ID: "kernel", Kind: inventory.KindKernel, RunningVersion: "6.1.119-1", Origins: []string{up}}},
		Origins: []inventory.Origin{{ID: up, Kind: inventory.OriginKernelUpstream, UpstreamVersion: "6.1.119"}},
	}
	kev := vuln("CVE-2026-100080", "High", "", "")
	kev.KnownExploited = true
	g := &fakeScanner{status: grype.DBStatus{Built: built, Valid: true}, lookups: map[string]grype.Vulnerability{"CVE-2026-100080": kev}}
	d := deps(root, t.TempDir(), t.TempDir(), g, fakeKernel{data: kernelTestData(t)})
	d.Family = osrel.Arch
	a := Run(context.Background(), d, inv)
	if a.Status != Complete || a.KernelData == nil || a.KernelData.Commit != "84a53c896276bc79eb2c0b9864fc2a53afe270b8" {
		t.Fatalf("audit %+v", a)
	}
	f := byVuln(a)
	if len(f) != 8 || len(g.lookedUp) != 8 {
		t.Fatalf("%d findings, %d looked up: the 8 records that affect 6.1.119", len(f), len(g.lookedUp))
	}
	k := f["CVE-2026-100080"]
	if k.Source != "kernel-cna" || k.Package.Name != "linux" || k.Package.Version != "6.1.119" || k.Risk != RiskCritical ||
		k.Fix.State != "fixed" || k.Fix.Versions[0] != "6.1.192" || k.Remediation != "Upgrade the kernel to Linux 6.1.192 or later (pacman -Syu), then reboot." {
		t.Errorf("finding %+v", k)
	}
	// Without the database's data, the CNA's own CVSS score gives the severity.
	if c := f["CVE-2025-40190"].Vulnerability; c.Severity != "High" || len(c.CVSS) != 1 || c.CVSS[0].Score != 7.8 {
		t.Errorf("CVE-2025-40190 %+v", c)
	}
	if c := f["CVE-2026-68086"].Vulnerability; c.Severity != "Unknown" || len(c.CVSS) != 0 {
		t.Errorf("CVE-2026-68086 has no score anywhere: %+v", c)
	}
	if st := statuses(a); st[up] != Scanned {
		t.Errorf("statuses %v", st)
	}
	g.lookupErr = errors.New("Grype failed: database locked")
	if a := Run(context.Background(), d, inv); a.Status != Partial || len(a.Findings) != 0 || a.Errors[0].Code != problem.OriginScanFailed {
		t.Fatalf("a failed lookup: %+v", a)
	}
}
