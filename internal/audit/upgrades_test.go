package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

func finding(origin, typ, pkg, version, state string, fixes ...string) Finding {
	return Finding{Origin: origin, Package: Package{Name: pkg, Version: version, Type: typ}, Fix: Fix{State: state, Versions: fixes}}
}

const shop = "appdir:/srv/shop"

func fixedIn(typ, pkg, version string, fixes ...string) Finding {
	return finding(shop, typ, pkg, version, "fixed", fixes...)
}

// withPURL gives a finding the purl Grype reported for its package.
func withPURL(f Finding, purl string) Finding {
	f.Package.PURL = purl
	return f
}

func TestUpgrades(t *testing.T) {
	up := func(pkg, typ, installed, version string, n int) Upgrade {
		return Upgrade{Origin: shop, Path: "/srv/shop", Package: pkg, Type: typ, Installed: []string{installed}, Version: version, Findings: n}
	}
	tests := []struct {
		name     string
		findings []Finding
		want     []Upgrade
	}{
		{
			// The real Grype 0.121.2 fix versions of lodash 4.17.20 (Shearbolt's npm-vulnerable fixture).
			name: "the highest fix version over all findings of a package",
			findings: []Finding{fixedIn("npm", "lodash", "4.17.20", "4.17.21"), fixedIn("npm", "lodash", "4.17.20", "4.17.21"),
				fixedIn("npm", "lodash", "4.17.20", "4.18.0"), fixedIn("npm", "lodash", "4.17.20", "4.17.23")},
			want: []Upgrade{up("lodash", "npm", "4.17.20", "4.18.0", 4)},
		},
		{
			name:     "a finding without a fix suppresses its package only",
			findings: []Finding{fixedIn("npm", "lodash", "4.17.20", "4.17.21"), finding(shop, "npm", "lodash", "4.17.20", "not-fixed"), fixedIn("npm", "minimist", "1.2.5", "1.2.6")},
			want:     []Upgrade{up("minimist", "npm", "1.2.5", "1.2.6", 1)},
		},
		{
			name:     "fixed without a fix version suppresses the package",
			findings: []Finding{fixedIn("npm", "a", "1.0.0", "1.0.1"), fixedIn("npm", "a", "1.0.0")},
		},
		{
			name:     "only app directories and jars get upgrade lines",
			findings: []Finding{finding("pkg:deb/debian/openssl@3.0.14-1~deb12u1?arch=amd64&distro=debian-12", "deb", "openssl", "3.0.14", "fixed", "3.0.15"), finding("binary:ab12", "go-module", "golang.org/x/net", "v0.1.0", "fixed", "v0.17.0"), finding("image:sha256:1", "npm", "a", "1.0.0", "fixed", "1.0.1")},
		},
		{
			name:     "any ecosystem with semver versions",
			findings: []Finding{fixedIn("python", "requests", "2.0.0", "2.31.0"), fixedIn("java-archive", "log4j-core", "2.14.1", "2.15.0", "2.16.0")},
			want:     []Upgrade{up("log4j-core", "java-archive", "2.14.1", "2.16.0", 1), up("requests", "python", "2.0.0", "2.31.0", 1)},
		},
		{
			name:     "numeric, not lexical",
			findings: []Finding{fixedIn("npm", "a", "4.8.0", "4.9.0"), fixedIn("npm", "a", "4.8.0", "4.10.0")},
			want:     []Upgrade{up("a", "npm", "4.8.0", "4.10.0", 2)},
		},
		{
			name:     "a version that is not semver suppresses the package",
			findings: []Finding{fixedIn("python", "django", "4.2", "4.2.1"), fixedIn("npm", "b", "1.0.0", "1.0.x")},
		},
		{
			name:     "the highest fix must be above every installed version",
			findings: []Finding{fixedIn("npm", "a", "1.0.0", "1.5.0"), fixedIn("npm", "a", "2.0.0", "1.5.0")},
		},
		{
			name:     "a highest fix with two spellings is ambiguous",
			findings: []Finding{fixedIn("npm", "a", "1.0.0", "1.0.1"), fixedIn("npm", "a", "1.0.0", "v1.0.1")},
		},
		{
			name:     "a release sorts above its pre-release",
			findings: []Finding{fixedIn("npm", "a", "0.9.0", "1.0.0-rc.1", "1.0.0")},
			want:     []Upgrade{up("a", "npm", "0.9.0", "1.0.0", 1)},
		},
		{
			name: "the same package in two app directories is two lines, sorted by count",
			findings: []Finding{finding("appdir:/srv/b", "npm", "a", "1.0.0", "fixed", "1.0.1"),
				finding("appdir:/srv/a.jar", "npm", "a", "1.0.0", "fixed", "1.0.2"), finding("appdir:/srv/a.jar", "npm", "a", "1.0.0", "fixed", "1.0.1")},
			want: []Upgrade{{Origin: "appdir:/srv/a.jar", Path: "/srv/a.jar", Package: "a", Type: "npm", Installed: []string{"1.0.0"}, Version: "1.0.2", Findings: 2},
				{Origin: "appdir:/srv/b", Path: "/srv/b", Package: "a", Type: "npm", Installed: []string{"1.0.0"}, Version: "1.0.1", Findings: 1}},
		},
		{
			// The real Grype 0.121.2 fix versions of lodash 3.10.1 and 4.17.20 in one app.
			name: "two installed versions are one line naming both, lowest first",
			findings: []Finding{withPURL(fixedIn("npm", "lodash", "4.17.20", "4.18.0"), "pkg:npm/lodash@4.17.20"),
				withPURL(fixedIn("npm", "lodash", "3.10.1", "4.17.21"), "pkg:npm/lodash@3.10.1"), withPURL(fixedIn("npm", "lodash", "4.17.20", "4.17.21"), "pkg:npm/lodash@4.17.20")},
			want: []Upgrade{{Origin: shop, Path: "/srv/shop", Package: "lodash", Type: "npm", Installed: []string{"3.10.1", "4.17.20"}, Version: "4.18.0", Findings: 3}},
		},
		{
			name:     "installed versions sort numerically",
			findings: []Finding{fixedIn("npm", "a", "10.0.0", "10.0.1"), fixedIn("npm", "a", "9.0.0", "9.0.1")},
			want:     []Upgrade{{Origin: shop, Path: "/srv/shop", Package: "a", Type: "npm", Installed: []string{"9.0.0", "10.0.0"}, Version: "10.0.1", Findings: 2}},
		},
		{
			name: "a Maven artifactId under two groupIds is two packages",
			findings: []Finding{withPURL(fixedIn("java-archive", "core", "1.0.0", "1.0.1"), "pkg:maven/org.a/core@1.0.0"),
				withPURL(fixedIn("java-archive", "core", "1.0.0", "2.0.0"), "pkg:maven/org.b/core@1.0.0")},
			want: []Upgrade{up("core", "java-archive", "1.0.0", "1.0.1", 1), up("core", "java-archive", "1.0.0", "2.0.0", 1)},
		},
		{
			name: "qualifiers and subpath do not split a package",
			findings: []Finding{withPURL(fixedIn("npm", "a", "1.0.0", "1.0.1"), "pkg:npm/a@1.0.0"),
				withPURL(fixedIn("npm", "a", "1.0.0", "1.0.2"), "pkg:npm/a@1.0.0?vcs_url=git%2Bhttps://x@y#lib")},
			want: []Upgrade{up("a", "npm", "1.0.0", "1.0.2", 2)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Upgrades(tc.findings); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestPURLVersion(t *testing.T) {
	tests := []struct{ purl, version, want, without string }{
		{"pkg:npm/lodash@4.17.20", "4.18.0", "pkg:npm/lodash@4.18.0", "pkg:npm/lodash"},
		{"pkg:npm/%40sveltejs/kit@1.0.0", "3.1.1", "pkg:npm/%40sveltejs/kit@3.1.1", "pkg:npm/%40sveltejs/kit"},
		{"pkg:maven/org.springframework.security/spring-security-core@6.0.0?type=jar", "6.1.8",
			"pkg:maven/org.springframework.security/spring-security-core@6.1.8?type=jar", "pkg:maven/org.springframework.security/spring-security-core"},
		{"pkg:npm/a@1.0.0#lib/x", "1.0.1", "pkg:npm/a@1.0.1#lib/x", "pkg:npm/a"},
		{"pkg:npm/a@1.0.0?vcs_url=git%2Bhttps://u@host/a.git#lib", "1.0.1", "pkg:npm/a@1.0.1?vcs_url=git%2Bhttps://u@host/a.git#lib", "pkg:npm/a"},
		{"pkg:golang/github.com/docker/docker@v20.10.7%2Bincompatible", "v28.0.0+incompatible",
			"pkg:golang/github.com/docker/docker@v28.0.0%2Bincompatible", "pkg:golang/github.com/docker/docker"},
		{"pkg:generic/a?x=1@2", "1.0.0", "", "pkg:generic/a"}, // no version
		{"", "1.0.0", "", ""},
	}
	for _, tc := range tests {
		got, ok := purlWithVersion(tc.purl, tc.version)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("purlWithVersion(%q, %q) = %q, %v; want %q", tc.purl, tc.version, got, ok, tc.want)
		}
		if got := purlWithoutVersion(tc.purl); got != tc.without {
			t.Errorf("purlWithoutVersion(%q) = %q, want %q", tc.purl, got, tc.without)
		}
	}
}

// checked runs checkUpgrades with g, and returns the lines and the warnings.
func checked(ctx context.Context, t *testing.T, g *fakeScanner, findings []Finding) ([]Upgrade, []problem.Problem, string) {
	t.Helper()
	au := &auditor{d: Deps{CacheDir: t.TempDir(), Grype: g}, a: &Audit{Warnings: []problem.Problem{}}}
	return au.checkUpgrades(ctx, upgradeCandidates(findings)), au.a.Warnings, au.scanDir()
}

func names(ups []Upgrade) []string {
	var out []string
	for _, u := range ups {
		out = append(out, u.Package+" "+u.Version)
	}
	return out
}

func TestCheckUpgrades(t *testing.T) {
	ctx := context.Background()
	lodash := []Finding{withPURL(fixedIn("npm", "lodash", "3.10.1", "4.17.21"), "pkg:npm/lodash@3.10.1"),
		withPURL(fixedIn("npm", "lodash", "4.17.20", "4.18.0"), "pkg:npm/lodash@4.17.20")}
	kit := withPURL(fixedIn("npm", "@sveltejs/kit", "1.0.0", "3.0.0"), "pkg:npm/%40sveltejs/kit@1.0.0")
	gone := vuln("GHSA-mw6w-2fmv-pvw3", "High", "fixed", "3.1.1")

	t.Run("kept when matching the version finds nothing", func(t *testing.T) {
		g := &fakeScanner{}
		ups, warns, dir := checked(ctx, t, g, append(lodash, kit))
		if !slices.Equal(names(ups), []string{"lodash 4.18.0", "@sveltejs/kit 3.0.0"}) || len(warns) != 0 || !slices.Equal(g.matched, []string{"upgrades.cdx.json"}) {
			t.Fatalf("lines %v, warnings %v, matched %v", names(ups), warns, g.matched)
		}
		data, err := os.ReadFile(filepath.Join(dir, "upgrades.cdx.json"))
		if err != nil {
			t.Fatal(err)
		}
		comps, err := grype.SBOMPackages(data)
		want := []grype.Component{{Name: "lodash", Version: "4.18.0", PURL: "pkg:npm/lodash@4.18.0"}, {Name: "@sveltejs/kit", Version: "3.0.0", PURL: "pkg:npm/%40sveltejs/kit@3.0.0"}}
		if err != nil || !slices.Equal(comps, want) {
			t.Fatalf("SBOM %v %v: one package per purl at the candidate version", comps, err)
		}
	})
	t.Run("dropped when the version still matches", func(t *testing.T) {
		g := &fakeScanner{vulns: map[string][]grype.Vulnerability{"pkg:npm/%40sveltejs/kit@3.0.0": {gone}}}
		if ups, warns, _ := checked(ctx, t, g, append(lodash, kit)); !slices.Equal(names(ups), []string{"lodash 4.18.0"}) || len(warns) != 0 {
			t.Fatalf("lines %v, warnings %v", names(ups), warns)
		}
	})
	t.Run("a match for a purl not in the SBOM drops the package", func(t *testing.T) {
		g := &fakeScanner{vulns: map[string][]grype.Vulnerability{"pkg:npm/%40sveltejs/kit@3.0.0": {gone}},
			purlAs: map[string]string{"pkg:npm/%40sveltejs/kit@3.0.0": "pkg:npm/@sveltejs/kit@3.0.0"}}
		if ups, _, _ := checked(ctx, t, g, append(lodash, kit)); !slices.Equal(names(ups), []string{"lodash 4.18.0"}) {
			t.Fatalf("lines %v", names(ups))
		}
	})
	t.Run("a Maven artifactId is checked per groupId", func(t *testing.T) {
		g := &fakeScanner{vulns: map[string][]grype.Vulnerability{"pkg:maven/org.a/core@2.0.0": {gone}}}
		ups, _, _ := checked(ctx, t, g, []Finding{withPURL(fixedIn("java-archive", "core", "1.0.0", "2.0.0"), "pkg:maven/org.a/core@1.0.0"),
			withPURL(fixedIn("java-archive", "core", "1.0.0", "2.0.0"), "pkg:maven/org.b/core@1.0.0")})
		if len(ups) != 1 || ups[0].Package != "core" {
			t.Fatalf("lines %+v", ups)
		}
	})
	t.Run("build metadata is percent-encoded in the purl", func(t *testing.T) {
		g := &fakeScanner{}
		_, _, dir := checked(ctx, t, g, []Finding{withPURL(fixedIn("go-module", "github.com/a/b", "v1.0.0+incompatible", "v2.0.0+incompatible"), "pkg:golang/github.com/a/b@v1.0.0%2Bincompatible")})
		data, _ := os.ReadFile(filepath.Join(dir, "upgrades.cdx.json"))
		comps, err := grype.SBOMPackages(data)
		if err != nil || len(comps) != 1 || comps[0].Version != "v2.0.0+incompatible" || comps[0].PURL != "pkg:golang/github.com/a/b@v2.0.0%2Bincompatible" {
			t.Fatalf("SBOM %v %v", comps, err)
		}
	})
	t.Run("dropped when it cannot be checked", func(t *testing.T) {
		cpe := fixedIn("binary", "node", "18.12.1", "18.20.4")
		cpe.Package.PURL, cpe.Source = "pkg:generic/node@18.12.1", "nvd:cpe" // the SBOM carries no CPE
		g := &fakeScanner{}
		if ups, warns, _ := checked(ctx, t, g, []Finding{fixedIn("npm", "a", "1.0.0", "1.0.1"), cpe}); len(ups) != 0 || len(warns) != 0 || len(g.matched) != 0 {
			t.Fatalf("lines %v, warnings %v, matched %v: a finding without a purl, or matched by CPE, cannot be checked", names(ups), warns, g.matched)
		}
		// A copy without a purl is told apart by its name, so it is a package of its own.
		ups, _, _ := checked(ctx, t, g, append(lodash, fixedIn("npm", "lodash", "4.17.19", "4.17.21")))
		if len(ups) != 1 || !slices.Equal(ups[0].Installed, []string{"3.10.1", "4.17.20"}) {
			t.Fatalf("lines %+v", ups)
		}
	})
	t.Run("no line when Grype fails", func(t *testing.T) {
		g := &fakeScanner{matchErr: map[string]error{"upgrades.cdx.json": errors.New("Grype failed: boom")}}
		ups, warns, _ := checked(ctx, t, g, lodash)
		if len(ups) != 0 || ups == nil || len(warns) != 1 || warns[0].Code != problem.UpgradeCheckFailed || warns[0].Kind != problem.Warning ||
			warns[0].Message != "the upgrade lines could not be checked with Grype, so none are given: Grype failed: boom" {
			t.Fatalf("lines %v, warnings %+v", ups, warns)
		}
	})
	t.Run("no line when the run is stopped", func(t *testing.T) {
		stopped, cancel := context.WithCancel(ctx)
		cancel()
		if ups, warns, _ := checked(stopped, t, &fakeScanner{}, lodash); len(ups) != 0 || len(warns) != 1 || warns[0].Code != problem.UpgradeCheckFailed {
			t.Fatalf("lines %v, warnings %+v", ups, warns)
		}
	})
}
