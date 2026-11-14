package audit

import (
	"slices"
	"testing"
)

func finding(origin, typ, pkg, version, state string, fixes ...string) Finding {
	return Finding{Origin: origin, Package: Package{Name: pkg, Version: version, Type: typ}, Fix: Fix{State: state, Versions: fixes}}
}

const shop = "appdir:/srv/shop"

func fixedIn(typ, pkg, version string, fixes ...string) Finding {
	return finding(shop, typ, pkg, version, "fixed", fixes...)
}

func TestUpgrades(t *testing.T) {
	up := func(pkg, typ, version string, n int) Upgrade {
		return Upgrade{Origin: shop, Path: "/srv/shop", Package: pkg, Type: typ, Version: version, Findings: n}
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
			want: []Upgrade{up("lodash", "npm", "4.18.0", 4)},
		},
		{
			name:     "a finding without a fix suppresses its package only",
			findings: []Finding{fixedIn("npm", "lodash", "4.17.20", "4.17.21"), finding(shop, "npm", "lodash", "4.17.20", "not-fixed"), fixedIn("npm", "minimist", "1.2.5", "1.2.6")},
			want:     []Upgrade{up("minimist", "npm", "1.2.6", 1)},
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
			want:     []Upgrade{up("log4j-core", "java-archive", "2.16.0", 1), up("requests", "python", "2.31.0", 1)},
		},
		{
			name:     "numeric, not lexical",
			findings: []Finding{fixedIn("npm", "a", "4.8.0", "4.9.0"), fixedIn("npm", "a", "4.8.0", "4.10.0")},
			want:     []Upgrade{up("a", "npm", "4.10.0", 2)},
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
			want:     []Upgrade{up("a", "npm", "1.0.0", 1)},
		},
		{
			name: "the same package in two app directories is two lines, sorted by count",
			findings: []Finding{finding("appdir:/srv/b", "npm", "a", "1.0.0", "fixed", "1.0.1"),
				finding("appdir:/srv/a.jar", "npm", "a", "1.0.0", "fixed", "1.0.2"), finding("appdir:/srv/a.jar", "npm", "a", "1.0.0", "fixed", "1.0.1")},
			want: []Upgrade{{Origin: "appdir:/srv/a.jar", Path: "/srv/a.jar", Package: "a", Type: "npm", Version: "1.0.2", Findings: 2},
				{Origin: "appdir:/srv/b", Path: "/srv/b", Package: "a", Type: "npm", Version: "1.0.1", Findings: 1}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Upgrades(tc.findings); !slices.Equal(got, tc.want) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}
