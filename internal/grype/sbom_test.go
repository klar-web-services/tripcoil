package grype

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestSBOMPackages(t *testing.T) {
	for _, c := range []struct {
		file        string
		n           int
		unmatchable bool
	}{{"debian12-staging.cdx.json", 88, false}, {"go-binary.cdx.json", 3, true}, {"stripped-c-binary.cdx.json", 0, false}, {"rocky9-packages.cdx.json", 3, false}} {
		pkgs, err := SBOMPackages(load(t, c.file))
		matchable, merr := Matchable(load(t, c.file))
		if err != nil || merr != nil || len(pkgs) != c.n || matchable == c.unmatchable {
			t.Errorf("%s: %d packages, matchable %v, %v %v", c.file, len(pkgs), matchable, err, merr)
		}
	}
	pkgs, _ := SBOMPackages(load(t, "rocky9-packages.cdx.json"))
	for _, p := range pkgs {
		if p.Name == "openssl-libs" && p.Version != "1:3.0.7-24.el9" {
			t.Errorf("an rpm epoch is part of the version: %+v", p)
		}
		if p.Type != "rpm" {
			t.Errorf("Syft's package type: %+v", p)
		}
	}
	// An Arch Linux SBOM: its operating system has no version, so matching the SBOM finds nothing.
	arch := `{"bomFormat":"CycloneDX","components":[{"type":"operating-system","name":"cachyos"},{"type":"library","name":"openssl","version":"4.1.0-1","purl":"pkg:alpm/cachyos/openssl@4.1.0-1"}]}`
	if ok, err := Matchable([]byte(arch)); ok || err != nil {
		t.Errorf("an SBOM without a distribution version is matchable: %v", err)
	}
	if _, err := SBOMPackages([]byte(`{"components": []}`)); err == nil {
		t.Fatal("a document that is not CycloneDX was accepted")
	}
}

// The package database's and images' SBOMs are read without their vulnerabilities, which repeat the
// report's matches: tens of thousands on hosts with Ubuntu's kernel headers. The rest is capped.
func TestReadSBOMReadsPastVulnerabilities(t *testing.T) {
	vuln := `{"bom-ref":"urn:uuid:1","id":"CVE-2026-1","description":"` + strings.Repeat("x", 5000) + `","affects":[{"ref":"pkg:deb/ubuntu/linux-modules"}]}`
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"file","name":"/stage"}},` +
		`"components":[{"type":"library","name":"linux-modules-5.15.0-131-generic","version":"5.15.0-131.141"}],` +
		`"vulnerabilities":[` + strings.Repeat(vuln+",", 199) + vuln + `],"dependencies":[{"ref":"a","dependsOn":["b"]}]}`
	path := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(path, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadSBOM(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal([]byte(sbom), &want)
	delete(want, "vulnerabilities")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("read %s", data)
	}
	if _, err := ReadSBOM(path, 200); err == nil || err.Error() != "Grype's SBOM is larger than 200 bytes without its vulnerabilities" {
		t.Errorf("above the cap: %v", err)
	}
	old := maxSystemReportSize
	maxSystemReportSize = 64 << 10
	defer func() { maxSystemReportSize = old }()
	if _, err := ReadSBOM(path, 4096); err == nil || err.Error() != "Grype's SBOM is larger than 65536 bytes" {
		t.Errorf("a file above the cap on the package database's and images' outputs: %v", err)
	}
	maxSystemReportSize = old
	for _, bad := range []string{`{"components":[}`, `{"components":[]} x`, `[]`, ``} {
		os.WriteFile(path, []byte(bad), 0o600)
		if _, err := ReadSBOM(path, 4096); err == nil {
			t.Errorf("%q read", bad)
		}
	}
}

func TestSBOMLocations(t *testing.T) {
	locs, err := SBOMLocations(load(t, "debian12-staging.cdx.json"))
	if err != nil || len(locs) != 88 {
		t.Fatalf("%d packages: %v", len(locs), err)
	}
	for _, l := range locs {
		if len(l) != 1 || l[0] != "/var/lib/dpkg/status" {
			t.Fatalf("locations %v", l)
		}
	}
	if locs, err := SBOMLocations(load(t, "stripped-c-binary.cdx.json")); err != nil || len(locs) != 0 {
		t.Fatalf("%v %v", locs, err)
	}
}

func TestStripSBOM(t *testing.T) {
	data := load(t, "debian12-staging.cdx.json")
	var doc map[string]any
	json.Unmarshal(data, &doc)
	doc["vulnerabilities"] = []any{map[string]any{"id": "CVE-2026-1"}}
	data, _ = json.Marshal(doc)
	stripped, err := StripSBOM(data)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Vulnerabilities []any `json:"vulnerabilities"`
		Components      []struct {
			Type string `json:"type"`
		} `json:"components"`
	}
	json.Unmarshal(stripped, &out)
	before, _ := SBOMPackages(data)
	after, _ := SBOMPackages(stripped)
	if out.Vulnerabilities != nil || len(after) != len(before) || len(stripped) >= len(data) {
		t.Fatalf("stripped %d bytes from %d, %d packages from %d", len(stripped), len(data), len(after), len(before))
	}
	for _, c := range out.Components {
		if c.Type == "file" {
			t.Fatal("a file component is left")
		}
	}
}

// Pop!_OS's purls name the distribution pop-22.04, which Grype does not know: matching the SBOM
// with them finds nothing, while the scan matches Ubuntu 22.04's data.
func TestStripSBOMDropsDistro(t *testing.T) {
	data := load(t, "pop22-staging.cdx.json")
	stripped, err := StripSBOM(data)
	if err != nil {
		t.Fatal(err)
	}
	type sbom struct {
		Components   []map[string]any `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	var before, after sbom
	json.Unmarshal(data, &before)
	json.Unmarshal(stripped, &after)
	before.Components = slices.DeleteFunc(before.Components, func(c map[string]any) bool { return c["type"] == "file" })
	if len(after.Components) != 5 || len(after.Components) != len(before.Components) {
		t.Fatalf("%d components from %d", len(after.Components), len(before.Components))
	}
	refs := map[string]bool{}
	for i, c := range after.Components {
		want := before.Components[i]
		for _, k := range []string{"purl", "bom-ref"} {
			if s, ok := want[k].(string); ok {
				want[k] = strings.Replace(s, "&distro=pop-22.04", "", 1)
			}
		}
		if !reflect.DeepEqual(c, want) {
			t.Errorf("got %v, want %v", c, want)
		}
		refs[c["bom-ref"].(string)] = true
	}
	if p := after.Components[3]["purl"]; p != "pkg:deb/pop/passwd@1%3A4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&upstream=shadow" {
		t.Errorf("passwd %v", p)
	}
	if len(after.Dependencies) != 3 {
		t.Fatalf("%d dependencies", len(after.Dependencies))
	}
	for _, d := range after.Dependencies {
		for _, r := range append([]string{d.Ref}, d.DependsOn...) {
			if !refs[r] {
				t.Errorf("dependency on %s, which is no component", r)
			}
		}
	}
}

func TestWithoutDistro(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:apk/alpine/musl@1.2.5-r9?arch=x86_64&distro=alpine-3.21.3&upstream=musl": "pkg:apk/alpine/musl@1.2.5-r9?arch=x86_64&upstream=musl",
		"pkg:deb/debian/tzdata@2026a?distro=debian-12":                                "pkg:deb/debian/tzdata@2026a",
		"pkg:rpm/rocky/bash@5.1?distro=rocky-9.3&arch=x86_64#sub":                     "pkg:rpm/rocky/bash@5.1?arch=x86_64#sub",
		"pkg:npm/lodash@4.17.21":                                                      "pkg:npm/lodash@4.17.21",
		"os:pop@22.04":                                                                "os:pop@22.04",
		"e3b0c44298fc1c14?distro=x":                                                   "e3b0c44298fc1c14?distro=x",
	} {
		if got := WithoutDistro(in); got != want {
			t.Errorf("WithoutDistro(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetKernel(t *testing.T) {
	data := load(t, "debian-kernel.cdx.json")
	out, n, err := SetKernel(data, "linux-image-6.1.0-54-amd64", "6.1.190-1", "6.1.76-1", "linux")
	if err != nil || n != 1 {
		t.Fatalf("%d changed: %v", n, err)
	}
	type prop struct{ Name, Value string }
	var got struct {
		Components []struct {
			Version    string `json:"version"`
			Properties []prop `json:"properties"`
		} `json:"components"`
	}
	json.Unmarshal(out, &got)
	var want struct {
		Version    string `json:"version"`
		Properties []prop `json:"properties"`
	}
	json.Unmarshal(load(t, "debian-kernel-rewritten-component.json"), &want)
	source := func(ps []prop) map[string]string {
		m := map[string]string{}
		for _, p := range ps {
			if p.Name == "syft:metadata:source" || p.Name == "syft:metadata:sourceVersion" {
				m[p.Name] = p.Value
			}
		}
		return m
	}
	g, w := source(got.Components[0].Properties), source(want.Properties)
	if got.Components[0].Version != want.Version || g["syft:metadata:source"] != w["syft:metadata:source"] || g["syft:metadata:sourceVersion"] != w["syft:metadata:sourceVersion"] {
		t.Fatalf("got %s %v, want %s %v", got.Components[0].Version, g, want.Version, w)
	}
	// Without a source to set, only the versions change.
	out, _, _ = SetKernel(data, "linux-image-6.1.0-54-amd64", "6.1.190-1", "6.1.76-1", "")
	json.Unmarshal(out, &got)
	if g := source(got.Components[0].Properties); g["syft:metadata:source"] != "linux-signed-amd64" || g["syft:metadata:sourceVersion"] != "6.1.76-1" {
		t.Fatalf("%v", g)
	}
	if _, n, _ := SetKernel(data, "linux-image-6.1.0-54-amd64", "6.1.189-1", "6.1.76-1", "linux"); n != 0 {
		t.Fatal("another version was changed")
	}
	// A package without a source property gets one, and a source version, once.
	for _, props := range []string{`[{"name":"syft:package:type","value":"deb"}]`,
		`[{"name":"syft:metadata:sourceVersion","value":"6.1.190+1"}]`} {
		in := `{"bomFormat":"CycloneDX","components":[{"type":"library","name":"linux-image-6.1.0-54-amd64","version":"6.1.190-1","properties":` + props + `}]}`
		out, n, err := SetKernel([]byte(in), "linux-image-6.1.0-54-amd64", "6.1.190-1", "6.1.76-1", "linux")
		if err != nil || n != 1 {
			t.Fatalf("%d changed: %v", n, err)
		}
		json.Unmarshal(out, &got)
		count := map[prop]int{}
		for _, p := range got.Components[0].Properties {
			count[p]++
		}
		if count[prop{"syft:metadata:source", "linux"}] != 1 || count[prop{"syft:metadata:sourceVersion", "6.1.76-1"}] != 1 ||
			len(got.Components[0].Properties) != len(count) {
			t.Errorf("%s: %v", props, got.Components[0].Properties)
		}
	}
}
