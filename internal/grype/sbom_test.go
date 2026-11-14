package grype

import (
	"encoding/json"
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
}
