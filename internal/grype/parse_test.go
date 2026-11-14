package grype

import (
	"os"
	"testing"
	"time"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/grype/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParse(t *testing.T) {
	rep, err := Parse(load(t, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DBBuilt.Equal(time.Date(2026, 11, 14, 6, 19, 25, 0, time.UTC)) || len(rep.Matches) != 4 || rep.Distro != "debian" {
		t.Fatalf("built %v, distro %q, %d matches", rep.DBBuilt, rep.Distro, len(rep.Matches))
	}
	log4j := rep.Matches[0]
	if log4j.Vulnerability.ID != "GHSA-jfh8-c2jp-5v3q" || log4j.Artifact.Name != "log4j-core" || log4j.Artifact.Version != "2.14.1" ||
		log4j.Artifact.Type != "java-archive" || log4j.Vulnerability.Severity != "Critical" || log4j.Vulnerability.FixState != "fixed" ||
		len(log4j.Artifact.Locations) == 0 || log4j.Vulnerability.Namespace == "" {
		t.Errorf("log4j %+v", log4j)
	}
	kev := false
	for _, r := range append([]Vulnerability{log4j.Vulnerability}, log4j.Related...) {
		kev = kev || (r.KnownExploited && r.EPSS > 0.9)
	}
	if !kev {
		t.Errorf("Log4Shell's KEV and EPSS: %+v %+v", log4j.Vulnerability, log4j.Related)
	}
	libc := rep.Matches[1]
	if len(libc.Vulnerability.CVSS) != 0 || len(libc.Related) == 0 || len(libc.Related[0].CVSS) == 0 || libc.Vulnerability.Namespace != "debian:distro:debian:12" {
		t.Errorf("Debian keeps the CVSS score in the related NVD record: %+v", libc)
	}
	if k := rep.Matches[3]; k.Artifact.Name != "linux-image-6.1.0-54-amd64" || k.Artifact.Version != "6.1.76-1" || k.Artifact.PURL == "" {
		t.Errorf("kernel %+v", k.Artifact)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, in := range []string{"not json", `{"matches": []}`, `{"descriptor": {"name": "grype", "db": {"status": {"built": ""}}}}`,
		`{"matches": [{"vulnerability": {"id": ""}, "artifact": {"name": "x"}}], "descriptor": {"name": "grype", "db": {"status": {"built": "2026-11-14T06:19:25Z"}}}}`} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%q) succeeded", in)
		}
	}
}
