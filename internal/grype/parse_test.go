package grype

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
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
	rep, err := Parse(bytes.NewReader(load(t, "report.json")))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DBBuilt.Equal(time.Date(2026, 11, 14, 6, 19, 25, 0, time.UTC)) || len(rep.Matches) != 4 || rep.Distro != "debian" || rep.DistroVersion != "12.15" {
		t.Fatalf("built %v, distro %q %q, %d matches", rep.DBBuilt, rep.Distro, rep.DistroVersion, len(rep.Matches))
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
	if !slices.Equal(log4j.Artifact.CPEs, []string{"cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*", "cpe:2.3:a:apache:log4j_core:2.14.1:*:*:*:*:*:*:*",
		"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "cpe:2.3:a:apache:core:2.14.1:*:*:*:*:*:*:*"}) {
		t.Errorf("log4j CPEs %q", log4j.Artifact.CPEs)
	}
	libc := rep.Matches[1]
	if !slices.Equal(libc.Artifact.CPEs, []string{`cpe:2.3:a:libc6:libc6:2.36-9\+deb12u14:*:*:*:*:*:*:*`}) {
		t.Errorf("libc6 CPEs %q: as Grype escapes them", libc.Artifact.CPEs)
	}
	if len(libc.Vulnerability.CVSS) != 0 || len(libc.Related) == 0 || len(libc.Related[0].CVSS) == 0 || libc.Vulnerability.Namespace != "debian:distro:debian:12" {
		t.Errorf("Debian keeps the CVSS score in the related NVD record: %+v", libc)
	}
	if k := rep.Matches[3]; k.Artifact.Name != "linux-image-6.1.0-54-amd64" || k.Artifact.Version != "6.1.76-1" || k.Artifact.PURL == "" {
		t.Errorf("kernel %+v", k.Artifact)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, in := range []string{"not json", `{"matches": []}`, `{"descriptor": {"name": "grype", "db": {"status": {"built": ""}}}}`,
		`{"matches": [{"vulnerability": {"id": ""}, "artifact": {"name": "x"}}], "descriptor": {"name": "grype", "db": {"status": {"built": "2026-11-14T06:19:25Z"}}}}`,
		`{"descriptor": {"name": "grype", "db": {"status": {"built": "2026-11-14T06:19:25Z"}}}}`,
		`{"matches": [], "descriptor": {"name": "grype", "db": {"status": {"built": "2026-11-14T06:19:25Z"}}}} {}`,
		`{"matches": [], "ignoredMatches": [{"x": }], "descriptor": {"name": "grype", "db": {"status": {"built": "2026-11-14T06:19:25Z"}}}}`,
		`{"matches": [], "descriptor": {"name": "grype", "db": {"status": {"built": "2026-11-14T06:19:25Z"}}}`} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) succeeded", in)
		}
	}
}

func TestParseWithoutDistro(t *testing.T) {
	rep, err := Parse(strings.NewReader(`{"matches": [], "descriptor": {"name": "grype", "db": {"status": {"built": "2026-11-14T06:19:25Z"}}}}`))
	if err != nil || rep.Distro != "" || rep.DistroVersion != "" || len(rep.Matches) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
}

// reportWithIgnored is a report of one match and n matches that Grype's rules ignore, each of about
// 5 KB, as Grype lists Debian's and Ubuntu's kernel headers. It is read as it is generated.
func reportWithIgnored(n int) io.Reader {
	ignored := `{"vulnerability":{"id":"CVE-2026-1","description":"` + strings.Repeat("x", 5000) + `"},"artifact":{"name":"linux-headers-6.1.0-54-amd64"},` +
		`"appliedIgnoreRules":[{"package":{"name":"linux(-.*)?-headers-.*","upstream-name":"linux.*"}}]}`
	parts := []io.Reader{strings.NewReader(`{"matches":[{"vulnerability":{"id":"CVE-2026-2"},"artifact":{"name":"linux-image-6.1.0-54-amd64"}}],"ignoredMatches":[`)}
	for i := range n {
		if i > 0 {
			parts = append(parts, strings.NewReader(","))
		}
		parts = append(parts, strings.NewReader(ignored))
	}
	parts = append(parts, strings.NewReader(`],"source":{"type":"directory","target":{"path":"/stage"}},"distro":{"name":"debian","version":"12"},`+
		`"descriptor":{"name":"grype","db":{"status":{"built":"2026-11-14T06:19:25Z"}}}}`))
	return io.MultiReader(parts...)
}

// heapWatch reads r and keeps the most heap in use while it is read, sampled at every 256th read.
type heapWatch struct {
	r     io.Reader
	reads int
	peak  uint64
}

func (h *heapWatch) Read(p []byte) (int, error) {
	if h.reads++; h.reads%256 == 0 {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		h.peak = max(h.peak, ms.HeapAlloc)
	}
	return h.r.Read(p)
}

// Parse reads past the matches that Grype's rules ignore without holding them: hosts with Debian's
// or Ubuntu's kernel headers give tens of thousands, in reports of hundreds of MB.
func TestParseReadsPastIgnoredMatches(t *testing.T) {
	const n = 8000 // 40 MB
	var base runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&base)
	report := &heapWatch{r: reportWithIgnored(n)}
	rep, err := Parse(report)
	if err != nil || len(rep.Matches) != 1 || rep.Matches[0].Artifact.Name != "linux-image-6.1.0-54-amd64" || rep.Distro != "debian" {
		t.Fatalf("%+v %v", rep, err)
	}
	if report.peak > base.HeapAlloc+16<<20 {
		t.Errorf("parsing a report of 40 MB, nearly all ignored matches, took %d MB of heap", (report.peak-base.HeapAlloc)>>20)
	}
}
