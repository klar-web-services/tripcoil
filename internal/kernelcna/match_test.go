package kernelcna

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testData reads the records in testdata/kernelcna: 29 real records from the vulns repository
// (commit 84a53c89, 2026-11-13) chosen to cover every kind of range the kernel CNA writes.
func testData(t *testing.T) *Data {
	t.Helper()
	paths, err := filepath.Glob("../../testdata/kernelcna/cve/published/*/CVE-*.json")
	if err != nil || len(paths) != 29 {
		t.Fatalf("%d records: %v", len(paths), err)
	}
	d := &Data{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseRecord(data)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		d.Records = append(d.Records, r)
	}
	return d
}

func expected(t *testing.T, tool, version string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../testdata/kernelcna/expected", tool, version+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(data))
}

func ids(ms []Match) []string {
	out := []string{}
	for _, m := range ms {
		out = append(out, m.CVE)
	}
	return out
}

// strakDifferences are where the records' JSON and strak, the vulns repository's own tool (which
// reads the commit-level .dyad files), disagree for these versions. extra: strak counts a fix of an
// earlier introduction against a later reintroduction, so the JSON is right. missing: the
// generator left an unfixed backport out of the JSON, so no rule on the JSON can find it.
var strakDifferences = map[string]struct{ extra, missing []string }{
	"7.3.3":    {extra: []string{"CVE-2021-47645"}},
	"6.12.58":  {extra: []string{"CVE-2021-47645", "CVE-2026-46205"}},
	"6.6.63":   {extra: []string{"CVE-2021-47645", "CVE-2026-46205"}, missing: []string{"CVE-2025-37750"}},
	"6.1.119":  {extra: []string{"CVE-2021-47645", "CVE-2026-46205"}, missing: []string{"CVE-2025-40039"}},
	"5.15.131": {extra: []string{"CVE-2024-38547", "CVE-2026-46205"}},
	"5.10.230": {extra: []string{"CVE-2022-50399", "CVE-2026-46205"}, missing: []string{"CVE-2022-49142"}},
}

func TestAffectedMatchesTheVulnsRepository(t *testing.T) {
	d := testData(t)
	for version, diff := range strakDifferences {
		got := ids(d.Affected(version))
		if want := expected(t, "scoped", version); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", version, got, want)
		}
		strak := expected(t, "strak", version)
		var extra, missing []string
		for _, id := range got {
			if !slices.Contains(strak, id) {
				extra = append(extra, id)
			}
		}
		for _, id := range strak {
			if !slices.Contains(got, id) {
				missing = append(missing, id)
			}
		}
		if !slices.Equal(extra, diff.extra) || !slices.Equal(missing, diff.missing) {
			t.Errorf("%s: differs from strak by +%v -%v, want +%v -%v", version, extra, missing, diff.extra, diff.missing)
		}
	}
}

func TestAffectedNormalizesAndRejects(t *testing.T) {
	d := testData(t)
	if !slices.Equal(ids(d.Affected("7.3.0")), ids(d.Affected("7.3"))) {
		t.Fatal("uname's 7.3.0 is the records' 7.3")
	}
	if got := d.Affected("not-a-version"); got != nil {
		t.Fatalf("%v", got)
	}
}

func TestFixFor(t *testing.T) {
	d := testData(t)
	fixes := map[string]map[string]string{}
	for _, v := range []string{"7.3.3", "6.1.119", "5.15.131"} {
		fixes[v] = map[string]string{}
		for _, m := range d.Affected(v) {
			fixes[v][m.CVE] = m.Fixed
		}
	}
	for _, c := range []struct{ version, cve, want string }{
		{"5.15.131", "CVE-2024-26581", "5.15.149"}, // fixed in its own branch
		{"7.3.3", "CVE-2026-68086", ""},            // fixed only in 7.1.4: no fix for 7.3
		{"6.1.119", "CVE-2026-100080", "6.1.192"},  // "0 < 6.1.192" in the backports, "6.1.192 <= 6.1.*" fixed
	} {
		if got, ok := fixes[c.version][c.cve]; !ok || got != c.want {
			t.Errorf("%s %s: fixed %q (affected %v), want %q", c.version, c.cve, got, ok, c.want)
		}
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"6.1", "6.1.0", 0}, {"6.1.9", "6.1.10", -1}, {"7.4-rc2", "7.4", -1}, {"7.3.3", "7.4-rc2", -1},
		{"7.4-rc2", "7.4-rc10", -1}, {"2.6.32.71", "2.6.32.8", 1}, {"0", "2.6.12", -1},
	} {
		a, _ := parseVersion(c.a)
		b, _ := parseVersion(c.b)
		if got := compare(a, b); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	for _, bad := range []string{"", "6.x", "6.1-rc", "6..1", "-1"} {
		if _, ok := parseVersion(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestParseRecord(t *testing.T) {
	data, err := os.ReadFile("../../testdata/kernelcna/cve/published/2024/CVE-2024-26581.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "CVE-2024-26581" || len(r.Affected) != 2 || r.CVSS == nil || r.CVSS.Score != 7.8 || r.CVSS.Severity != "HIGH" {
		t.Fatalf("%+v", r)
	}
	for _, e := range r.Affected {
		for _, v := range e.Versions {
			if v.VersionType == "git" {
				t.Fatal("git ranges are dropped")
			}
		}
	}
	if _, err := ParseRecord([]byte(`{"cveMetadata":{"cveId":"CVE-2024-1","state":"REJECTED"}}`)); err == nil {
		t.Fatal("a rejected record parsed")
	}
}
