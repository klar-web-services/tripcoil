package grype

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

func TestParseSearch(t *testing.T) {
	vs, err := parseSearch(load(t, "dbsearch-nvd.json"))
	if err != nil {
		t.Fatal(err)
	}
	v := vs["CVE-2024-1086"]
	if len(vs) != 1 || v.Severity != "high" || !v.KnownExploited || v.EPSS != 0.28058 || len(v.CVSS) != 2 || v.CVSS[0].Score != 7.8 || len(v.URLs) == 0 || v.Description == "" {
		t.Fatalf("%+v", v)
	}
	if vs, err := parseSearch([]byte("[]")); err != nil || len(vs) != 0 {
		t.Fatalf("an unknown ID: %v %v", vs, err)
	}
	if _, err := parseSearch([]byte("{}")); err == nil {
		t.Fatal("garbage was accepted")
	}
}

func TestSearchVulnerabilities(t *testing.T) {
	r, _, log := newRunner(t, `FAKE_GRYPE_SEARCH=[{"id":"CVE-2024-1086","severity":"high","known_exploited":[{"cve":"CVE-2024-1086"}],"epss":[{"epss":0.28}]}]`)
	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-2026-%d", i)
	}
	vs, err := r.SearchVulnerabilities(context.Background(), ids)
	if err != nil || !vs["CVE-2024-1086"].KnownExploited {
		t.Fatalf("%+v %v", vs, err)
	}
	got := args(t, log) // the second call, with the 1001st ID
	if !slices.Equal(got, []string{"db", "search", "vuln", "CVE-2026-1000", "--provider", "nvd", "--limit", "0", "-o", "json", "-c", got[len(got)-1]}) {
		t.Fatalf("args %q", got)
	}
}
