package audit

import "testing"

func TestFindingID(t *testing.T) {
	p := Package{Name: "libssl3", Version: "3.0.15-1~deb12u1", Type: "deb", Location: "/var/lib/dpkg/status"}
	id := FindingID("pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12", "CVE-2026-1234", p)
	if len(id) != 18 || id[:2] != "f:" {
		t.Fatalf("id %q", id)
	}
	if again := FindingID("pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12", "CVE-2026-1234", p); again != id {
		t.Fatalf("not stable: %q, %q", id, again)
	}
	other := p
	other.Location = "/var/lib/dpkg/status.d/libssl3"
	if FindingID("pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12", "CVE-2026-1234", other) == id {
		t.Fatal("the location is part of the ID")
	}
	if FindingID("a", "bc", Package{}) == FindingID("ab", "c", Package{}) {
		t.Fatal("parts run together")
	}
	p = Package{Name: "libssl3", Version: "3.0.15-1~deb12u1", Type: "deb", Location: "/var/lib/dpkg/status"}
	if id := FindingID("pkg:deb/debian/libssl3@3.0.15-1~deb12u1?distro=debian-12", "CVE-2026-1234", p); id != "f:2fbbc5f665b4ae55" {
		t.Fatalf("id %q, want f:2fbbc5f665b4ae55", id)
	}
}

func TestRisk(t *testing.T) {
	fixed := Fix{State: "fixed", Versions: []string{"2"}}
	cases := []struct {
		name string
		v    Vulnerability
		fix  Fix
		want string
	}{
		{"KEV beats everything", Vulnerability{Severity: "Low", KnownExploited: true}, Fix{State: "not-fixed"}, RiskCritical},
		{"EPSS 0.10", Vulnerability{Severity: "Low", EPSS: 0.10}, Fix{State: "unknown"}, RiskHigh},
		{"EPSS just below", Vulnerability{Severity: "Critical", EPSS: 0.0999}, Fix{State: "not-fixed"}, RiskLow},
		{"fixed High", Vulnerability{Severity: "High"}, fixed, RiskMedium},
		{"fixed Critical", Vulnerability{Severity: "Critical"}, fixed, RiskMedium},
		{"fixed Unknown counts as High", Vulnerability{Severity: "Unknown"}, fixed, RiskMedium},
		{"fixed Medium", Vulnerability{Severity: "Medium"}, fixed, RiskLow},
		{"fixed, spelled in lower case", Vulnerability{Severity: "high"}, fixed, RiskMedium},
		{"fixed, an unexpected spelling counts as High", Vulnerability{Severity: "Important"}, fixed, RiskMedium},
		{"fixed, no severity counts as High", Vulnerability{}, fixed, RiskMedium},
		{"fixed none", Vulnerability{Severity: "none"}, fixed, RiskLow},
		{"unfixed Critical", Vulnerability{Severity: "Critical"}, Fix{State: "wont-fix"}, RiskLow},
	}
	for _, c := range cases {
		if got := Risk(c.v, c.fix); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestSeverity(t *testing.T) {
	for in, want := range map[string]string{"High": "High", "critical": "Critical", " MEDIUM ": "Medium", "Negligible": "Negligible", "none": "Negligible", "None": "Negligible", "": "Unknown", "Important": "Unknown"} {
		if got := Severity(in); got != want {
			t.Errorf("Severity(%q) = %q, want %q", in, got, want)
		}
	}
}
