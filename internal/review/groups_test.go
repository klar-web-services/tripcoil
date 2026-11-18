package review

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

func TestGroupFindings(t *testing.T) {
	kernel := func(id, risk, desc string, fixed ...string) audit.Finding {
		return audit.Finding{ID: id, Risk: risk, Source: "kernel-cna", Origin: "kernel-upstream:6.8.12", Items: []string{"kernel"},
			Package: audit.Package{Name: "linux", Version: "6.8.12"}, Fix: audit.Fix{Versions: fixed},
			Vulnerability: audit.Vulnerability{Description: kernelPrefix + desc}}
	}
	pkg := func(id, risk, origin, name, version string, items ...string) audit.Finding {
		return audit.Finding{ID: id, Risk: risk, Source: "debian:distro:debian:12", Origin: origin, Items: items,
			Package: audit.Package{Name: name, Version: version}, Fix: audit.Fix{Versions: []string{}}}
	}
	aud := &audit.Audit{Findings: []audit.Finding{
		kernel("f:k1", "low", "\n\ndrm/amd/display: fix a leak\n\nMore text.", "6.8.13"),
		kernel("f:k2", "medium", "\n\nDRM: check a pointer", "6.9.1"),
		kernel("f:k3", "low", "  tls: fix handling of zero-length records", "6.8.13"),
		kernel("f:k4", "low", "\n\nA flaw was found in something without a subsystem."),
		kernel("f:k5", "high", "\n\nnet/mlx5e: fix a race", "6.8.13"),
		// a distribution kernel package matched by Grype counts as the kernel too
		{ID: "f:k6", Risk: "low", Source: "ubuntu:distro:ubuntu:24.04", Origin: "pkg:linux-image", Items: []string{"kernel"},
			Package: audit.Package{Name: "linux-image-6.8.0-45-generic", Version: "6.8.0-45.45"}, Fix: audit.Fix{Versions: []string{}},
			Vulnerability: audit.Vulnerability{Description: kernelPrefix + "\n\nnet: sched: fix a leak", KnownExploited: true, EPSS: 0.4}},
		pkg("f:p2", "critical", "pkg:openssl", "openssl", "3.0.13", "proc:nginx", "proc:sshd"),
		pkg("f:p1", "medium", "pkg:openssl", "openssl", "3.0.13", "proc:nginx"),
		pkg("f:p3", "low", "image:abc", "openssl", "3.0.13", "ctr:web"),
	}}
	inv := &inventory.Inventory{Items: []inventory.Item{{ID: "kernel", Name: "kernel"}, {ID: "proc:nginx", Name: "nginx"}, {ID: "proc:sshd", Name: "sshd"}, {ID: "ctr:web", Name: "web"}}}

	got := GroupFindings(aud, inv)
	type short struct {
		ID, Label string
		Risk      RiskCounts
		KEV       int
		FixedIn   []string
		Items     []string
		Findings  []string
	}
	var s []short
	for _, g := range got.Groups {
		s = append(s, short{g.ID, g.Label, g.Risk, g.KnownExploited, g.FixedIn, g.Items, g.Findings})
	}
	ssl, img := pkgID("pkg:openssl", "openssl", "3.0.13"), pkgID("image:abc", "openssl", "3.0.13")
	want := []short{
		{ssl, "openssl 3.0.13 in nginx, sshd", RiskCounts{Critical: 1, Medium: 1}, 0, []string{}, []string{"proc:nginx", "proc:sshd"}, []string{"f:p2", "f:p1"}},
		{"kernel:net", "Linux kernel net subsystem", RiskCounts{High: 1, Low: 1}, 1, []string{"6.8.13"}, []string{"kernel"}, []string{"f:k5", "f:k6"}},
		{"kernel:drm", "Linux kernel drm subsystem", RiskCounts{Medium: 1, Low: 1}, 0, []string{"6.8.13", "6.9.1"}, []string{"kernel"}, []string{"f:k2", "f:k1"}},
		{"kernel:other", "Linux kernel, subsystem not named in the description", RiskCounts{Low: 1}, 0, []string{}, []string{"kernel"}, []string{"f:k4"}},
		{"kernel:tls", "Linux kernel tls subsystem", RiskCounts{Low: 1}, 0, []string{"6.8.13"}, []string{"kernel"}, []string{"f:k3"}},
		{img, "openssl 3.0.13 in web", RiskCounts{Low: 1}, 0, []string{}, []string{"ctr:web"}, []string{"f:p3"}},
	}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("got\n%+v\nwant\n%+v", s, want)
	}
	if got.Groups[1].MaxEPSS != 0.4 || got.SchemaVersion != "1" {
		t.Errorf("%+v", got.Groups[1])
	}
	a, _ := json.Marshal(got)
	for range 5 {
		if b, _ := json.Marshal(GroupFindings(aud, inv)); string(a) != string(b) {
			t.Fatal("the groups are not deterministic")
		}
	}
	if e, _ := json.Marshal(GroupFindings(&audit.Audit{}, nil)); string(e) != `{"schemaVersion":"1","groups":[]}` {
		t.Errorf("no findings: %s", e)
	}
}

func pkgID(origin, name, version string) string {
	for _, g := range GroupFindings(&audit.Audit{Findings: []audit.Finding{{ID: "f:x", Origin: origin, Package: audit.Package{Name: name, Version: version}}}}, nil).Groups {
		return g.ID
	}
	return ""
}
