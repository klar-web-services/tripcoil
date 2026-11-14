package audit

import (
	"context"
	"fmt"

	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/kernelcna"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

// kernel matches a kernel by its upstream version against the kernel CNA data (spec section
// 6.3). Severity, CVSS, EPSS and KEV come from the Grype database, as for every other finding.
func (au *auditor) kernel(ctx context.Context, o inventory.Origin) {
	data, err := au.d.Kernel.Load(ctx, au.d.Now(), au.d.MaxAge)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		au.a.Origins = append(au.a.Origins, OriginResult{ID: o.ID, Kind: o.Kind, Status: ScanFailed, Error: err.Error()})
		au.a.Errors = append(au.a.Errors, problem.New(problem.Error, problem.KernelDataStale, "audit", "the kernel is not audited: %v", err))
		au.a.Status = Partial
		return
	}
	au.a.KernelData = &KernelData{Commit: data.Commit, Checked: data.Checked}
	if !kernelcna.IsVersion(o.UpstreamVersion) {
		au.failOrigin(o, fmt.Errorf("%q is not a kernel version, so the kernel cannot be matched", o.UpstreamVersion))
		return
	}
	matches := data.Affected(o.UpstreamVersion)
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		ids = append(ids, m.CVE)
	}
	info, err := au.d.Grype.Lookup(ctx, ids)
	if err != nil {
		if ctx.Err() == nil {
			au.failOrigin(o, err)
		}
		return
	}
	au.a.Origins = append(au.a.Origins, OriginResult{ID: o.ID, Kind: o.Kind, Status: Scanned, Packages: 1})
	seen := map[string]bool{}
	for _, m := range matches {
		v, ok := info[m.CVE]
		if !ok {
			v.ID = m.CVE
		}
		vuln := vulnerability(v, nil)
		if c := m.CVSS; c != nil { // the CNA's own score, when the database has none
			if vuln.Severity == "Unknown" {
				vuln.Severity = Severity(c.Severity)
			}
			if len(vuln.CVSS) == 0 {
				vuln.CVSS = []CVSS{{Score: c.Score, Vector: c.Vector}}
			}
		}
		f := Finding{
			Vulnerability: vuln,
			Origin:        o.ID,
			Package:       Package{Name: "linux", Version: o.UpstreamVersion, Type: "linux-kernel"},
			Fix:           Fix{State: "not-fixed", Versions: []string{}},
			Source:        "kernel-cna",
		}
		if m.Fixed != "" {
			f.Fix = Fix{State: "fixed", Versions: []string{m.Fixed}}
		}
		au.add(f, seen)
	}
}
