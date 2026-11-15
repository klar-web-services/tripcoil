// Package report renders report.md from what a run produced (spec section 11.3).
package report

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/facts"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/review"
	"github.com/klar-web-services/tripcoil/internal/run"
)

// Input is what a run produced. Inventory, Audit, Facts and Review are nil when their stage wrote
// nothing.
type Input struct {
	Run       *run.Record
	Inventory *inventory.Inventory
	Audit     *audit.Audit
	Facts     *facts.Index
	// Review is the run's review, or the one it carries forward (Run.CarriedFrom). Without it, the
	// report is audit-only, and NoReview says why.
	Review   *review.Review
	NoReview string
	// Agent names the agent CLI, its version and the model, for the host line.
	Agent string
}

// maxItems is how many items a finding names; the C library belongs to nearly every process.
const maxItems = 5

// Gap is one coverage gap: something Tripcoil could not audit, by design or because it could not
// identify it (spec section 12).
type Gap struct {
	Code    string
	Subject string
	Detail  string
}

// Gaps lists the coverage gaps of a run: unresolved and unidentified origins, items without an
// app directory, containers audited by their image only, and facts that could not be collected.
func Gaps(inv *inventory.Inventory, aud *audit.Audit, idx *facts.Index) []Gap {
	var gaps []Gap
	if idx != nil {
		for _, m := range idx.Missing {
			gaps = append(gaps, Gap{problem.FactMissing, "facts/" + m.Fact, m.Reason})
		}
	}
	if inv == nil {
		return gaps
	}
	names := itemNames(inv)
	origins := originsByID(inv)
	for _, o := range inv.Origins {
		if o.Kind == inventory.OriginUnresolved {
			gaps = append(gaps, Gap{problem.OriginUnresolved, describe(o, names[o.ID]), o.Reason})
		}
	}
	if aud != nil {
		for _, o := range aud.Origins {
			if o.Status == audit.Unidentified {
				gaps = append(gaps, Gap{problem.OriginUnidentified, describe(origins[o.ID], names[o.ID]), cmp.Or(o.Reason, "no packages were identified in it")})
			}
		}
	}
	for _, it := range inv.Items {
		for _, n := range it.Notes {
			switch n {
			case problem.AppDirNotFound:
				gaps = append(gaps, Gap{n, it.Name + " (" + it.Exe + ")", "no app directory was found, so only the interpreter is audited"})
			case problem.ImageOnly:
				gaps = append(gaps, Gap{n, "container " + it.Name, "only the image is audited, not bind-mounted code or changes made in the running container"})
			}
		}
	}
	return gaps
}

// Render writes report.md. It always renders, whatever the run produced.
func Render(in Input) string {
	if in.Review != nil && in.Audit != nil && in.Run.Status != run.Interrupted && in.Run.Stages["audit"] != run.StageFailed {
		return renderReviewed(in)
	}
	var b strings.Builder
	gaps := Gaps(in.Inventory, in.Audit, in.Facts)
	b.WriteString(verdict(in, len(gaps)) + "\n\n")
	b.WriteString(hostLine(in) + "\n\n")
	if len(in.Run.Errors) > 0 {
		b.WriteString("## Errors\n\n")
		for _, e := range in.Run.Errors {
			stage := e.Stage
			if stage == "" {
				stage = "run"
			}
			fmt.Fprintf(&b, "- %s, `%s`: %s\n", titleCase(stage), e.Code, md(e.Message))
		}
		b.WriteString("\n")
	}
	if in.Audit != nil {
		writeUpgrades(&b, in.Audit.Upgrades)
		writeFindings(&b, in.Audit.Findings, in.Inventory)
	}
	writeRestarts(&b, in.Inventory)
	writeGaps(&b, gaps, in.Audit, in.Inventory)
	writeFreshness(&b, in.Audit)
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func verdict(in Input, gaps int) string {
	r := in.Run
	switch {
	case r.Status == run.Interrupted:
		return "⛔ Run incomplete: the run was interrupted" + suffixes(r, gaps, false)
	case in.Audit == nil || r.Stages["audit"] == run.StageFailed:
		return "⛔ Run incomplete: " + failure(r) + suffixes(r, gaps, false)
	}
	counts := map[string]int{}
	for _, f := range in.Audit.Findings {
		counts[f.Risk]++
	}
	var parts []string
	for _, t := range audit.Tiers {
		parts = append(parts, fmt.Sprintf("%d %s", counts[t], t))
	}
	return fmt.Sprintf("⚠️ Audit only (%s): %s findings%s", in.NoReview, strings.Join(parts, ", "), suffixes(r, gaps, true))
}

// failure is the reason a run has no audit results: the error that fails a whole audit (an
// unwritable run folder, Grype unavailable, a stale database), else the first error of the audit,
// or of an earlier stage that stopped it.
func failure(r *run.Record) string {
	for _, code := range []string{problem.RunFolderUnwritable, problem.GrypeUnavailable, problem.DBStale} {
		for _, e := range r.Errors {
			if e.Code == code {
				return md(e.Message) + " (" + e.Code + ")"
			}
		}
	}
	for _, stage := range []string{"audit", "inventory", ""} {
		for _, e := range r.Errors {
			if e.Stage == stage {
				return md(e.Message) + " (" + e.Code + ")"
			}
		}
	}
	return "the audit did not run"
}

// suffixes notes a partial run, and a failed one that still has audit results (otherwise the
// verdict already gives the failure).
func suffixes(r *run.Record, gaps int, withAudit bool) string {
	s := ""
	if r.Status == run.Partial || r.Status == run.Failed && withAudit {
		var codes []string
		for _, e := range r.Errors {
			if !slices.Contains(codes, e.Code) {
				codes = append(codes, e.Code)
			}
		}
		s += " (run " + r.Status + ": " + strings.Join(codes, ", ") + ")"
	}
	if gaps > 0 {
		s += " (" + plural(gaps, "coverage gap", "coverage gaps") + ")"
	}
	return s
}

func hostLine(in Input) string {
	parts := []string{}
	if inv := in.Inventory; inv != nil {
		parts = append(parts, "**"+md(inv.Host.Hostname)+"**", md(distroName(inv.Host.Distro)))
		for _, it := range inv.Items {
			if it.Kind == inventory.KindKernel {
				parts = append(parts, "kernel "+md(it.Release))
			}
		}
	}
	parts = append(parts, "run "+in.Run.RunID+", "+in.Run.StartedAt.UTC().Format("2006-01-02 15:04 UTC"))
	return strings.Join(parts, " · ")
}

func distroName(d inventory.Distro) string {
	if d.VersionID == "" {
		return d.ID
	}
	return d.ID + " " + d.VersionID
}

func writeUpgrades(b *strings.Builder, ups []audit.Upgrade) {
	if len(ups) == 0 {
		return
	}
	b.WriteString("## Upgrades\n\n")
	for _, u := range ups {
		installed := make([]string, len(u.Installed))
		for i, v := range u.Installed {
			installed[i] = md(v)
		}
		fmt.Fprintf(b, "- Upgrade %s %s in %s to %s to clear %s.\n", md(u.Package), strings.Join(installed, ", "), md(u.Path), md(u.Version), clears(u.Findings))
	}
	b.WriteString("\n")
}

func clears(n int) string {
	if n == 1 {
		return "its finding"
	}
	return fmt.Sprintf("all %d of its findings", n)
}

// maxGroups is how many groups the summary of a risk tier names.
const maxGroups = 25

// severities orders the severities a vulnerability can have in different sources.
var severities = []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}

// writeFindings lists critical and high findings in full, grouped by vulnerability, and
// summarizes medium and low ones by where they are.
func writeFindings(b *strings.Builder, findings []audit.Finding, inv *inventory.Inventory) {
	writeFindingsAt(b, "##", findings, inv)
}

// writeFindingsAt is writeFindings with the tiers' headings at level (## or ###).
func writeFindingsAt(b *strings.Builder, level string, findings []audit.Finding, inv *inventory.Inventory) {
	byTier := map[string][]audit.Finding{}
	for _, f := range findings {
		byTier[f.Risk] = append(byTier[f.Risk], f)
	}
	for _, tier := range audit.Tiers {
		fs := byTier[tier]
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(b, "%s %s risk (%d)\n\n", level, titleCase(tier), len(fs))
		if tier == audit.RiskCritical || tier == audit.RiskHigh {
			writeByVulnerability(b, fs, itemNamesByID(inv))
		} else {
			writeSummary(b, tier, fs, inv)
		}
		b.WriteString("\n")
	}
}

func writeByVulnerability(b *strings.Builder, fs []audit.Finding, names map[string]string) {
	type affected struct {
		items string
		f     audit.Finding
	}
	byID := map[string][]affected{}
	for _, f := range fs {
		byID[f.Vulnerability.ID] = append(byID[f.Vulnerability.ID], affected{itemList(f, names), f})
	}
	vulns := map[string]audit.Vulnerability{}
	for id, as := range byID {
		slices.SortFunc(as, func(x, y affected) int {
			return cmp.Or(cmp.Compare(x.items, y.items), cmp.Compare(x.f.Package.Name, y.f.Package.Name), cmp.Compare(x.f.Package.Version, y.f.Package.Version), cmp.Compare(x.f.ID, y.f.ID))
		})
		group := make([]audit.Finding, len(as))
		for i, a := range as {
			group[i] = a.f
		}
		vulns[id] = merge(group)
	}
	ids := slices.Collect(maps.Keys(byID))
	slices.SortFunc(ids, func(x, y string) int { return cmp.Or(cmp.Compare(vulns[y].EPSS, vulns[x].EPSS), cmp.Compare(x, y)) })
	for _, id := range ids {
		fmt.Fprintf(b, "- %s: %s.\n", vulnLink(vulns[id]), signals(vulns[id]))
		for _, a := range byID[id] {
			fmt.Fprintf(b, "  - %s %s", escapeBlockStart(md(a.f.Package.Name)), md(a.f.Package.Version))
			if a.items != "" {
				fmt.Fprintf(b, " in %s", md(a.items))
			}
			if a.f.Source == "kernel-cna" {
				b.WriteString(" (matched by upstream kernel version)")
			}
			fmt.Fprintf(b, ": %s\n", md(a.f.Remediation))
		}
	}
}

// itemList names the items of a finding.
func itemList(f audit.Finding, names map[string]string) string {
	var items []string
	for _, id := range f.Items {
		items = append(items, names[id])
	}
	slices.Sort(items)
	items = slices.Compact(items)
	if len(items) > maxItems {
		items = append(items[:maxItems], fmt.Sprintf("and %d more", len(items)-maxItems))
	}
	return strings.Join(items, ", ")
}

// merge is the vulnerability of a group of findings: every severity its sources give, KEV and the
// highest EPSS of any of them, and their links in order.
func merge(fs []audit.Finding) audit.Vulnerability {
	v := audit.Vulnerability{ID: fs[0].Vulnerability.ID}
	var sevs []string
	for _, f := range fs {
		if !slices.Contains(sevs, f.Vulnerability.Severity) {
			sevs = append(sevs, f.Vulnerability.Severity)
		}
		v.KnownExploited = v.KnownExploited || f.Vulnerability.KnownExploited
		v.EPSS = max(v.EPSS, f.Vulnerability.EPSS)
		v.URLs = append(v.URLs, f.Vulnerability.URLs...)
	}
	slices.SortFunc(sevs, func(x, y string) int { return cmp.Compare(slices.Index(severities, x), slices.Index(severities, y)) })
	v.Severity = strings.Join(sevs, " or ")
	return v
}

func signals(v audit.Vulnerability) string {
	s := []string{"severity " + v.Severity}
	if v.KnownExploited {
		s = append(s, "known exploited (CISA KEV)")
	}
	switch e := v.EPSS; {
	case e > 0 && e < 0.0005: // would round to 0.0%
		s = append(s, "EPSS <0.1%")
	case e > 0:
		s = append(s, fmt.Sprintf("EPSS %.1f%%", e*100))
	}
	return strings.Join(s, ", ")
}

// writeSummary counts the findings of a tier per image, binary, app directory, jar and kernel,
// and those of the host's packages together. The host's packages and the kernel come first, so the
// limit never hides them.
func writeSummary(b *strings.Builder, tier string, fs []audit.Finding, inv *inventory.Inventory) {
	type group struct {
		id       string // the origin; "" for the host's packages
		name     string
		rank     int // 0 for the host's packages, 1 for the kernel, 2 for the rest
		count    int
		packages map[string]int
	}
	origins, names, kernel := map[string]inventory.Origin{}, map[string][]string{}, map[string]bool{}
	if inv != nil {
		origins, names = originsByID(inv), itemNames(inv)
		for _, it := range inv.Items {
			if it.Kind == inventory.KindKernel {
				for _, id := range it.Origins {
					kernel[id] = true
				}
			}
		}
	}
	groups := map[string]*group{}
	host := &group{packages: map[string]int{}}
	hostPackages := map[string]bool{}
	for _, f := range fs {
		o := origins[f.Origin]
		isKernel := kernel[f.Origin] || o.Kind == inventory.OriginKernelUpstream
		g := host
		if o.Kind == inventory.OriginPackage && !isKernel {
			hostPackages[f.Origin] = true
		} else if g = groups[f.Origin]; g == nil {
			o.ID = f.Origin
			g = &group{id: f.Origin, name: groupName(o, names[f.Origin], isKernel), rank: 2, packages: map[string]int{}}
			if isKernel {
				g.rank = 1
			}
			groups[f.Origin] = g
		}
		g.count++
		g.packages[f.Package.Name]++
	}
	list := slices.Collect(maps.Values(groups))
	if host.count > 0 {
		host.name = "this host's packages (" + plural(len(hostPackages), "package", "packages") + ")"
		list = append(list, host)
	}
	slices.SortFunc(list, func(x, y *group) int {
		return cmp.Or(cmp.Compare(x.rank, y.rank), cmp.Compare(y.count, x.count), cmp.Compare(x.name, y.name), cmp.Compare(x.id, y.id))
	})
	for i, g := range list {
		if i == maxGroups {
			rest := 0
			for _, g := range list[i:] {
				rest += g.count
			}
			fmt.Fprintf(b, "- … and %d more with %s.\n", len(list)-i, plural(rest, "finding", "findings"))
			break
		}
		fmt.Fprintf(b, "- %d in %s; %s\n", g.count, md(g.name), topPackages(g.packages))
	}
	fmt.Fprintf(b, "\nEvery %s risk finding, with its remediation, is in audit.json.\n", tier)
}

// groupName names an origin in a summary, with its items.
func groupName(o inventory.Origin, items []string, kernel bool) string {
	if len(items) > maxItems {
		items = append(items[:maxItems:maxItems], fmt.Sprintf("and %d more", len(items)-maxItems))
	}
	names := strings.Join(items, ", ")
	var what string
	switch {
	case o.Kind == inventory.OriginKernelUpstream:
		return "the kernel (Linux " + o.UpstreamVersion + ")"
	case kernel:
		return "the kernel (package " + o.Name + " " + o.Version + ")"
	case o.Kind == inventory.OriginImage:
		ref := cmp.Or(o.Ref, o.ImageID)
		switch len(items) {
		case 0:
			return "the image " + ref
		case 1:
			return "the container " + names + " (" + ref + ")"
		}
		return "the containers " + names + " (" + ref + ")"
	case o.Kind == inventory.OriginBinary:
		what = "the binary " + strings.Join(o.Paths, ", ")
	case o.Kind == inventory.OriginAppDir && o.Jar:
		what = "the jar " + o.Path
	case o.Kind == inventory.OriginAppDir:
		what = "the app directory " + o.Path
	default:
		what = o.ID
	}
	if names == "" {
		return what
	}
	return what + " (" + names + ")"
}

// topPackages names the three packages with the most findings in a group.
func topPackages(counts map[string]int) string {
	pkgs := slices.Collect(maps.Keys(counts))
	slices.SortFunc(pkgs, func(x, y string) int { return cmp.Or(cmp.Compare(counts[y], counts[x]), cmp.Compare(x, y)) })
	how := "all in "
	if len(pkgs) > 3 {
		pkgs, how = pkgs[:3], "including "
	}
	parts := make([]string, len(pkgs))
	for i, p := range pkgs {
		parts[i] = fmt.Sprintf("%s (%d)", md(p), counts[p])
	}
	return how + strings.Join(parts, ", ")
}

func writeRestarts(b *strings.Builder, inv *inventory.Inventory) {
	if inv == nil {
		return
	}
	var lines []string
	for _, it := range inv.Items {
		switch {
		case it.Kind == inventory.KindKernel && it.RebootPending != nil && *it.RebootPending:
			lines = append(lines, fmt.Sprintf("- Reboot: the running kernel %s is not the newest installed (%s).", md(it.Release), md(strings.Join(it.RebootReasons, "; "))))
		case len(it.RestartNeeded) > 0:
			who := md(it.Name)
			if units := systemUnits(it.Units); len(units) > 0 {
				who = md(strings.Join(units, ", "))
			}
			line := fmt.Sprintf("- Restart %s: it still runs replaced files: %s.", who, md(strings.Join(it.RestartNeeded, ", ")))
			if !slices.Contains(lines, line) {
				lines = append(lines, line)
			}
		}
	}
	if len(lines) == 0 {
		return
	}
	b.WriteString("## Restart or reboot needed\n\n" + strings.Join(lines, "\n") + "\n\n")
}

// systemUnits drops a user's own manager unit (user@1000.service), which is not restarted for a replaced file.
func systemUnits(units []string) []string {
	return slices.DeleteFunc(slices.Clone(units), func(u string) bool { return strings.HasPrefix(u, "user@") })
}

func writeGaps(b *strings.Builder, gaps []Gap, aud *audit.Audit, inv *inventory.Inventory) {
	var failed []Gap
	if aud != nil && inv != nil && aud.Status != audit.Failed { // a failed audit's verdict says why
		names := itemNames(inv)
		origins := originsByID(inv)
		for _, o := range aud.Origins {
			if o.Status == audit.ScanFailed {
				failed = append(failed, Gap{Subject: describe(origins[o.ID], names[o.ID]), Detail: o.Error})
			}
		}
	}
	if len(gaps) == 0 && len(failed) == 0 {
		return
	}
	b.WriteString("## Coverage gaps\n\n")
	for _, g := range groupGaps(gaps) {
		if len(g) == 1 {
			fmt.Fprintf(b, "- `%s` %s: %s\n", g[0].Code, md(g[0].Subject), md(g[0].Detail))
		} else {
			fmt.Fprintf(b, "- %d × `%s`: %s (%s)\n", len(g), g[0].Code, md(g[0].Detail), examples(g))
		}
	}
	for _, g := range groupGaps(failed) {
		if len(g) == 1 {
			fmt.Fprintf(b, "- Not audited: %s: %s\n", md(g[0].Subject), md(g[0].Detail))
		} else {
			fmt.Fprintf(b, "- %d × Not audited: %s (%s)\n", len(g), md(g[0].Detail), examples(g))
		}
	}
	b.WriteString("\n")
}

// examples names the first three gaps of a group, and how many more there are.
func examples(g []Gap) string {
	var s []string
	for _, x := range g[:min(3, len(g))] {
		s = append(s, md(x.Subject))
	}
	if len(g) > 3 {
		s = append(s, fmt.Sprintf("and %d more", len(g)-3))
	}
	return strings.Join(s, "; ")
}

// groupGaps groups gaps by code and reason, the largest group first.
func groupGaps(gaps []Gap) [][]Gap {
	var groups [][]Gap
	at := map[[2]string]int{}
	for _, g := range gaps {
		k := [2]string{g.Code, g.Detail}
		i, ok := at[k]
		if !ok {
			i = len(groups)
			at[k] = i
			groups = append(groups, nil)
		}
		groups[i] = append(groups[i], g)
	}
	slices.SortStableFunc(groups, func(x, y []Gap) int { return cmp.Compare(len(y), len(x)) })
	return groups
}

func writeFreshness(b *strings.Builder, aud *audit.Audit) {
	if aud == nil {
		return
	}
	b.WriteString("## Data freshness\n\n")
	if aud.Grype.DBBuilt.IsZero() {
		fmt.Fprintf(b, "- No vulnerability database was loaded (Grype %s).\n", aud.Grype.Version)
	} else {
		fmt.Fprintf(b, "- Vulnerability database built %s (Grype %s).\n", stamp(aud.Grype.DBBuilt), aud.Grype.Version)
	}
	if k := aud.KernelData; k != nil {
		fmt.Fprintf(b, "- Kernel CNA data checked %s (vulns repository at %.12s). It holds the CVEs the Linux kernel CNA published; "+
			"kernel CVEs that other CNAs assigned, mostly before 2024, are not matched by upstream version.\n", stamp(k.Checked), k.Commit)
	}
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// describe names an origin for the report, with the items it belongs to.
func describe(o inventory.Origin, items []string) string {
	var what string
	switch o.Kind {
	case inventory.OriginPackage:
		what = "package " + o.Name + " " + o.Version
	case inventory.OriginBinary, inventory.OriginUnresolved:
		what = strings.Join(o.Paths, ", ")
	case inventory.OriginAppDir:
		what = o.Path
	case inventory.OriginImage:
		what = "image " + cmp.Or(o.Ref, o.ImageID)
	case inventory.OriginKernelUpstream:
		what = "Linux " + o.UpstreamVersion
	}
	if len(items) == 0 {
		return cmp.Or(what, o.ID)
	}
	if len(items) > maxItems {
		items = append(items[:maxItems:maxItems], fmt.Sprintf("and %d more", len(items)-maxItems))
	}
	if what == "" {
		return strings.Join(items, ", ")
	}
	return strings.Join(items, ", ") + ": " + what
}

func originsByID(inv *inventory.Inventory) map[string]inventory.Origin {
	m := map[string]inventory.Origin{}
	for _, o := range inv.Origins {
		m[o.ID] = o
	}
	return m
}

// itemNames lists, for each origin, the names of its items.
func itemNames(inv *inventory.Inventory) map[string][]string {
	m := map[string][]string{}
	for _, it := range inv.Items {
		for _, id := range it.Origins {
			if !slices.Contains(m[id], it.Name) {
				m[id] = append(m[id], it.Name)
			}
		}
	}
	for id := range m {
		slices.Sort(m[id])
	}
	return m
}

func itemNamesByID(inv *inventory.Inventory) map[string]string {
	m := map[string]string{}
	if inv != nil {
		for _, it := range inv.Items {
			m[it.ID] = it.Name
		}
	}
	return m
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// vulnLink links a vulnerability's ID to the first safe URL that names it, else to the first safe one.
func vulnLink(v audit.Vulnerability) string {
	id := md(v.ID)
	var first, named string
	for _, u := range v.URLs {
		if !strings.HasPrefix(u, "https://") || strings.ContainsFunc(u, unsafeURLRune) {
			continue
		}
		first = cmp.Or(first, u)
		if named == "" && namesID(u, v.ID) {
			named = u
		}
	}
	if u := cmp.Or(named, first); u != "" {
		return "[" + id + "](" + u + ")"
	}
	return escapeBlockStart(id)
}

// namesID reports whether a URL contains an ID, ignoring case, and not as the start of a longer
// one (CVE-2026-1000 in CVE-2026-10001).
func namesID(u, id string) bool {
	u, id = strings.ToLower(u), strings.ToLower(id)
	for id != "" {
		i := strings.Index(u, id)
		if i < 0 {
			return false
		}
		if end := i + len(id); end == len(u) || !unicode.IsLetter(rune(u[end])) && !unicode.IsDigit(rune(u[end])) {
			return true
		}
		u = u[i+1:]
	}
	return false
}

// escapeBlockStart keeps text printed at the start of a list item from opening a Markdown block.
// Leading spaces go first: clean turns control characters into spaces, and spaces before a block
// marker still open the block.
func escapeBlockStart(s string) string {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return s
	}
	if strings.ContainsRune("#+-=>", rune(s[0])) {
		return `\` + s
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i > 0 && i < len(s) && (s[i] == '.' || s[i] == ')') {
		return s[:i] + `\` + s[i:]
	}
	return s
}

func unsafeURLRune(r rune) bool {
	return r <= ' ' || r >= 0x7f || strings.ContainsRune("()<>\"'|\\`[]", r)
}

// clean replaces control and Unicode format characters (bidi controls, zero-width characters), so
// untrusted text can neither drive the terminal nor spoof a name.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
}

var mdEscaper = strings.NewReplacer(`\`, `\\`, "|", `\|`, "*", `\*`, "_", `\_`, "`", "\\`", "~", `\~`, "[", `\[`, "]", `\]`, "<", "&lt;", ">", "&gt;")

// md escapes untrusted text for Markdown.
func md(s string) string { return mdEscaper.Replace(clean(s)) }
