package audit

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/kernelcna"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/problem"
	"github.com/klar-web-services/tripcoil/internal/procfs"
	"github.com/klar-web-services/tripcoil/internal/run"
)

// Deps is everything the Audit uses from outside.
type Deps struct {
	Root     string // host root, "/" in production
	CacheDir string // Tripcoil's cache: Grype, its database, SBOMs, the kernel CNA data
	RunDir   string // the run folder; Grype's raw output goes to its raw/
	Family   osrel.Family
	MaxAge   time.Duration // audit.maxDatabaseAgeHours
	Now      func() time.Time
	Grype    Scanner
	Kernel   KernelSource
	Proc     ProcFiles // nil: unpackaged files are read at their paths only
	Images   Images    // nil: an image is scanned without checking that the daemon still has it
}

// Images is what the Audit asks the local Docker daemon (dockerapi.Client in production).
type Images interface {
	// ImageExists reports whether the daemon still has an image, by ID.
	ImageExists(ctx context.Context, id string) (bool, error)
}

// ProcFiles opens the files of running processes through /proc (procfs.FS in production).
type ProcFiles interface {
	OpenExe(pid int) (io.ReadCloser, error)
	Maps(pid int) ([]procfs.Mapping, error)
	OpenMapFile(pid int, m procfs.Mapping) (io.ReadCloser, error)
}

// Scanner is what the Audit uses of Grype.
type Scanner interface {
	// Prepare installs the pinned Grype and updates its database, then reports the database's
	// status. updateErr is set when the update failed but a database is there.
	Prepare(ctx context.Context) (st grype.DBStatus, updateErr, err error)
	// Scan catalogs and matches a source, writing Grype's report to raw and the SBOM to sbom.
	Scan(ctx context.Context, source, raw, sbom string) (*grype.Report, error)
	// Match matches an SBOM, writing Grype's report to raw.
	Match(ctx context.Context, sbom, raw string) (*grype.Report, error)
	// Lookup returns what the database holds about vulnerabilities, by ID.
	Lookup(ctx context.Context, ids []string) (map[string]grype.Vulnerability, error)
}

// KernelSource is the kernel CNA data, fetched at most daily.
type KernelSource interface {
	// Load returns the data, refreshing it when it is a day old. An error means there is no data
	// younger than maxAge.
	Load(ctx context.Context, now time.Time, maxAge time.Duration) (*kernelcna.Data, error)
}

// auditor holds one Audit's state.
type auditor struct {
	d     Deps
	inv   *inventory.Inventory
	a     *Audit
	rem   remediation
	cache sbomCache
	maps  map[int][]procfs.Mapping // the mappings of processes, read once
	seen  map[string]bool          // the IDs of the findings so far
	reads *readBudget              // what the Audit may still read from files

	mounts     []string // the mount points, read at the first app directory (see mountBelow)
	mountsErr  error
	mountsRead bool
}

// Run audits every origin of the Inventory. It always returns an Audit: one that could not match
// anything has status failed and says why.
func Run(ctx context.Context, d Deps, inv *inventory.Inventory) *Audit {
	au := &auditor{d: d, inv: inv,
		a: &Audit{SchemaVersion: "1", Status: Complete, Grype: GrypeInfo{Version: grype.Version},
			Origins: []OriginResult{}, Findings: []Finding{}, Upgrades: []Upgrade{}, Errors: []problem.Problem{}, Warnings: []problem.Problem{}},
		rem:   newRemediation(d.Family, inv),
		cache: sbomCache{root: filepath.Join(d.CacheDir, "sbom"), now: d.Now},
		maps:  map[int][]procfs.Mapping{},
		seen:  map[string]bool{},
		reads: &readBudget{left: runReadCap},
	}
	au.run(ctx)
	if ctx.Err() != nil {
		au.interrupted()
	}
	return au.a
}

// interrupted ends an Audit that a signal stopped: what it did not scan is failed, so audit.json
// never reads as complete.
func (au *auditor) interrupted() {
	a := au.a
	done := map[string]bool{}
	for _, o := range a.Origins {
		done[o.ID] = true
	}
	for _, o := range au.inv.Origins {
		switch {
		case done[o.ID]:
		case o.Kind == inventory.OriginUnresolved: // a gap whatever happened
			a.Origins = append(a.Origins, OriginResult{ID: o.ID, Kind: o.Kind, Status: Unresolved, Reason: o.Reason})
		default:
			a.Origins = append(a.Origins, OriginResult{ID: o.ID, Kind: o.Kind, Status: ScanFailed, Error: "not scanned: the run was interrupted"})
		}
	}
	slices.SortFunc(a.Origins, func(x, y OriginResult) int { return cmp.Compare(x.ID, y.ID) })
	a.Errors = append(a.Errors, problem.New(problem.Error, problem.Interrupted, "audit", "the audit was stopped by a signal"))
	if a.Status == Complete {
		a.Status = Partial
	}
}

func (au *auditor) run(ctx context.Context) {
	a, d := au.a, au.d
	// The cache is root's alone (spec section 4.3), and what a killed Grype left in it goes.
	if err := os.MkdirAll(d.CacheDir, 0o700); err == nil {
		os.Chmod(d.CacheDir, 0o700)
	}
	os.RemoveAll(filepath.Join(d.CacheDir, "tmp"))
	st, updateErr, err := d.Grype.Prepare(ctx)
	switch {
	case ctx.Err() != nil:
		a.Status = Failed
		return
	case err != nil:
		au.fail(problem.GrypeUnavailable, "Grype or its vulnerability database is not available: %v", err)
		return
	case !st.Valid:
		au.fail(problem.GrypeUnavailable, "the vulnerability database is not valid; it is downloaded again at the next run")
		return
	}
	a.Grype.DBBuilt, a.Grype.DBSchema = st.Built, st.SchemaVersion
	if age := d.Now().Sub(st.Built); age > d.MaxAge {
		msg := fmt.Sprintf("the vulnerability database was built %.0f hours ago, which is older than audit.maxDatabaseAgeHours (%.0f)", age.Hours(), d.MaxAge.Hours())
		if updateErr != nil {
			msg += fmt.Sprintf("; updating it failed: %v", updateErr)
		}
		au.fail(problem.DBStale, "%s. Check that this host can reach grype.anchore.io.", msg)
		return
	}
	if updateErr != nil {
		a.Warnings = append(a.Warnings, problem.New(problem.Warning, problem.DBUpdateFailed, "audit",
			"updating the vulnerability database failed, so the one built %s is used: %v", st.Built.Format(time.RFC3339), updateErr))
	}
	defer os.RemoveAll(au.scanDir()) // the verified copies and scratch SBOMs of this run
	if _, err := run.CreateSubfolder(d.RunDir, "raw"); err != nil {
		au.fail(problem.RunFolderUnwritable, "cannot create the raw/ folder: %v", err)
		return
	}

	// The package database first, one scan for all: the closer to the Inventory, the less of it
	// has changed since.
	var packages []inventory.Origin
	for _, o := range au.inv.Origins {
		if o.Kind == inventory.OriginPackage {
			packages = append(packages, o)
		}
	}
	if len(packages) > 0 && ctx.Err() == nil {
		au.packages(ctx, packages)
	}
	for _, o := range au.inv.Origins {
		if ctx.Err() != nil {
			break // interrupted() records what was not scanned
		}
		switch o.Kind {
		case inventory.OriginUnresolved:
			a.Origins = append(a.Origins, OriginResult{ID: o.ID, Kind: o.Kind, Status: Unresolved, Reason: o.Reason})
		case inventory.OriginPackage: // scanned above
		case inventory.OriginKernelUpstream:
			au.kernel(ctx, o)
		default:
			au.origin(ctx, o)
		}
	}
	slices.SortFunc(a.Origins, func(x, y OriginResult) int { return cmp.Compare(x.ID, y.ID) })
	slices.SortFunc(a.Findings, func(x, y Finding) int {
		return cmp.Or(cmp.Compare(slices.Index(Tiers, x.Risk), slices.Index(Tiers, y.Risk)), cmp.Compare(x.Vulnerability.ID, y.Vulnerability.ID), cmp.Compare(x.ID, y.ID))
	})
	if ctx.Err() != nil {
		return // no upgrade lines: they are checked with Grype
	}
	a.Upgrades = au.checkUpgrades(ctx, upgradeCandidates(a.Findings))
	au.cache.prune()
}

// fail ends an Audit that cannot match anything: every origin is failed, except the unresolved.
func (au *auditor) fail(code, format string, args ...any) {
	stage := "audit"
	if code == problem.RunFolderUnwritable {
		stage = "" // of no stage (spec section 12)
	}
	p := problem.New(problem.Error, code, stage, format, args...)
	au.a.Status = Failed
	au.a.Errors = append(au.a.Errors, p)
	for _, o := range au.inv.Origins {
		if o.Kind == inventory.OriginUnresolved {
			au.a.Origins = append(au.a.Origins, OriginResult{ID: o.ID, Kind: o.Kind, Status: Unresolved, Reason: o.Reason})
		} else {
			au.a.Origins = append(au.a.Origins, OriginResult{ID: o.ID, Kind: o.Kind, Status: ScanFailed, Error: p.Message})
		}
	}
}

// failOrigin records an origin that could not be scanned; the Audit goes on with the others.
func (au *auditor) failOrigin(o inventory.Origin, err error) {
	au.a.Origins = append(au.a.Origins, OriginResult{ID: o.ID, Kind: o.Kind, Status: ScanFailed, Error: err.Error()})
	au.a.Errors = append(au.a.Errors, problemf(originName(o), "%v", err))
	au.a.Status = Partial
}

// problemf is an ORIGIN_SCAN_FAILED error about subject.
func problemf(subject, format string, args ...any) problem.Problem {
	return problem.New(problem.Error, problem.OriginScanFailed, "audit", "%s: %s", subject, fmt.Sprintf(format, args...))
}

// rawName is the run folder file for an origin's Grype output: the first 8 hex digits of the
// SHA-256 of its ID.
func rawName(id, ext string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])[:8] + ext
}

func (au *auditor) addFindings(matches []grype.Match, raw string, owner func(grype.Match) (string, bool)) {
	for _, m := range matches {
		origin, ok := owner(m)
		if !ok {
			continue
		}
		f := Finding{
			Vulnerability: vulnerability(m.Vulnerability, m.Related),
			Origin:        origin,
			Package:       Package{Name: m.Artifact.Name, Version: m.Artifact.Version, Type: m.Artifact.Type, PURL: m.Artifact.PURL, CPEs: m.Artifact.CPEs},
			Fix:           Fix{State: cmp.Or(m.Vulnerability.FixState, "unknown"), Versions: nonNil(m.Vulnerability.FixVersions)},
			Source:        m.Vulnerability.Namespace,
			Raw:           raw,
		}
		f.Package.Location = findingLocation(m.Artifact.Locations)
		au.add(f)
	}
}

// packageDB matches the package databases Syft reads a distribution's packages from, as its
// catalogers name them: dpkg's status, the RPM database, apk's installed and pacman's local db.
var packageDB = regexp.MustCompile(`(^|/)(lib/dpkg/(status|status\.d/[^/]+)|(var/lib|usr/share|usr/lib/sysimage)/rpm/(Packages|Packages\.db|rpmdb\.sqlite)|lib/apk/db/installed|var/lib/pacman/local/[^/]+/desc)$`)

// findingLocation is the one of a package's locations that its findings name: the package
// database when it is one of them, else the first path in sort order. The finding ID hashes it,
// and Grype lists the locations in another order when it matches an SBOM than when it scans: for
// a Debian image, the package's copyright file first instead of /var/lib/dpkg/status.
func findingLocation(locations []string) string {
	if len(locations) == 0 {
		return ""
	}
	return slices.MinFunc(locations, func(a, b string) int {
		if x, y := packageDB.MatchString(a), packageDB.MatchString(b); x != y {
			if x {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	})
}

// add completes a finding with its ID, items, risk and remediation, once per ID.
func (au *auditor) add(f Finding) {
	f.ID = FindingID(f.Origin, f.Vulnerability.ID, f.Package)
	if au.seen[f.ID] {
		return
	}
	au.seen[f.ID] = true
	f.Items = au.rem.itemIDs(f.Origin)
	f.Risk = Risk(f.Vulnerability, f.Fix)
	f.Remediation = au.rem.line(f)
	au.a.Findings = append(au.a.Findings, f)
}

// vulnerability merges a match's vulnerability with its related ones: their IDs become aliases,
// and KEV and EPSS count from any of them (spec section 6.5).
func vulnerability(v grype.Vulnerability, related []grype.Vulnerability) Vulnerability {
	out := Vulnerability{ID: v.ID, Aliases: []string{}, Severity: Severity(v.Severity), CVSS: []CVSS{}, EPSS: v.EPSS,
		KnownExploited: v.KnownExploited, Description: v.Description, URLs: nonNil(v.URLs)}
	for _, c := range v.CVSS {
		out.CVSS = append(out.CVSS, CVSS{Score: c.Score, Vector: c.Vector})
	}
	for _, r := range related {
		if r.ID != v.ID && !slices.Contains(out.Aliases, r.ID) {
			out.Aliases = append(out.Aliases, r.ID)
		}
		out.EPSS = max(out.EPSS, r.EPSS)
		out.KnownExploited = out.KnownExploited || r.KnownExploited
		if out.Severity == "Unknown" {
			out.Severity = Severity(r.Severity)
		}
		if len(out.CVSS) == 0 {
			for _, c := range r.CVSS {
				out.CVSS = append(out.CVSS, CVSS{Score: c.Score, Vector: c.Vector})
			}
		}
		if out.Description == "" {
			out.Description = r.Description
		}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// originName names an origin in a message.
func originName(o inventory.Origin) string {
	switch o.Kind {
	case inventory.OriginBinary:
		if len(o.Paths) > 0 {
			return o.Paths[0]
		}
	case inventory.OriginAppDir:
		return o.Path
	case inventory.OriginImage:
		return "image " + cmp.Or(o.Ref, o.ImageID)
	case inventory.OriginKernelUpstream:
		return "the kernel (Linux " + o.UpstreamVersion + ")"
	case inventory.OriginPackage:
		return o.Name + " " + o.Version
	}
	return o.ID
}
