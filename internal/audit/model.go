// Package audit scans the Inventory's origins for known vulnerabilities and turns the matches into
// findings with risk tiers and remediation (spec section 6).
package audit

import (
	"time"

	"github.com/klar-web-services/tripcoil/internal/problem"
)

// Audit statuses.
const (
	Complete = "complete" // no origin failed
	Partial  = "partial"  // some origins failed, or the kernel data was stale
	Failed   = "failed"   // no matching possible
)

// Origin scan statuses.
const (
	Scanned      = "scanned"
	Unidentified = "unidentified" // Grype found no packages in it: a coverage gap
	ScanFailed   = "failed"
	Unresolved   = "unresolved" // the Inventory could not resolve it: a coverage gap
)

// Risk tiers, highest first.
const (
	RiskCritical = "critical"
	RiskHigh     = "high"
	RiskMedium   = "medium"
	RiskLow      = "low"
)

// Tiers lists the risk tiers, highest first.
var Tiers = []string{RiskCritical, RiskHigh, RiskMedium, RiskLow}

// Audit is audit.json.
type Audit struct {
	SchemaVersion string            `json:"schemaVersion"`
	Status        string            `json:"status"`
	Grype         GrypeInfo         `json:"grype"`
	KernelData    *KernelData       `json:"kernelData,omitempty"` // set when the kernel CNA data was used
	Origins       []OriginResult    `json:"origins"`
	Findings      []Finding         `json:"findings"`
	Upgrades      []Upgrade         `json:"upgrades"`
	Errors        []problem.Problem `json:"errors"`
	Warnings      []problem.Problem `json:"warnings"`
}

// GrypeInfo names the Grype release and the vulnerability database the Audit matched with.
type GrypeInfo struct {
	Version  string    `json:"version"`
	DBBuilt  time.Time `json:"dbBuilt,omitzero"`
	DBSchema string    `json:"dbSchema,omitempty"`
}

// KernelData says which kernel CNA data the kernel was matched against.
type KernelData struct {
	Commit  string    `json:"commit"`  // the vulns repository commit
	Checked time.Time `json:"checked"` // when that commit was last confirmed to be the newest
}

// OriginResult is the scan of one origin of the Inventory.
type OriginResult struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	Packages int    `json:"packages"`         // packages Grype cataloged in it
	Error    string `json:"error,omitempty"`  // why the scan failed
	Reason   string `json:"reason,omitempty"` // why the Inventory could not resolve it
	Raw      *Raw   `json:"raw,omitempty"`
}

// Raw names the run folder's files with Grype's output for an origin.
type Raw struct {
	Grype string `json:"grype"`          // raw/<hash>.grype.json
	SBOM  string `json:"sbom,omitempty"` // raw/<hash>.cdx.json
}

// Finding is one vulnerability matched in one package of one origin (spec section 6.4).
type Finding struct {
	ID            string        `json:"id"`
	Vulnerability Vulnerability `json:"vulnerability"`
	Origin        string        `json:"origin"`
	Package       Package       `json:"package"`
	Fix           Fix           `json:"fix"`
	Source        string        `json:"source"` // the Grype namespace, or kernel-cna
	Items         []string      `json:"items"`
	Risk          string        `json:"risk"`
	Remediation   string        `json:"remediation"`
	Raw           string        `json:"raw,omitempty"`
}

// Vulnerability is what the vulnerability data says about one vulnerability.
type Vulnerability struct {
	ID             string   `json:"id"`
	Aliases        []string `json:"aliases"`
	Severity       string   `json:"severity"` // Critical, High, Medium, Low, Negligible or Unknown
	CVSS           []CVSS   `json:"cvss"`
	EPSS           float64  `json:"epss"`
	KnownExploited bool     `json:"knownExploited"`
	Description    string   `json:"description,omitempty"`
	URLs           []string `json:"urls"`
}

// CVSS is one CVSS score.
type CVSS struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector"`
}

// Package is the matched package.
type Package struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type"`
	PURL     string   `json:"purl,omitempty"` // as Grype reports it, without the distro qualifier; kernel findings have none
	CPEs     []string `json:"cpes,omitempty"` // as Grype reports them
	Location string   `json:"location,omitempty"`
}

// Fix is the fix state: fixed, not-fixed, wont-fix or unknown.
type Fix struct {
	State    string   `json:"state"`
	Versions []string `json:"versions"`
}

// Upgrade is one version of a package in an app directory that clears all its findings: Grype
// matched the package at that version and found nothing (spec section 6.6).
type Upgrade struct {
	Origin    string   `json:"origin"`
	Path      string   `json:"path"` // the app directory or jar
	Package   string   `json:"package"`
	Type      string   `json:"type"`
	Installed []string `json:"installed"` // the installed versions, each once, lowest first
	Version   string   `json:"version"`
	Findings  int      `json:"findings"`
}
