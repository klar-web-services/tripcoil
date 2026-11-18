package audit

import (
	"time"

	"github.com/klar-web-services/tripcoil/internal/problem"
)

const (
	Complete = "complete"
	Partial  = "partial"
	Failed   = "failed"
)

const (
	Scanned      = "scanned"
	Unidentified = "unidentified"
	ScanFailed   = "failed"
	Unresolved   = "unresolved"
)

const (
	RiskCritical = "critical"
	RiskHigh     = "high"
	RiskMedium   = "medium"
	RiskLow      = "low"
)

var Tiers = []string{RiskCritical, RiskHigh, RiskMedium, RiskLow}

type Audit struct {
	SchemaVersion string            `json:"schemaVersion"`
	Status        string            `json:"status"`
	Grype         GrypeInfo         `json:"grype"`
	KernelData    *KernelData       `json:"kernelData,omitempty"`
	Origins       []OriginResult    `json:"origins"`
	Findings      []Finding         `json:"findings"`
	Upgrades      []Upgrade         `json:"upgrades"`
	Errors        []problem.Problem `json:"errors"`
	Warnings      []problem.Problem `json:"warnings"`
}

type GrypeInfo struct {
	Version  string    `json:"version"`
	DBBuilt  time.Time `json:"dbBuilt,omitzero"`
	DBSchema string    `json:"dbSchema,omitempty"`
}

type KernelData struct {
	Commit  string    `json:"commit"`
	Checked time.Time `json:"checked"`
}

type OriginResult struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	Packages int    `json:"packages"`
	Error    string `json:"error,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Raw      *Raw   `json:"raw,omitempty"`
}

type Raw struct {
	Grype string `json:"grype"`
	SBOM  string `json:"sbom,omitempty"`
}

type Finding struct {
	ID            string        `json:"id"`
	Vulnerability Vulnerability `json:"vulnerability"`
	Origin        string        `json:"origin"`
	Package       Package       `json:"package"`
	Fix           Fix           `json:"fix"`
	Source        string        `json:"source"`
	Items         []string      `json:"items"`
	Risk          string        `json:"risk"`
	Remediation   string        `json:"remediation"`
	Raw           string        `json:"raw,omitempty"`
}

type Vulnerability struct {
	ID             string   `json:"id"`
	Aliases        []string `json:"aliases"`
	Severity       string   `json:"severity"`
	CVSS           []CVSS   `json:"cvss"`
	EPSS           float64  `json:"epss"`
	KnownExploited bool     `json:"knownExploited"`
	Description    string   `json:"description,omitempty"`
	URLs           []string `json:"urls"`
}

type CVSS struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector"`
}

type Package struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type"`
	PURL     string   `json:"purl,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
	Location string   `json:"location,omitempty"`
}

type Fix struct {
	State    string   `json:"state"`
	Versions []string `json:"versions"`
}

type Upgrade struct {
	Origin    string   `json:"origin"`
	Path      string   `json:"path"`
	Package   string   `json:"package"`
	Type      string   `json:"type"`
	Installed []string `json:"installed"`
	Version   string   `json:"version"`
	Findings  int      `json:"findings"`
}
