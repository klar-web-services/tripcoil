package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// FindingID is "f:" plus the first 16 hex digits of the SHA-256 of origin, vulnerability and
// package, so a finding keeps its ID across runs (spec section 6.4).
func FindingID(origin, vulnerability string, p Package) string {
	h := sha256.Sum256([]byte(strings.Join([]string{origin, vulnerability, p.Name, p.Version, p.Type, p.Location}, "\x00")))
	return "f:" + hex.EncodeToString(h[:])[:16]
}

// Risk is the risk tier of a finding: the first rule of spec section 6.5 that applies. KEV and
// EPSS already include the related vulnerabilities.
func Risk(v Vulnerability, fix Fix) string {
	switch {
	case v.KnownExploited:
		return RiskCritical
	case v.EPSS >= 0.10:
		return RiskHigh
	case fix.State == "fixed" && (v.Severity == "Critical" || v.Severity == "High" || v.Severity == "Unknown"):
		return RiskMedium
	}
	return RiskLow
}

// Severity spells a severity the one way audit.json uses; anything unrecognised is Unknown.
func Severity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "negligible":
		return "Negligible"
	}
	return "Unknown"
}
