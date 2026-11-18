package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func FindingID(origin, vulnerability string, p Package) string {
	h := sha256.Sum256([]byte(strings.Join([]string{origin, vulnerability, p.Name, p.Version, p.Type, p.Location}, "\x00")))
	return "f:" + hex.EncodeToString(h[:])[:16]
}

func Risk(v Vulnerability, fix Fix) string {
	s := Severity(v.Severity)
	switch {
	case v.KnownExploited:
		return RiskCritical
	case v.EPSS >= 0.10:
		return RiskHigh
	case fix.State == "fixed" && (s == "Critical" || s == "High" || s == "Unknown"):
		return RiskMedium
	}
	return RiskLow
}

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
	case "negligible", "none":
		return "Negligible"
	}
	return "Unknown"
}
