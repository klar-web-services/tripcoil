package kernelcna

import (
	"encoding/json"
	"fmt"
	"regexp"
)

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]+$`)

// Record is what Tripcoil keeps of one CVE record: its affected entries without the git ranges,
// and the CNA's own CVSS score when it gave one.
type Record struct {
	ID       string  `json:"id"`
	Affected []Entry `json:"affected"`
	CVSS     *CVSS   `json:"cvss,omitempty"`
}

// Entry is one entry of a record's affected list.
type Entry struct {
	DefaultStatus string  `json:"defaultStatus"`
	Versions      []Range `json:"versions"`
}

// Range is one version or version range of an entry, as CVE JSON 5 writes it.
type Range struct {
	Version         string `json:"version"`
	LessThan        string `json:"lessThan,omitempty"`
	LessThanOrEqual string `json:"lessThanOrEqual,omitempty"`
	Status          string `json:"status"`
	VersionType     string `json:"versionType,omitempty"`
}

// CVSS is the CNA's CVSS 3.1 score.
type CVSS struct {
	Score    float64 `json:"score"`
	Vector   string  `json:"vector"`
	Severity string  `json:"severity"`
}

// ParseRecord reads a published CVE JSON 5 record.
func ParseRecord(data []byte) (Record, error) {
	var doc struct {
		CVEMetadata struct {
			CVEID string `json:"cveId"`
			State string `json:"state"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA struct {
				Affected []Entry `json:"affected"`
				Metrics  []struct {
					CVSSV31 *struct {
						VectorString string  `json:"vectorString"`
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssV3_1"`
				} `json:"metrics"`
			} `json:"cna"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Record{}, err
	}
	if !cveID.MatchString(doc.CVEMetadata.CVEID) || doc.CVEMetadata.State != "PUBLISHED" {
		return Record{}, fmt.Errorf("not a published CVE record: %q %q", doc.CVEMetadata.CVEID, doc.CVEMetadata.State)
	}
	r := Record{ID: doc.CVEMetadata.CVEID, Affected: []Entry{}}
	for _, e := range doc.Containers.CNA.Affected {
		kept := Entry{DefaultStatus: e.DefaultStatus, Versions: []Range{}}
		for _, v := range e.Versions {
			if v.VersionType != "git" { // commit ranges are not versions
				kept.Versions = append(kept.Versions, v)
			}
		}
		r.Affected = append(r.Affected, kept)
	}
	for _, m := range doc.Containers.CNA.Metrics {
		if c := m.CVSSV31; c != nil && r.CVSS == nil {
			r.CVSS = &CVSS{Score: c.BaseScore, Vector: c.VectorString, Severity: c.BaseSeverity}
		}
	}
	return r, nil
}
