package grype

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Report is what Tripcoil takes from one Grype JSON report.
type Report struct {
	DBBuilt time.Time
	// Distro is the distribution Grype detected, such as debian, whether or not its database has
	// data for it; "" when Grype saw none.
	Distro        string
	DistroVersion string // such as 12.15
	Matches       []Match
}

// Match is one vulnerability matched in one package.
type Match struct {
	Vulnerability Vulnerability
	Related       []Vulnerability // the same vulnerability under other IDs, such as the CVE of a DSA
	Artifact      Artifact
}

// Vulnerability is a vulnerability record as Grype reports it.
type Vulnerability struct {
	ID             string
	Namespace      string // such as debian:distro:debian:12
	Severity       string
	Description    string
	URLs           []string
	FixState       string
	FixVersions    []string
	CVSS           []CVSS
	EPSS           float64 // the highest EPSS score listed
	KnownExploited bool    // listed in CISA KEV
}

// CVSS is one CVSS score.
type CVSS struct {
	Score  float64
	Vector string
}

// Artifact is the matched package.
type Artifact struct {
	Name, Version, Type, PURL string
	CPEs                      []string // CPE 2.3 formatted strings
	Locations                 []string
}

type rawVulnerability struct {
	ID          string   `json:"id"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	URLs        []string `json:"urls"`
	Fix         struct {
		Versions []string `json:"versions"`
		State    string   `json:"state"`
	} `json:"fix"`
	KnownExploited []json.RawMessage `json:"knownExploited"`
	EPSS           []struct {
		EPSS float64 `json:"epss"`
	} `json:"epss"`
	CVSS []struct {
		Vector  string `json:"vector"`
		Metrics struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"metrics"`
	} `json:"cvss"`
}

func (r rawVulnerability) convert() Vulnerability {
	v := Vulnerability{ID: r.ID, Namespace: r.Namespace, Severity: r.Severity, Description: r.Description, URLs: r.URLs,
		FixState: r.Fix.State, FixVersions: r.Fix.Versions, KnownExploited: len(r.KnownExploited) > 0}
	for _, e := range r.EPSS {
		v.EPSS = max(v.EPSS, e.EPSS)
	}
	for _, c := range r.CVSS {
		v.CVSS = append(v.CVSS, CVSS{Score: c.Metrics.BaseScore, Vector: c.Vector})
	}
	return v
}

type document struct {
	Matches *[]struct {
		Vulnerability          rawVulnerability   `json:"vulnerability"`
		RelatedVulnerabilities []rawVulnerability `json:"relatedVulnerabilities"`
		Artifact               struct {
			Name      string   `json:"name"`
			Version   string   `json:"version"`
			Type      string   `json:"type"`
			PURL      string   `json:"purl"`
			CPEs      []string `json:"cpes"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
	Distro struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"distro"`
	Descriptor struct {
		Name string `json:"name"`
		DB   struct {
			Status struct {
				Built string `json:"built"`
			} `json:"status"`
		} `json:"db"`
	} `json:"descriptor"`
}

// Parse reads a Grype JSON report. Unknown or malformed output is an error.
func Parse(data []byte) (*Report, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("unparseable Grype output: %w", err)
	}
	if doc.Descriptor.Name != "grype" {
		return nil, errors.New("unparseable Grype output: the grype descriptor is missing")
	}
	built, err := time.Parse(time.RFC3339, doc.Descriptor.DB.Status.Built)
	if err != nil {
		return nil, errors.New("Grype output has no valid vulnerability database build time")
	}
	if doc.Matches == nil {
		return nil, errors.New("unparseable Grype output: the matches are missing")
	}
	rep := &Report{DBBuilt: built.UTC(), Distro: doc.Distro.Name, DistroVersion: doc.Distro.Version}
	for _, m := range *doc.Matches {
		if m.Vulnerability.ID == "" || m.Artifact.Name == "" {
			return nil, errors.New("unparseable Grype output: a match has no vulnerability ID or package name")
		}
		out := Match{Vulnerability: m.Vulnerability.convert(),
			Artifact: Artifact{Name: m.Artifact.Name, Version: m.Artifact.Version, Type: m.Artifact.Type, PURL: m.Artifact.PURL, CPEs: m.Artifact.CPEs}}
		for _, l := range m.Artifact.Locations {
			out.Artifact.Locations = append(out.Artifact.Locations, l.Path)
		}
		for _, r := range m.RelatedVulnerabilities {
			out.Related = append(out.Related, r.convert())
		}
		rep.Matches = append(rep.Matches, out)
	}
	return rep, nil
}
