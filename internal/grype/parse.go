package grype

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type rawMatch struct {
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
}

func (m rawMatch) convert() Match {
	out := Match{Vulnerability: m.Vulnerability.convert(),
		Artifact: Artifact{Name: m.Artifact.Name, Version: m.Artifact.Version, Type: m.Artifact.Type, PURL: m.Artifact.PURL, CPEs: m.Artifact.CPEs}}
	for _, l := range m.Artifact.Locations {
		out.Artifact.Locations = append(out.Artifact.Locations, l.Path)
	}
	for _, r := range m.RelatedVulnerabilities {
		out.Related = append(out.Related, r.convert())
	}
	return out
}

// Parse reads a Grype JSON report. Unknown or malformed output is an error. It reads the report as
// a stream and holds only the matches and what else Tripcoil takes: Grype also lists every match
// that its rules ignore, about 5 KB each, and its default rules ignore Debian's and Ubuntu's kernel
// headers, which give tens of thousands. Those are read one at a time and dropped.
func Parse(r io.Reader) (*Report, error) {
	var (
		rep     Report
		matches bool
		distro  struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		descriptor struct {
			Name string `json:"name"`
			DB   struct {
				Status struct {
					Built string `json:"built"`
				} `json:"status"`
			} `json:"db"`
		}
	)
	dec := json.NewDecoder(r)
	err := members(dec, func(key string) error {
		switch key {
		case "matches":
			matches, rep.Matches = true, nil
			return elements(dec, func() error {
				var m rawMatch
				if err := dec.Decode(&m); err != nil {
					return err
				}
				if m.Vulnerability.ID == "" || m.Artifact.Name == "" {
					return errors.New("a match has no vulnerability ID or package name")
				}
				rep.Matches = append(rep.Matches, m.convert())
				return nil
			})
		case "distro":
			return dec.Decode(&distro)
		case "descriptor":
			return dec.Decode(&descriptor)
		}
		return skip(dec)
	})
	if err == nil {
		if _, end := dec.Token(); end != io.EOF {
			err = errors.New("more follows the report")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("unparseable Grype output: %w", err)
	}
	if descriptor.Name != "grype" {
		return nil, errors.New("unparseable Grype output: the grype descriptor is missing")
	}
	built, err := time.Parse(time.RFC3339, descriptor.DB.Status.Built)
	if err != nil {
		return nil, errors.New("Grype output has no valid vulnerability database build time")
	}
	if !matches {
		return nil, errors.New("unparseable Grype output: the matches are missing")
	}
	rep.DBBuilt, rep.Distro, rep.DistroVersion = built.UTC(), distro.Name, distro.Version
	return &rep, nil
}

// members reads a JSON object from dec and calls member with each of its keys; member reads the
// key's value.
func members(dec *json.Decoder, member func(key string) error) error {
	if err := delim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string) // Token gives an object's keys as strings
		if err := member(key); err != nil {
			return err
		}
	}
	return delim(dec, '}')
}

// elements reads a JSON array from dec and calls element for each of its elements, which element
// reads.
func elements(dec *json.Decoder, element func() error) error {
	if err := delim(dec, '['); err != nil {
		return err
	}
	for dec.More() {
		if err := element(); err != nil {
			return err
		}
	}
	return delim(dec, ']')
}

func delim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != want {
		return fmt.Errorf("%v where %v belongs", tok, want)
	}
	return nil
}

// skip reads past the next value of dec, holding at most one element of an array at a time.
func skip(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('['):
		for dec.More() {
			var element json.RawMessage
			if err := dec.Decode(&element); err != nil {
				return err
			}
		}
	case json.Delim('{'):
		for dec.More() {
			if _, err := dec.Token(); err != nil {
				return err
			}
			if err := skip(dec); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = dec.Token()
	return err
}
