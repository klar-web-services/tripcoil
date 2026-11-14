package grype

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Component is one package in a CycloneDX SBOM written by Grype.
type Component struct {
	Name, Version, PURL string
}

type cdxDocument struct {
	BOMFormat  string `json:"bomFormat"`
	Components []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"components"`
}

func parseSBOM(data []byte) (cdxDocument, error) {
	var doc cdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("unparseable SBOM from Grype: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return doc, errors.New("unparseable SBOM from Grype: not a CycloneDX document")
	}
	return doc, nil
}

// SBOMPackages lists the packages in an SBOM: its components that are neither files nor the
// operating system.
func SBOMPackages(data []byte) ([]Component, error) {
	doc, err := parseSBOM(data)
	if err != nil {
		return nil, err
	}
	var out []Component
	for _, c := range doc.Components {
		if c.Type != "file" && c.Type != "operating-system" {
			out = append(out, Component{Name: c.Name, Version: c.Version, PURL: c.PURL})
		}
	}
	return out, nil
}

var locationProperty = regexp.MustCompile(`^syft:location:[0-9]+:path$`)

// SBOMLocations lists, for each package of an SBOM, the files it was read from, as paths below
// the scanned directory with a leading slash, such as "/package-lock.json".
func SBOMLocations(data []byte) ([][]string, error) {
	var doc struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			Type       string `json:"type"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("unparseable SBOM from Grype: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return nil, errors.New("unparseable SBOM from Grype: not a CycloneDX document")
	}
	var out [][]string
	for _, c := range doc.Components {
		if c.Type == "file" || c.Type == "operating-system" {
			continue
		}
		var locs []string
		for _, p := range c.Properties {
			if locationProperty.MatchString(p.Name) && !slices.Contains(locs, p.Value) {
				locs = append(locs, p.Value)
			}
		}
		out = append(out, locs)
	}
	return out, nil
}

// SBOMComponents counts the packages in an SBOM.
func SBOMComponents(data []byte) (int, error) {
	pkgs, err := SBOMPackages(data)
	return len(pkgs), err
}

// Matchable reports whether matching an SBOM gives the same matches as scanning what it came
// from, so that the SBOM can be cached. It does not when the SBOM holds Go modules: Grype keeps
// only the Go matches whose code is linked into a binary, which it sees in the binary but not in
// an SBOM. Nor when its operating system has no version, as on Arch Linux and its derivatives:
// Grype then loses the distribution and matches none of its packages.
func Matchable(data []byte) (bool, error) {
	doc, err := parseSBOM(data)
	if err != nil {
		return false, err
	}
	for _, c := range doc.Components {
		if strings.HasPrefix(c.PURL, "pkg:golang/") || (c.Type == "operating-system" && c.Version == "") {
			return false, nil
		}
	}
	return true, nil
}

// StripSBOM drops what matching does not need from an SBOM written by Grype: its vulnerabilities
// and its file components. That makes it about ten times smaller and gives the same matches.
func StripSBOM(data []byte) ([]byte, error) {
	if _, err := parseSBOM(data); err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	delete(doc, "vulnerabilities")
	if comps, ok := doc["components"].([]any); ok {
		kept := []any{}
		for _, c := range comps {
			if m, ok := c.(map[string]any); !ok || m["type"] != "file" {
				kept = append(kept, c)
			}
		}
		doc["components"] = kept
	}
	return json.Marshal(doc)
}

// SetKernel returns the SBOM with the kernel package name at version from set to the running
// version: in its version and the source version Grype matches by. When source is not empty, it
// also becomes the package's source: Debian's kernel packages are built by linux-signed-<arch>,
// but Debian's vulnerability data names the source linux. It reports how many components it
// changed.
func SetKernel(data []byte, name, from, running, source string) ([]byte, int, error) {
	if _, err := parseSBOM(data); err != nil {
		return nil, 0, err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, 0, err
	}
	comps, _ := doc["components"].([]any)
	n := 0
	for _, c := range comps {
		m, ok := c.(map[string]any)
		if !ok || m["name"] != name || m["version"] != from {
			continue
		}
		m["version"] = running
		props, _ := m["properties"].([]any)
		hasSource := false
		for _, p := range props {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			switch pm["name"] {
			case "syft:metadata:sourceVersion":
				pm["value"] = running
			case "syft:metadata:source":
				hasSource = true
				if source != "" {
					pm["value"] = source
				}
			}
		}
		if source != "" && !hasSource {
			m["properties"] = append(props, map[string]any{"name": "syft:metadata:source", "value": source},
				map[string]any{"name": "syft:metadata:sourceVersion", "value": running})
		}
		n++
	}
	out, err := json.Marshal(doc)
	return out, n, err
}
