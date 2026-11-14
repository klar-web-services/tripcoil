package grype

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// Component is one package in a CycloneDX SBOM written by Grype.
type Component struct {
	Name, Version, PURL string
	Type                string // Syft's package type, such as deb or npm
}

type cdxComponent struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	PURL       string `json:"purl"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

type cdxDocument struct {
	BOMFormat  string         `json:"bomFormat"`
	Components []cdxComponent `json:"components"`
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

// ReadSBOM reads the SBOM that Grype wrote to path of the package database or an image without its
// vulnerabilities, which it reads past an element at a time: they repeat the report's matches. An
// Ubuntu 22.04 host with two kernels gives 28,000 of them, in an SBOM of 34 MB of which 1 MB is
// packages. A file larger than maxSystemReportSize is not read, and what is left must be at most
// limit bytes.
func ReadSBOM(path string, limit int64) ([]byte, error) {
	f, err := openOutput(path, "Grype's SBOM", maxSystemReportSize)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tooLarge := fmt.Errorf("Grype's SBOM is larger than %d bytes without its vulnerabilities", limit)
	out := []byte{'{'}
	dec := json.NewDecoder(io.LimitReader(f, maxSystemReportSize))
	err = members(dec, func(key string) error {
		if key == "vulnerabilities" {
			return skip(dec)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		name, _ := json.Marshal(key)
		if len(out) > 1 {
			out = append(out, ',')
		}
		if out = append(append(append(out, name...), ':'), value...); int64(len(out)) >= limit {
			return tooLarge
		}
		return nil
	})
	if err == nil {
		if _, end := dec.Token(); end != io.EOF {
			err = errors.New("more follows the SBOM")
		}
	}
	switch {
	case err == tooLarge:
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("unparseable SBOM from Grype: %w", err)
	}
	return append(out, '}'), nil
}

// sbomPackages returns the packages in an SBOM: its components that are neither files nor the
// operating system.
func sbomPackages(data []byte) ([]cdxComponent, error) {
	doc, err := parseSBOM(data)
	if err != nil {
		return nil, err
	}
	var out []cdxComponent
	for _, c := range doc.Components {
		if c.Type != "file" && c.Type != "operating-system" {
			out = append(out, c)
		}
	}
	return out, nil
}

// SBOMPackages lists the packages in an SBOM: its components that are neither files nor the
// operating system.
func SBOMPackages(data []byte) ([]Component, error) {
	pkgs, err := sbomPackages(data)
	if err != nil {
		return nil, err
	}
	var out []Component
	for _, c := range pkgs {
		comp := Component{Name: c.Name, Version: c.Version, PURL: c.PURL}
		for _, p := range c.Properties {
			if p.Name == "syft:package:type" {
				comp.Type = p.Value
			}
		}
		out = append(out, comp)
	}
	return out, nil
}

var locationProperty = regexp.MustCompile(`^syft:location:[0-9]+:path$`)

// SBOMLocations lists, for each package of SBOMPackages in the same order, the files it was read
// from, as paths below the scanned directory with a leading slash, such as "/package-lock.json".
func SBOMLocations(data []byte) ([][]string, error) {
	pkgs, err := sbomPackages(data)
	if err != nil {
		return nil, err
	}
	var out [][]string
	for _, c := range pkgs {
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

// Matchable reports false for an SBOM known to match otherwise than a scan of what it came from. It
// only filters: the Audit still matches any other SBOM and compares its matches with the scan's
// before caching it. An SBOM that holds Go modules matches otherwise: Grype keeps only the Go
// matches whose code is linked into a binary, which it sees in the binary but not in an SBOM. So
// may an SBOM whose operating system has no version: matching it may lose the distribution of a
// derivative, as it did for CachyOS.
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
// and its file components. That makes it about ten times smaller and gives the same matches. It
// also drops the distro qualifier from purls: Grype matches a package against the distribution
// the qualifier names, and finds nothing for a derivative it does not know, such as Pop!_OS;
// without it, Grype uses the distribution it detected, as a scan does.
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
			m, ok := c.(map[string]any)
			if ok && m["type"] == "file" {
				continue
			}
			for _, k := range []string{"purl", "bom-ref"} {
				if s, ok := m[k].(string); ok {
					m[k] = WithoutDistro(s)
				}
			}
			kept = append(kept, c)
		}
		doc["components"] = kept
	}
	// The dependencies name packages by their bom-ref.
	deps, _ := doc["dependencies"].([]any)
	for _, d := range deps {
		m, _ := d.(map[string]any)
		if s, ok := m["ref"].(string); ok {
			m["ref"] = WithoutDistro(s)
		}
		on, _ := m["dependsOn"].([]any)
		for i, r := range on {
			if s, ok := r.(string); ok {
				on[i] = WithoutDistro(s)
			}
		}
	}
	return json.Marshal(doc)
}

// WithoutDistro returns s without its distro qualifier when s is a purl, and s otherwise.
func WithoutDistro(s string) string {
	rest, subpath, hasSubpath := strings.Cut(s, "#")
	base, query, ok := strings.Cut(rest, "?")
	if !strings.HasPrefix(s, "pkg:") || !ok {
		return s
	}
	qs := slices.DeleteFunc(strings.Split(query, "&"), func(q string) bool { return strings.HasPrefix(q, "distro=") })
	if len(qs) > 0 {
		base += "?" + strings.Join(qs, "&")
	}
	if hasSubpath {
		base += "#" + subpath
	}
	return base
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
		hasSource, hasSourceVersion := false, false
		for _, p := range props {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			switch pm["name"] {
			case "syft:metadata:sourceVersion":
				hasSourceVersion = true
				pm["value"] = running
			case "syft:metadata:source":
				hasSource = true
				if source != "" {
					pm["value"] = source
				}
			}
		}
		if source != "" && !hasSource {
			props = append(props, map[string]any{"name": "syft:metadata:source", "value": source})
			if !hasSourceVersion {
				props = append(props, map[string]any{"name": "syft:metadata:sourceVersion", "value": running})
			}
			m["properties"] = props
		}
		n++
	}
	out, err := json.Marshal(doc)
	return out, n, err
}
