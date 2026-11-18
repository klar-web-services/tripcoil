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

type Component struct {
	Name, Version, PURL string
	Type                string
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
