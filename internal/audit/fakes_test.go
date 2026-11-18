package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/kernelcna"
	"github.com/klar-web-services/tripcoil/internal/procfs"
	"github.com/klar-web-services/tripcoil/internal/run"
)

func init() { run.AgentGID = func() (int, bool) { return 0, false } }

type fakeScanner struct {
	status     grype.DBStatus
	updateErr  error
	prepareErr error
	sboms      map[string][]grype.Component
	osVersion  string
	distro     string
	locations  map[string]string
	found      map[string][]string
	cpes       map[string]string
	catalogErr map[string]error
	vulns      map[string][]grype.Vulnerability
	lookups    map[string]grype.Vulnerability
	lookupErr  error
	matchErr   map[string]error
	purlAs     map[string]string
	catalogs   []string
	matched    []string
	lookedUp   []string
	copiesLeft []string
	scanning   func(source string)
	matching   func(*grype.Report)
	asUsers    map[string][]bool
	sbomVulns  int
	onMatch    func(sbom string)
}

func (f *fakeScanner) Prepare(context.Context) (grype.DBStatus, error, error) {
	return f.status, f.updateErr, f.prepareErr
}

func (f *fakeScanner) Scan(ctx context.Context, source, raw, sbom string) (*grype.Report, error) {
	f.catalogs = append(f.catalogs, source)
	if f.scanning != nil {
		f.scanning(source)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for prefix, err := range f.catalogErr {
		if strings.HasPrefix(source, prefix) {
			os.WriteFile(raw, nil, 0o600)
			return nil, err
		}
	}
	if path, ok := strings.CutPrefix(source, "local-file:"); ok {
		if _, err := os.Stat(path); err != nil {
			return nil, err
		}
		dir := filepath.Dir(path)
		copies, _ := filepath.Glob(filepath.Join(filepath.Dir(dir), "*", "*"))
		for _, c := range copies {
			if filepath.Dir(c) != dir {
				f.copiesLeft = append(f.copiesLeft, c)
			}
		}
	}
	comps, ok := f.sboms[source]
	if !ok {
		return nil, errors.New("the fake has no SBOM for " + source)
	}
	type prop struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type comp struct {
		Type       string `json:"type"`
		Name       string `json:"name"`
		Version    string `json:"version"`
		PURL       string `json:"purl"`
		CPE        string `json:"cpe,omitempty"`
		Properties []prop `json:"properties,omitempty"`
	}
	doc := struct {
		BOMFormat       string `json:"bomFormat"`
		Serial          string `json:"serialNumber"`
		Components      []comp `json:"components"`
		Vulnerabilities []any  `json:"vulnerabilities"`
	}{"CycloneDX", source, []comp{{Type: "operating-system", Name: "debian", Version: f.osVersion}, {Type: "file", Name: "/etc/os-release"}}, []any{"x"}}
	for range f.sbomVulns {
		doc.Vulnerabilities = append(doc.Vulnerabilities, strings.Repeat("x", 5000))
	}
	for _, c := range comps {
		cc := comp{Type: "library", Name: c.Name, Version: c.Version, PURL: c.PURL, CPE: f.cpes[c.Name]}
		if typ, _, ok := strings.Cut(strings.TrimPrefix(c.PURL, "pkg:"), "/"); ok {
			if typ == "ebuild" {
				typ = "portage"
			}
			cc.Properties = append(cc.Properties, prop{"syft:package:type", typ})
		}
		if l, ok := f.locations[c.Name]; ok {
			cc.Properties = append(cc.Properties, prop{"syft:location:0:path", l})
		}
		doc.Components = append(doc.Components, cc)
	}
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(sbom, data, 0o600); err != nil {
		return nil, err
	}
	return f.match(ctx, sbom, raw)
}

func (f *fakeScanner) Match(ctx context.Context, sbom, raw string, users bool) (*grype.Report, error) {
	if f.onMatch != nil {
		f.onMatch(sbom)
	}
	if f.asUsers != nil {
		if data, err := os.ReadFile(sbom); err == nil {
			comps, _ := grype.SBOMPackages(data)
			for _, c := range comps {
				f.asUsers[c.Name] = append(f.asUsers[c.Name], users)
			}
		}
	}
	rep, err := f.match(ctx, sbom, raw)
	if err == nil && f.matching != nil {
		f.matching(rep)
	}
	return rep, err
}

func (f *fakeScanner) match(ctx context.Context, sbom, raw string) (*grype.Report, error) {
	f.matched = append(f.matched, filepath.Base(sbom))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.matchErr[filepath.Base(sbom)]; err != nil {
		os.WriteFile(raw, nil, 0o600)
		return nil, err
	}
	data, err := os.ReadFile(sbom)
	if err != nil {
		return nil, err
	}
	comps, err := grype.SBOMPackages(data)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Components []struct {
			Type string `json:"type"`
			CPE  string `json:"cpe"`
		} `json:"components"`
	}
	json.Unmarshal(data, &doc)
	var cpes []string
	for _, c := range doc.Components {
		if c.Type != "file" && c.Type != "operating-system" {
			cpes = append(cpes, c.CPE)
		}
	}
	rep := &grype.Report{DBBuilt: f.status.Built, Distro: f.distro}
	if f.distro != "" {
		rep.DistroVersion = f.osVersion
	}
	for i, c := range comps {
		typ, _, _ := strings.Cut(strings.TrimPrefix(c.PURL, "pkg:"), "/")
		purl := c.PURL
		if p, ok := f.purlAs[purl]; ok {
			purl = p
		}
		locations := []string{"/where/" + c.Name}
		if l, ok := f.found[c.Name]; ok {
			locations = l
		}
		var cpe []string
		if cpes[i] != "" {
			cpe = []string{cpes[i]}
		}
		for _, v := range slices.Concat(f.vulns[c.Name+"@"+c.Version], f.vulns[c.PURL], f.vulns[cpes[i]]) {
			rep.Matches = append(rep.Matches, grype.Match{Vulnerability: v,
				Artifact: grype.Artifact{Name: c.Name, Version: c.Version, Type: typ, PURL: purl, CPEs: cpe, Locations: slices.Clone(locations)}})
		}
	}
	return rep, os.WriteFile(raw, []byte(`{"matches":[]}`), 0o600)
}

func (f *fakeScanner) Lookup(_ context.Context, ids []string) (map[string]grype.Vulnerability, error) {
	f.lookedUp = append(f.lookedUp, ids...)
	return f.lookups, f.lookupErr
}

type fakeImages struct {
	ids map[string]bool
	err error
}

func (f fakeImages) ImageExists(_ context.Context, id string) (bool, error) { return f.ids[id], f.err }

type fakeKernel struct {
	data *kernelcna.Data
	err  error
}

func (k fakeKernel) Load(context.Context, time.Time, time.Duration) (*kernelcna.Data, error) {
	return k.data, k.err
}

type fakeProc struct {
	exes   map[int]string
	maps   map[int][]procfs.Mapping
	mapped map[string]string
}

func (p fakeProc) OpenExe(pid int) (io.ReadCloser, error) {
	if f, ok := p.exes[pid]; ok {
		return os.Open(f)
	}
	return nil, os.ErrNotExist
}

func (p fakeProc) Maps(pid int) ([]procfs.Mapping, error) { return p.maps[pid], nil }

func (p fakeProc) OpenMapFile(pid int, m procfs.Mapping) (io.ReadCloser, error) {
	if f, ok := p.mapped[m.Path]; ok {
		return os.Open(f)
	}
	return nil, os.ErrNotExist
}
