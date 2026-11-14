package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/kernelcna"
	"github.com/klar-web-services/tripcoil/internal/procfs"
)

// fakeScanner imitates Grype. Scan writes the SBOM listed for the source and matches it; Match
// matches every package of the SBOM it is given against vulns, keyed by name@version, so a
// cached or rewritten SBOM gives the matches it holds.
type fakeScanner struct {
	status     grype.DBStatus
	updateErr  error
	prepareErr error
	sboms      map[string][]grype.Component // by source; sources are compared by prefix
	osVersion  string                       // the version of the SBOMs' operating system; Arch has none
	distro     string                       // the distribution Grype reports; "" when it saw none
	locations  map[string]string            // the file each package (by name) was read from
	catalogErr map[string]error
	vulns      map[string][]grype.Vulnerability
	lookups    map[string]grype.Vulnerability
	lookupErr  error
	catalogs   []string // the sources cataloged, in order
	lookedUp   []string
}

func (f *fakeScanner) Prepare(context.Context) (grype.DBStatus, error, error) {
	return f.status, f.updateErr, f.prepareErr
}

func (f *fakeScanner) Scan(ctx context.Context, source, raw, sbom string) (*grype.Report, error) {
	f.catalogs = append(f.catalogs, source)
	for prefix, err := range f.catalogErr {
		if strings.HasPrefix(source, prefix) {
			os.WriteFile(raw, nil, 0o600) // Grype empties its output files when it fails
			return nil, err
		}
	}
	for prefix, comps := range f.sboms {
		if strings.HasPrefix(source, prefix) {
			type prop struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			}
			type comp struct {
				Type       string `json:"type"`
				Name       string `json:"name"`
				Version    string `json:"version"`
				PURL       string `json:"purl"`
				Properties []prop `json:"properties,omitempty"`
			}
			doc := struct {
				BOMFormat       string `json:"bomFormat"`
				Serial          string `json:"serialNumber"`
				Components      []comp `json:"components"`
				Vulnerabilities []any  `json:"vulnerabilities"`
			}{"CycloneDX", source, []comp{{Type: "operating-system", Name: "debian", Version: f.osVersion}, {Type: "file", Name: "/etc/os-release"}}, []any{"x"}}
			for _, c := range comps {
				cc := comp{Type: "library", Name: c.Name, Version: c.Version, PURL: c.PURL}
				if l, ok := f.locations[c.Name]; ok {
					cc.Properties = []prop{{"syft:location:0:path", l}}
				}
				doc.Components = append(doc.Components, cc)
			}
			data, _ := json.Marshal(doc)
			if err := os.WriteFile(sbom, data, 0o600); err != nil {
				return nil, err
			}
			return f.Match(ctx, sbom, raw)
		}
	}
	return nil, errors.New("the fake has no SBOM for " + source)
}

func (f *fakeScanner) Match(_ context.Context, sbom, raw string) (*grype.Report, error) {
	data, err := os.ReadFile(sbom)
	if err != nil {
		return nil, err
	}
	comps, err := grype.SBOMPackages(data)
	if err != nil {
		return nil, err
	}
	rep := &grype.Report{DBBuilt: f.status.Built, Distro: f.distro}
	for _, c := range comps {
		typ, _, _ := strings.Cut(strings.TrimPrefix(c.PURL, "pkg:"), "/")
		for _, v := range f.vulns[c.Name+"@"+c.Version] {
			rep.Matches = append(rep.Matches, grype.Match{Vulnerability: v,
				Artifact: grype.Artifact{Name: c.Name, Version: c.Version, Type: typ, PURL: c.PURL, Locations: []string{"/where/" + c.Name}}})
		}
	}
	return rep, os.WriteFile(raw, []byte(`{"matches":[]}`), 0o600)
}

func (f *fakeScanner) Lookup(_ context.Context, ids []string) (map[string]grype.Vulnerability, error) {
	f.lookedUp = append(f.lookedUp, ids...)
	return f.lookups, f.lookupErr
}

// fakeKernel is kernel CNA data, or the error of loading it.
type fakeKernel struct {
	data *kernelcna.Data
	err  error
}

func (k fakeKernel) Load(context.Context, time.Time, time.Duration) (*kernelcna.Data, error) {
	return k.data, k.err
}

// fakeProc opens the running files of processes, by PID.
type fakeProc struct {
	exes   map[int]string           // pid: the file /proc/<pid>/exe opens
	maps   map[int][]procfs.Mapping // pid: its mappings
	mapped map[string]string        // mapping path: the file /proc/<pid>/map_files/<range> opens
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
