package audit

import (
	"context"
	"fmt"

	"github.com/klar-web-services/tripcoil/internal/grype"
)

type grypeScanner struct {
	installer *grype.Installer
	runner    *grype.Runner
}

func NewGrype(cacheDir string) Scanner {
	return &grypeScanner{installer: grype.NewInstaller(cacheDir), runner: &grype.Runner{CacheDir: cacheDir,
		HasRoom: func(dir string) bool { return hasRoom(dir, 0) == nil }}}
}

func (g *grypeScanner) Prepare(ctx context.Context) (grype.DBStatus, error, error) {
	bin, err := g.installer.Ensure(ctx)
	if err != nil {
		return grype.DBStatus{}, nil, err
	}
	g.runner.Binary = bin
	updateErr := g.runner.UpdateDB(ctx)
	st, err := g.runner.DBStatus(ctx)
	if err != nil && updateErr != nil {
		err = fmt.Errorf("%w (updating the database failed: %v)", err, updateErr)
	}
	return st, updateErr, err
}

func (g *grypeScanner) Scan(ctx context.Context, source, raw, sbom string) (*grype.Report, error) {
	return g.runner.Scan(ctx, source, raw, sbom)
}

func (g *grypeScanner) Match(ctx context.Context, sbom, raw string, users bool) (*grype.Report, error) {
	return g.runner.Match(ctx, sbom, raw, users)
}

func (g *grypeScanner) Lookup(ctx context.Context, ids []string) (map[string]grype.Vulnerability, error) {
	return g.runner.SearchVulnerabilities(ctx, ids)
}
