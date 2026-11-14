package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/run"
)

// origin scans a binary, app directory, jar or image (spec section 6.2).
func (au *auditor) origin(ctx context.Context, o inventory.Origin) {
	res := OriginResult{ID: o.ID, Kind: o.Kind, Status: Scanned, Raw: rawFiles(o.ID)}
	rep, packages, err := au.scanOrigin(ctx, o, res.Raw)
	if err != nil {
		au.removeRaw(res.Raw)
		if ctx.Err() == nil {
			au.failOrigin(o, err)
		}
		return
	}
	res.Packages = packages
	if packages == 0 {
		res.Status = Unidentified
	}
	au.a.Origins = append(au.a.Origins, res)
	au.addFindings(rep.Matches, res.Raw.Grype, func(grype.Match) (string, bool) { return o.ID, true })
}

// rawFiles names an origin's files in the run folder: the first 8 hex digits of the SHA-256 of
// its ID, as raw/<hash>.grype.json and raw/<hash>.cdx.json.
func rawFiles(id string) *Raw {
	return &Raw{Grype: "raw/" + rawName(id, ".grype.json"), SBOM: "raw/" + rawName(id, ".cdx.json")}
}

// removeRaw removes what a failed scan left in the run folder: Grype empties its output files
// when it fails.
func (au *auditor) removeRaw(raw *Raw) {
	os.Remove(filepath.Join(au.d.RunDir, raw.Grype))
	os.Remove(filepath.Join(au.d.RunDir, raw.SBOM))
}

func (au *auditor) scanDir() string { return filepath.Join(au.d.CacheDir, "scan") }

// scanOrigin returns an origin's matches and how many packages it holds, and leaves Grype's
// report and the SBOM in the run folder. Cataloging is the slow part of a scan, so an origin's
// SBOM is cached under a content key, and later runs only match it; an origin whose SBOM does not
// match like the origin itself (Go modules, an operating system without a version) is scanned
// directly every run instead. A cached SBOM that cannot be read or matched is dropped and the
// origin scanned again.
func (au *auditor) scanOrigin(ctx context.Context, o inventory.Origin, raw *Raw) (*grype.Report, int, error) {
	key, files, err := au.cacheKey(ctx, o)
	if err != nil {
		return nil, 0, err
	}
	if key != "" {
		if sbom, ok := au.cache.get(key); ok {
			rep, n, err := au.matchCached(ctx, sbom, raw)
			if err == nil || ctx.Err() != nil {
				return rep, n, err
			}
			au.cache.remove(key)
		}
	}
	source, cleanup, err := au.source(ctx, o, key)
	if err != nil {
		return nil, 0, err
	}
	defer cleanup()
	if err := os.MkdirAll(au.scanDir(), 0o700); err != nil {
		return nil, 0, err
	}
	tmp := filepath.Join(au.scanDir(), rawName(o.ID, ".cdx.json"))
	defer os.Remove(tmp)
	rawPath := filepath.Join(au.d.RunDir, raw.Grype)
	rep, err := au.d.Grype.Scan(ctx, source, rawPath, tmp)
	if err != nil {
		return nil, 0, err
	}
	if err := run.Share(rawPath, 0o640); err != nil {
		return nil, 0, err
	}
	data, err := os.ReadFile(tmp)
	if err == nil {
		data, err = grype.StripSBOM(data)
	}
	var pkgs []grype.Component
	if err == nil {
		pkgs, err = grype.SBOMPackages(data)
	}
	if err == nil {
		err = run.WriteFile(filepath.Join(au.d.RunDir, raw.SBOM), data, 0o640)
	}
	if err != nil {
		return nil, 0, err
	}
	au.cacheIfMatchable(key, files, data)
	return rep, len(pkgs), nil
}

// matchCached matches a cached SBOM.
func (au *auditor) matchCached(ctx context.Context, sbom string, raw *Raw) (*grype.Report, int, error) {
	data, err := os.ReadFile(sbom)
	if err != nil {
		return nil, 0, err
	}
	pkgs, err := grype.SBOMPackages(data)
	if err != nil {
		return nil, 0, err
	}
	rep, err := au.matchSBOM(ctx, sbom, data, raw)
	return rep, len(pkgs), err
}

// cacheIfMatchable caches a stripped SBOM under key, unless there is no key or matching the SBOM
// would not give the scan's matches (see grype.Matchable): such an origin is scanned every run.
// When files is set, every package must have been read from one of them: an app directory's key
// hashes only its own lockfiles and manifests, and Grype also reads nested lockfiles and
// virtual environments, which would change unseen. The cache only saves time, so a failed write
// is not an error.
func (au *auditor) cacheIfMatchable(key string, files []string, data []byte) {
	if key == "" {
		return
	}
	if ok, err := grype.Matchable(data); err != nil || !ok {
		return
	}
	if files != nil {
		locations, err := grype.SBOMLocations(data)
		if err != nil {
			return
		}
		for _, pkg := range locations {
			if len(pkg) == 0 {
				return // a package without a file it came from
			}
			for _, l := range pkg {
				if !slices.Contains(files, l) {
					return
				}
			}
		}
	}
	_ = au.cache.put(key, data)
}

// cacheKey is an origin's SBOM cache key (spec section 6.2), or "" when it is cataloged every
// run: an app directory without a lockfile. For an app directory it also returns the files the
// key hashes, as Grype names its locations.
func (au *auditor) cacheKey(ctx context.Context, o inventory.Origin) (string, []string, error) {
	switch o.Kind {
	case inventory.OriginBinary:
		return "binary-" + o.SHA256, nil, nil
	case inventory.OriginImage:
		return keyOf("image", o.ImageID), nil, nil
	case inventory.OriginAppDir:
		host := filepath.Join(au.d.Root, o.Path)
		if o.Jar {
			sha, err := hashFile(ctx, host)
			if err != nil {
				return "", nil, err
			}
			return "jar-" + sha, nil, nil
		}
		return appDirKey(host)
	}
	return "", nil, fmt.Errorf("origin kind %q cannot be scanned", o.Kind)
}

// source is what Grype scans for an origin: a verified copy of a binary or jar, an app directory,
// or an image by ID from the local Docker daemon. cleanup removes a copy made for the scan.
func (au *auditor) source(ctx context.Context, o inventory.Origin, key string) (string, func(), error) {
	none := func() {}
	switch {
	case o.Kind == inventory.OriginBinary:
		return au.binaryFile(ctx, o)
	case o.Kind == inventory.OriginAppDir && o.Jar:
		path, err := copyVerified(ctx, openPath(filepath.Join(au.d.Root, o.Path)), strings.TrimPrefix(key, "jar-"), au.scanDir())
		if err != nil {
			return "", none, err
		}
		return "file:" + path, func() { os.Remove(path) }, nil
	case o.Kind == inventory.OriginAppDir:
		return "dir:" + filepath.Join(au.d.Root, o.Path), none, nil
	}
	return "docker:" + o.ImageID, none, nil
}

// binaryFile returns a file with the binary's content: the Inventory's copy of a replaced file,
// or a verified copy of the file that runs. The copy is read through a process that runs or maps
// it, as the Inventory read it, because the path is the process's: a service with PrivateTmp
// sees its own /tmp. Only when no such process is left is the file read at its path on the host.
func (au *auditor) binaryFile(ctx context.Context, o inventory.Origin) (string, func(), error) {
	none := func() {}
	if o.Copy != "" {
		return "file:" + o.Copy, none, nil
	}
	err := errors.New("it has no path")
	var path string
	au.eachOpener(o, func(open func() (*os.File, error)) bool {
		path, err = copyVerified(ctx, open, o.SHA256, au.scanDir())
		return err == nil || ctx.Err() != nil
	})
	switch {
	case err == nil:
		return "file:" + path, func() { os.Remove(path) }, nil
	case ctx.Err() != nil:
		return "", none, ctx.Err()
	}
	return "", none, fmt.Errorf("cannot read the file that ran: %w", err)
}

// eachOpener offers try the ways to open an unpackaged file, until try returns true: through each
// process of the origin's items that runs or maps it, then at each of its paths on the host.
func (au *auditor) eachOpener(o inventory.Origin, try func(func() (*os.File, error)) bool) {
	if au.d.Proc != nil {
		for _, it := range au.rem.users[o.ID] {
			for _, p := range it.Processes {
				for _, path := range o.Paths {
					if open := au.procOpener(p.PID, it.Exe, path); open != nil && try(open) {
						return
					}
				}
			}
		}
	}
	for _, p := range o.Paths {
		if try(openPath(filepath.Join(au.d.Root, p))) {
			return
		}
	}
}

// procOpener opens a file that process pid runs (exe) or maps, or is nil when it does neither. A
// process's mappings are read once per Audit: a library is shared by many processes.
func (au *auditor) procOpener(pid int, exe, path string) func() (*os.File, error) {
	if path == exe {
		return func() (*os.File, error) { return asFile(au.d.Proc.OpenExe(pid)) }
	}
	maps, ok := au.maps[pid]
	if !ok {
		maps, _ = au.d.Proc.Maps(pid)
		au.maps[pid] = maps
	}
	for _, m := range maps {
		if m.Path == path && !m.Deleted {
			return func() (*os.File, error) { return asFile(au.d.Proc.OpenMapFile(pid, m)) }
		}
	}
	return nil
}

// asFile takes the file procfs opened.
func asFile(rc io.ReadCloser, err error) (*os.File, error) {
	if err != nil {
		return nil, err
	}
	f, ok := rc.(*os.File)
	if !ok {
		rc.Close()
		return nil, errors.New("not a file")
	}
	return f, nil
}

// matchSBOM keeps a copy of an SBOM in the run folder and matches it.
func (au *auditor) matchSBOM(ctx context.Context, sbom string, data []byte, raw *Raw) (*grype.Report, error) {
	if err := run.WriteFile(filepath.Join(au.d.RunDir, raw.SBOM), data, 0o640); err != nil {
		return nil, err
	}
	rawPath := filepath.Join(au.d.RunDir, raw.Grype)
	rep, err := au.d.Grype.Match(ctx, sbom, rawPath)
	if err != nil {
		return nil, err
	}
	return rep, run.Share(rawPath, 0o640)
}
