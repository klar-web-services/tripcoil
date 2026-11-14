package audit

import (
	"context"
	"encoding/json"
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
	rep, n, err := au.scanOrigin(ctx, o, res.Raw)
	if err != nil {
		au.removeRaw(res.Raw)
		if ctx.Err() == nil {
			au.failOrigin(o, err)
		}
		return
	}
	res.Packages = n.packages
	switch {
	case n.packages == 0:
		res.Status = Unidentified
	case rep.Distro == "" && n.os > 0:
		// As for the package database, never clean: no distribution data applies to its packages.
		// Its other packages are matched all the same.
		res.Status, res.Reason = Unidentified, fmt.Sprintf("Grype did not recognise the distribution, so its vulnerability data does not apply to its %d operating system packages", n.os)
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
// directly every run instead. A cached SBOM that is itself at fault (see badSBOM) is dropped and
// the origin scanned again; on any other failure the origin fails, and the entry is kept.
func (au *auditor) scanOrigin(ctx context.Context, o inventory.Origin, raw *Raw) (*grype.Report, counts, error) {
	if o.Kind == inventory.OriginImage && au.d.Images != nil {
		// For an image the daemon does not have, it would try a pull from Docker Hub.
		ok, err := au.d.Images.ImageExists(ctx, o.ImageID)
		switch {
		case err != nil:
			return nil, counts{}, fmt.Errorf("cannot check that the Docker daemon still has the image: %w", err)
		case !ok:
			return nil, counts{}, errors.New("the image was removed after the inventory")
		}
	}
	if o.Kind == inventory.OriginAppDir && o.Jar {
		sha, err := hashFile(ctx, filepath.Join(au.d.Root, o.Path))
		if err != nil {
			return nil, counts{}, err
		}
		o.SHA256 = sha // a jar is keyed and copied like a binary
	}
	key, files, err := au.cacheKey(o)
	if err != nil {
		return nil, counts{}, err
	}
	if key != "" {
		if sbom, ok := au.cache.get(key); ok {
			rep, n, err := au.matchCached(ctx, sbom, raw)
			if !errors.As(err, new(badSBOM)) {
				return rep, n, err
			}
			au.cache.remove(key)
		}
	}
	source, cleanup, err := au.source(ctx, o)
	if err != nil {
		return nil, counts{}, err
	}
	defer cleanup()
	if err := os.MkdirAll(au.scanDir(), 0o700); err != nil {
		return nil, counts{}, err
	}
	tmp := filepath.Join(au.scanDir(), rawName(o.ID, ".cdx.json"))
	defer os.Remove(tmp)
	rawPath := filepath.Join(au.d.RunDir, raw.Grype)
	rep, err := au.d.Grype.Scan(ctx, source, rawPath, tmp)
	if err != nil {
		return nil, counts{}, err
	}
	if err := run.Share(rawPath, 0o640); err != nil {
		return nil, counts{}, err
	}
	data, err := os.ReadFile(tmp)
	if err == nil {
		data, err = grype.StripSBOM(data)
	}
	var n counts
	if err == nil {
		n, err = countPackages(data)
	}
	if err == nil {
		err = run.WriteFile(filepath.Join(au.d.RunDir, raw.SBOM), data, 0o640)
	}
	if err != nil {
		return nil, counts{}, err
	}
	au.cacheIfMatchable(key, files, data)
	return rep, n, nil
}

// counts is how many packages an SBOM holds, and how many of them Syft read from a distribution's
// package database: only that distribution's vulnerability data matches those.
type counts struct{ packages, os int }

// osPackageTypes are Syft's types of the packages in a distribution's package database.
var osPackageTypes = []string{"deb", "rpm", "apk", "alpm"}

func countPackages(data []byte) (counts, error) {
	pkgs, err := grype.SBOMPackages(data)
	if err != nil {
		return counts{}, err
	}
	var doc struct {
		Components []struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return counts{}, err
	}
	n := counts{packages: len(pkgs)}
	for _, c := range doc.Components {
		for _, p := range c.Properties {
			if p.Name == "syft:package:type" && slices.Contains(osPackageTypes, p.Value) {
				n.os++
			}
		}
	}
	return n, nil
}

// matchCached matches a cached SBOM.
func (au *auditor) matchCached(ctx context.Context, sbom string, raw *Raw) (*grype.Report, counts, error) {
	data, n, err := readCached(sbom)
	if err != nil {
		return nil, counts{}, err
	}
	rep, err := au.matchSBOM(ctx, sbom, data, raw)
	return rep, n, err
}

// badSBOM is the failure of a cached SBOM itself: it cannot be read or decoded, or Grype cannot
// decode it. Only then is the entry dropped. Any other failure, such as a full run folder, a
// timeout or an interruption, keeps it for the next run.
type badSBOM struct{ error }

func (e badSBOM) Unwrap() error { return e.error }

// readCached reads and decodes a cached SBOM.
func readCached(path string) ([]byte, counts, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, counts{}, badSBOM{err}
	}
	n, err := countPackages(data)
	if err != nil {
		return nil, counts{}, badSBOM{err}
	}
	return data, n, nil
}

// rejected marks Grype's failure to decode an SBOM as badSBOM.
func rejected(err error) error {
	if err != nil && strings.Contains(err.Error(), "unable to decode sbom") {
		return badSBOM{err}
	}
	return err
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
// key hashes, as Grype names its locations. A binary's or jar's key holds its file name too,
// because the SBOM depends on it (see source).
func (au *auditor) cacheKey(o inventory.Origin) (string, []string, error) {
	switch o.Kind {
	case inventory.OriginBinary:
		return keyOf("binary", o.SHA256, fileName(o)), nil, nil
	case inventory.OriginImage:
		return keyOf("image", o.ImageID), nil, nil
	case inventory.OriginAppDir:
		if o.Jar {
			return keyOf("jar", o.SHA256, fileName(o)), nil, nil
		}
		return appDirKey(filepath.Join(au.d.Root, o.Path))
	}
	return "", nil, fmt.Errorf("origin kind %q cannot be scanned", o.Kind)
}

// fileName is the name of a binary or jar on the host: of a binary, its first path.
func fileName(o inventory.Origin) string {
	switch {
	case o.Kind == inventory.OriginAppDir:
		return filepath.Base(o.Path)
	case len(o.Paths) > 0:
		return filepath.Base(o.Paths[0])
	}
	return o.SHA256
}

// source is what Grype scans for an origin: a verified copy of a binary or jar, an app directory,
// or an image by ID from the local Docker daemon. A copy is scan/<sha>/<file name>, because
// Syft's Java cataloger and binary classifiers go by the file name (*.jar, python*, node, ...).
// cleanup removes it.
func (au *auditor) source(ctx context.Context, o inventory.Origin) (string, func(), error) {
	none := func() {}
	switch {
	case o.Kind == inventory.OriginImage:
		return "docker:" + o.ImageID, none, nil
	case o.Kind == inventory.OriginAppDir && !o.Jar:
		return "dir:" + filepath.Join(au.d.Root, o.Path), none, nil
	}
	dir := filepath.Join(au.scanDir(), o.SHA256)
	path := filepath.Join(dir, fileName(o))
	var err error
	if o.Jar {
		err = copyVerified(ctx, openPath(filepath.Join(au.d.Root, o.Path)), o.SHA256, path)
	} else {
		err = au.binaryFile(ctx, o, path)
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", none, err
	}
	return "file:" + path, func() { os.RemoveAll(dir) }, nil
}

// binaryFile puts the binary's content at path: the Inventory's copy of a replaced file, or a
// verified copy of the file that runs. The copy is read through a process that runs or maps it,
// as the Inventory read it, because the path is the process's: a service with PrivateTmp sees
// its own /tmp. Only when no such process is left is the file read at its path on the host.
func (au *auditor) binaryFile(ctx context.Context, o inventory.Origin, path string) error {
	if o.Copy != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if os.Link(o.Copy, path) == nil {
			return nil
		}
		return copyVerified(ctx, openPath(o.Copy), o.SHA256, path)
	}
	err := errors.New("it has no path")
	au.eachOpener(o, func(open func() (*os.File, error)) bool {
		err = copyVerified(ctx, open, o.SHA256, path)
		return err == nil || ctx.Err() != nil
	})
	switch {
	case err == nil:
		return nil
	case ctx.Err() != nil:
		return ctx.Err()
	}
	return fmt.Errorf("cannot read the file that ran: %w", err)
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
// process's mappings are read once per Audit: a library is shared by many processes. A mapping of
// a file replaced since the Inventory (deleted) is read too: the copy is verified by its SHA-256.
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
		if m.Path == path {
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
		return nil, rejected(err)
	}
	return rep, run.Share(rawPath, 0o640)
}
