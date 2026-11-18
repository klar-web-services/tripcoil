package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/run"
)

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
		res.Status, res.Reason = Unidentified, fmt.Sprintf("Grype did not recognise the distribution, so its vulnerability data does not apply to its %d operating system packages", n.os)
	}
	au.a.Origins = append(au.a.Origins, res)
	au.addFindings(rep.Matches, res.Raw.Grype, func(grype.Match) (string, bool) { return o.ID, true })
}

func rawFiles(id string) *Raw {
	return &Raw{Grype: "raw/" + rawName(id, ".grype.json"), SBOM: "raw/" + rawName(id, ".cdx.json")}
}

func (au *auditor) removeRaw(raw *Raw) {
	os.Remove(filepath.Join(au.d.RunDir, raw.Grype))
	os.Remove(filepath.Join(au.d.RunDir, raw.SBOM))
}

func (au *auditor) scanDir() string { return filepath.Join(au.d.CacheDir, "scan") }

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
		sha, err := hashFile(ctx, au.reads, filepath.Join(au.d.Root, o.Path))
		if err != nil {
			return nil, counts{}, err
		}
		o.SHA256 = sha
	}
	// The copy and the cache key take one name: which path's file root owns can change meanwhile.
	name := au.fileName(o)
	key, files, err := au.cacheKey(ctx, o, name)
	if err != nil {
		return nil, counts{}, err
	}
	users := o.Kind != inventory.OriginImage
	if key != "" {
		if sbom, ok := au.cache.get(key); ok {
			rep, n, err := au.matchCached(ctx, sbom, raw, users)
			if !errors.As(err, new(badSBOM)) {
				return rep, n, err
			}
			au.cache.remove(key)
		}
	}
	source, cleanup, err := au.source(ctx, o, name)
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
	var data []byte
	if users {
		data, err = grype.ReadOutput(tmp, "Grype's SBOM", maxSBOMSize)
	} else {
		data, err = grype.ReadSBOM(tmp, maxSBOMSize)
	}
	if err == nil {
		data, err = grype.StripSBOM(data)
	}
	var n counts
	if err == nil {
		n, err = countPackages(data)
	}
	if err == nil {
		err = au.writeRaw(raw.SBOM, data)
	}
	if err != nil {
		return nil, counts{}, err
	}
	if key != "" {
		if again, _, err := au.cacheKey(ctx, o, name); err != nil || again != key {
			key = ""
		}
	}
	au.cacheIfVerified(ctx, key, files, data, rep, rawName(o.ID, ".verify"), users)
	return rep, n, nil
}

// maxSBOMSize is the largest SBOM that the Audit reads. Users control what some SBOMs hold, such
// as an app directory's lockfile, and reading one takes up to 13 times its size: a package-lock.json
// of 50,000 packages gives a 72 MB SBOM. The largest real SBOMs are about 15 MB, of a 5 GB image.
// The package database's and images' SBOMs are capped without their vulnerabilities (see
// grype.ReadSBOM): they repeat the report's matches, 28,000 on an Ubuntu host with two kernels.
var maxSBOMSize int64 = 32 << 20

func (au *auditor) writeRaw(name string, data []byte) error {
	path := filepath.Join(au.d.RunDir, name)
	if err := aboveFloor(filepath.Dir(path), int64(len(data)), errRunFolderFull); err != nil {
		return err
	}
	return run.WriteFile(path, data, 0o640)
}

type counts struct{ packages, os int }

var osPackageTypes = []string{"deb", "rpm", "apk", "alpm", "portage", "nix"}

func countPackages(data []byte) (counts, error) {
	pkgs, err := grype.SBOMPackages(data)
	if err != nil {
		return counts{}, err
	}
	n := counts{packages: len(pkgs)}
	for _, p := range pkgs {
		if slices.Contains(osPackageTypes, p.Type) {
			n.os++
		}
	}
	return n, nil
}

func (au *auditor) matchCached(ctx context.Context, sbom string, raw *Raw, users bool) (*grype.Report, counts, error) {
	data, n, err := readCached(sbom)
	if err != nil {
		return nil, counts{}, err
	}
	rep, err := au.matchSBOM(ctx, sbom, data, raw, users)
	return rep, n, err
}

type badSBOM struct{ error }

func (e badSBOM) Unwrap() error { return e.error }

func readCached(path string) ([]byte, counts, error) {
	data, err := grype.ReadOutput(path, "the cached SBOM", maxSBOMSize)
	if err != nil {
		return nil, counts{}, badSBOM{err}
	}
	n, err := countPackages(data)
	if err != nil {
		return nil, counts{}, badSBOM{err}
	}
	return data, n, nil
}

func rejected(err error) error {
	if err != nil && strings.Contains(err.Error(), "unable to decode sbom") {
		return badSBOM{err}
	}
	return err
}

// cacheIfVerified caches a stripped SBOM under key when matching it gives what the scan gave
// (see sameMatches), and reports whether it did. Matching an SBOM can lose a derivative's
// distribution, or match some packages otherwise than a scan, so the SBOM is matched once, exactly
// as it would be cached, as name.cdx.json in the scan folder; grype.Matchable first rules out the
// cases known to differ. An origin whose SBOM is not cached is scanned every run. When files is
// set, every package must have been read from one of them, the lockfiles and manifests whose
// content an app directory's key hashes: the rest of its tree is fingerprinted by size, inode and
// ctime only, which a file rewritten in place within one tick of a coarse file system clock keeps.
// users says that users control what the SBOM holds. The cache only saves time, so a failed match
// or write is not an error.
func (au *auditor) cacheIfVerified(ctx context.Context, key string, files []string, data []byte, scan *grype.Report, name string, users bool) bool {
	if key == "" {
		return false
	}
	if ok, err := grype.Matchable(data); err != nil || !ok {
		return false
	}
	if files != nil {
		locations, err := grype.SBOMLocations(data)
		if err != nil {
			return false
		}
		for _, pkg := range locations {
			if len(pkg) == 0 {
				return false
			}
			for _, l := range pkg {
				if !slices.Contains(files, l) {
					return false
				}
			}
		}
	}
	sbom := filepath.Join(au.scanDir(), name+".cdx.json")
	raw := filepath.Join(au.scanDir(), name+".grype.json")
	defer os.Remove(sbom)
	defer os.Remove(raw)
	if hasRoom(au.scanDir(), int64(len(data))) != nil {
		return false
	}
	if err := os.WriteFile(sbom, data, 0o600); err != nil {
		return false
	}
	rep, err := au.d.Grype.Match(ctx, sbom, raw, users)
	if err != nil || !sameMatches(rep, scan) {
		return false
	}
	_ = au.cache.put(key, data)
	return true
}

func sameMatches(a, b *grype.Report) bool {
	if a.Distro != b.Distro || a.DistroVersion != b.DistroVersion {
		return false
	}
	set := func(r *grype.Report) map[string]bool {
		s := map[string]bool{}
		for _, m := range r.Matches {
			v := m.Vulnerability
			s[strings.Join(append([]string{v.ID, m.Artifact.Name, m.Artifact.Version, m.Artifact.Type, findingLocation(m.Artifact.Locations), v.Namespace, v.FixState}, v.FixVersions...), "\x00")] = true
		}
		return s
	}
	return maps.Equal(set(a), set(b))
}

func (au *auditor) cacheKey(ctx context.Context, o inventory.Origin, name string) (string, []string, error) {
	switch o.Kind {
	case inventory.OriginBinary:
		return keyOf("binary", o.SHA256, name), nil, nil
	case inventory.OriginImage:
		return keyOf("image", o.ImageID), nil, nil
	case inventory.OriginAppDir:
		if o.Jar {
			return keyOf("jar", o.SHA256, name), nil, nil
		}
		return appDirKey(ctx, au.reads, filepath.Join(au.d.Root, o.Path), au.d.Now().UTC().Format("2006-01-02"), au.mountBelow)
	}
	return "", nil, fmt.Errorf("origin kind %q cannot be scanned", o.Kind)
}

// fileName is the name of a binary's or jar's copy, made a name that Syft never unpacks as other
// than it is (see copyName and jarName): a jar's own name, and of a binary, the name of its first
// path whose file root owns, or else of its first path. Syft's classifiers go by the name, and a
// user who runs a renamed copy of root's file, such as ~/x of /opt/app/bin/python3.12, shares its
// origin with a path that may sort first.
func (au *auditor) fileName(o inventory.Origin) string {
	switch {
	case o.Kind == inventory.OriginAppDir:
		return jarName(filepath.Base(o.Path))
	case len(o.Paths) > 0:
		name := o.Paths[0]
		for _, p := range o.Paths {
			if rootOwned(filepath.Join(au.d.Root, p)) {
				name = p
				break
			}
		}
		return copyName(filepath.Base(name))
	}
	return o.SHA256
}

func rootOwned(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// archiveName matches the names for which Syft 1.57, in Grype 0.121.2, unpacks a file into the
// cache, as measured: its file source unpacks a file whose name holds .tar, .zip, .7z or .rar, or
// ends in .tgz, .tbz2, .txz, .tzst or .tlz, and its Java cataloger the Java archives below, .zip
// and .rar among them. Appending a suffix would not do: the file source matches .tar, .zip, .7z
// and .rar anywhere in the name.
var archiveName = regexp.MustCompile(`(?i)\.(tar|zip|7z|rar)|\.(tgz|tbz2|txz|tzst|tlz|` + javaArchives + `)$`)

const javaArchives = `jar|war|ear|par|sar|nar|kar|hpi|jpi|far|zap|lpkg`

var javaExtension = regexp.MustCompile(`(?i)\.(` + javaArchives + `)$`)

// copyName is the name of a binary's copy: its file name, with the dot of each archive extension
// made an underscore, so that Syft reads the copy as the binary it is (libx.so.1.tar.gz becomes
// libx.so.1_tar.gz). A user can map an archive under a library's name. A real binary's name keeps
// its dots, so the binary classifiers' globs, such as libpython*.so*, still match it.
func copyName(name string) string {
	return archiveName.ReplaceAllStringFunc(name, func(ext string) string { return "_" + ext[1:] })
}

// jarName is the name of a jar's copy: the copy name of its file name as a binary's, but with its
// Java archive extension kept, or .jar added when it has none, so that Syft reads it as the Java
// archive it is and nothing else. java -jar runs a Java archive of any name, such as ~/app.tar.gz,
// which Syft would unpack as a tar (app_tar.gz.jar).
func jarName(name string) string {
	ext := javaExtension.FindString(name)
	if ext == "" {
		return copyName(name) + ".jar"
	}
	return copyName(strings.TrimSuffix(name, ext)) + ext
}

// source is what Grype scans for an origin: a verified copy of a binary or jar, an app directory,
// or an image by ID from the local Docker daemon. A copy is scan/<sha>/<name> (see fileName),
// because Syft's Java cataloger and binary classifiers go by the file name (*.jar, python*, node,
// ...). cleanup removes it. Users control copies and app directories, so Grype reads them only as
// a file and a directory: its file: and dir: sources also take any file that holds a docker save
// or OCI archive, and any directory that holds an OCI layout, for an image, and unpack its layers.
func (au *auditor) source(ctx context.Context, o inventory.Origin, name string) (string, func(), error) {
	none := func() {}
	switch {
	case o.Kind == inventory.OriginImage:
		return "docker:" + o.ImageID, none, nil
	case o.Kind == inventory.OriginAppDir && !o.Jar:
		return "local-directory:" + filepath.Join(au.d.Root, o.Path), none, nil
	}
	dir := filepath.Join(au.scanDir(), o.SHA256)
	path := filepath.Join(dir, name)
	var err error
	if o.Jar {
		jar := filepath.Join(au.d.Root, o.Path)
		err = copyVerified(ctx, au.reads, jar, openPath(jar), o.SHA256, path)
	} else {
		err = au.binaryFile(ctx, o, path)
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", none, err
	}
	return "local-file:" + path, func() { os.RemoveAll(dir) }, nil
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
		return copyVerified(ctx, au.reads, o.Copy, openPath(o.Copy), o.SHA256, path)
	}
	err := errors.New("it has no path")
	au.eachOpener(o, func(name string, open func() (*os.File, error)) bool {
		err = copyVerified(ctx, au.reads, name, open, o.SHA256, path)
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

func (au *auditor) eachOpener(o inventory.Origin, try func(string, func() (*os.File, error)) bool) {
	if au.d.Proc != nil {
		for _, it := range au.rem.users[o.ID] {
			for _, p := range it.Processes {
				for _, path := range o.Paths {
					if open := au.procOpener(p.PID, it.Exe, path); open != nil && try(path, open) {
						return
					}
				}
			}
		}
	}
	for _, p := range o.Paths {
		if host := filepath.Join(au.d.Root, p); try(host, openPath(host)) {
			return
		}
	}
}

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

func (au *auditor) matchSBOM(ctx context.Context, sbom string, data []byte, raw *Raw, users bool) (*grype.Report, error) {
	if err := au.writeRaw(raw.SBOM, data); err != nil {
		return nil, err
	}
	rawPath := filepath.Join(au.d.RunDir, raw.Grype)
	rep, err := au.d.Grype.Match(ctx, sbom, rawPath, users)
	if err != nil {
		return nil, rejected(err)
	}
	return rep, run.Share(rawPath, 0o640)
}
