package audit

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/run"
)

// packagesID names the one scan of the package database, for its raw files and messages.
const packagesID = "packages"

// packages scans the package database once and keeps the matches of packages that are origins.
func (au *auditor) packages(ctx context.Context, origins []inventory.Origin) {
	raw := rawFiles(packagesID)
	rep, comps, err := au.scanPackages(ctx, raw)
	if err != nil {
		au.removeRaw(raw)
		au.failPackages(ctx, origins, err)
		return
	}
	byKey := map[string]string{}
	for _, o := range origins {
		byKey[packageKey(o.Name, au.originVersion(o), o.Arch)] = o.ID
	}
	owner := func(name, version, purl string) (string, bool) {
		if id, ok := byKey[packageKey(name, version, purlArch(purl))]; ok {
			return id, true
		}
		id, ok := byKey[packageKey(name, version, "")]
		return id, ok
	}
	counts := map[string]int{}
	for _, c := range comps {
		if id, ok := owner(c.Name, c.Version, c.PURL); ok {
			counts[id]++
		}
	}
	for _, o := range origins {
		res := OriginResult{ID: o.ID, Kind: o.Kind, Status: Scanned, Packages: counts[o.ID], Raw: raw}
		_, _, kernel := au.kernelPackage(o)
		switch {
		case rep.Distro == "":
			// Without a distribution, no distribution data applies, and no match would come.
			res.Status, res.Reason = Unidentified, "Grype did not recognise the distribution, so its vulnerability data does not apply"
		case res.Packages == 0 && kernel:
			// It is counted at its running version only when runningKernel found it at the
			// version the Inventory saw, and changed it.
			au.failOrigin(o, errors.New("the kernel package changed since the inventory, so the kernel is audited at the next run"))
			continue
		case res.Packages == 0:
			res.Status, res.Reason = Unidentified, "the package tool knows it, but Grype did not read it from the package database"
		}
		au.a.Origins = append(au.a.Origins, res)
	}
	au.addFindings(rep.Matches, raw.Grype, func(m grype.Match) (string, bool) {
		return owner(m.Artifact.Name, m.Artifact.Version, m.Artifact.PURL)
	})
}

// scanPackages stages the package database and returns its matches and packages: from its cached
// SBOM, or from a scan of the staging root when the database changed, its SBOM does not match
// like the staging root (see cacheIfVerified), or the cached one is at fault (see badSBOM). The
// running kernel's package is matched at its running version. The SBOM is verified against the
// scan and cached before that change, which a cached SBOM gets as it is matched.
func (au *auditor) scanPackages(ctx context.Context, raw *Raw) (*grype.Report, []grype.Component, error) {
	stage := filepath.Join(au.d.CacheDir, "staging")
	os.RemoveAll(stage)
	defer os.RemoveAll(stage)
	key, err := stagePackageDB(au.reads, au.d.Root, au.d.Family, stage)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(au.scanDir(), 0o700); err != nil {
		return nil, nil, err
	}
	if sbom, ok := au.cache.get(key); ok {
		data, _, err := readCached(sbom)
		var rep *grype.Report
		var comps []grype.Component
		if err == nil {
			rep, comps, err = au.matchPackages(ctx, data, raw)
		}
		if !errors.As(err, new(badSBOM)) {
			return rep, comps, err
		}
		au.cache.remove(key)
	}
	out := filepath.Join(au.scanDir(), "packages.cdx.json")
	rep, err := au.d.Grype.Scan(ctx, "dir:"+stage, filepath.Join(au.d.RunDir, raw.Grype), out)
	if err != nil {
		return nil, nil, err
	}
	data, err := grype.ReadOutput(out, "Grype's SBOM", maxSBOMSize)
	if err == nil {
		data, err = grype.StripSBOM(data)
	}
	if err != nil {
		return nil, nil, err
	}
	au.cacheIfVerified(ctx, key, nil, data, rep, packagesID+".verify")
	if changed, err := au.kernelChanged(data); err != nil || changed {
		if err != nil {
			return nil, nil, err
		}
		return au.matchPackages(ctx, data, raw)
	}
	return au.keepPackages(rep, data, raw)
}

// matchPackages matches a package SBOM after changing the running kernel's package.
func (au *auditor) matchPackages(ctx context.Context, data []byte, raw *Raw) (*grype.Report, []grype.Component, error) {
	data, _, err := au.runningKernel(data)
	if err != nil {
		return nil, nil, err
	}
	sbom := filepath.Join(au.scanDir(), "packages-match.cdx.json")
	if err := os.WriteFile(sbom, data, 0o600); err != nil {
		return nil, nil, err
	}
	rep, err := au.d.Grype.Match(ctx, sbom, filepath.Join(au.d.RunDir, raw.Grype))
	if err != nil {
		return nil, nil, rejected(err)
	}
	return au.keepPackages(rep, data, raw)
}

// keepPackages leaves the report and the matched SBOM in the run folder and lists its packages.
func (au *auditor) keepPackages(rep *grype.Report, data []byte, raw *Raw) (*grype.Report, []grype.Component, error) {
	if err := run.Share(filepath.Join(au.d.RunDir, raw.Grype), 0o640); err != nil {
		return nil, nil, err
	}
	if err := au.writeRaw(raw.SBOM, data); err != nil {
		return nil, nil, err
	}
	comps, err := grype.SBOMPackages(data)
	return rep, comps, err
}

// kernelChanged reports whether runningKernel changes the SBOM.
func (au *auditor) kernelChanged(data []byte) (bool, error) {
	_, changed, err := au.runningKernel(data)
	return changed, err
}

func (au *auditor) failPackages(ctx context.Context, origins []inventory.Origin, err error) {
	if ctx.Err() != nil {
		return
	}
	for _, o := range origins {
		au.a.Origins = append(au.a.Origins, OriginResult{ID: o.ID, Kind: o.Kind, Status: ScanFailed, Error: err.Error()})
	}
	au.a.Errors = append(au.a.Errors, problemf(packagesID, "the installed packages: %v", err))
	au.a.Status = Partial
}

// packageKey identifies a package across the package tool and Grype: name, the version with its
// epoch, and the architecture when both name one.
func packageKey(name, version, arch string) string {
	return name + "\x00" + version + "\x00" + arch
}

// originVersion is a package origin's version as Grype spells it: with the epoch, and for the
// running kernel's package, the running version (see runningKernel).
func (au *auditor) originVersion(o inventory.Origin) string {
	if running, _, ok := au.kernelPackage(o); ok {
		return running
	}
	if o.Epoch != "" {
		return o.Epoch + ":" + o.Version
	}
	return o.Version
}

func purlArch(purl string) string {
	_, query, _ := strings.Cut(purl, "?")
	q, _ := url.ParseQuery(query)
	return q.Get("arch")
}

// kernelPackage reports whether o is the package of the running kernel on Debian or Ubuntu, whose
// SBOM entry must change before matching (spec section 6.2), with the running version and the
// source to set. A kernel package there can be upgraded in place under the same release name, and
// the findings must be for what runs. Debian's kernel packages also name linux-signed-<arch> as
// their source, while Debian's vulnerability data is filed under linux, so without the change no
// kernel vulnerability would ever match.
func (au *auditor) kernelPackage(o inventory.Origin) (running, source string, ok bool) {
	if o.Kind != inventory.OriginPackage {
		return "", "", false // a kernel matched by its upstream version
	}
	for _, it := range au.inv.Items {
		if it.Kind != inventory.KindKernel || it.RunningVersion == "" || len(it.Origins) != 1 || it.Origins[0] != o.ID {
			continue
		}
		switch {
		case au.d.Family == osrel.Debian:
			return it.RunningVersion, "linux", true
		case au.d.Family == osrel.Ubuntu && it.RunningVersion != o.Version:
			return it.RunningVersion, "", true
		}
	}
	return "", "", false
}

// runningKernel changes the running kernel's package in an SBOM as kernelPackage says, and reports
// whether it changed anything. When the SBOM does not hold the package at the version the
// Inventory saw, because it was upgraded in place since, the SBOM stays as it is: packages()
// then fails the kernel's origin alone.
func (au *auditor) runningKernel(data []byte) ([]byte, bool, error) {
	for _, o := range au.inv.Origins {
		running, source, ok := au.kernelPackage(o)
		if !ok {
			continue
		}
		out, n, err := grype.SetKernel(data, o.Name, o.Version, running, source)
		if err != nil || n == 0 {
			return data, false, err
		}
		return out, true, nil
	}
	return data, false, nil
}
