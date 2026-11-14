//go:build integration

package integration

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/grype"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/kernelcna"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/pkgtool"
)

// The tests share one Tripcoil cache with the pinned Grype, today's database and the kernel CNA
// data, prepared on first use and removed when the tests end. It holds about 3.5 GB, under
// $TRIPCOIL_TEST_CACHE_PARENT when that is set, else under the temporary directory, which may be
// a tmpfs; TMPDIR=/var/tmp works too.
var (
	cacheOnce sync.Once
	cacheDir  string
	cacheErr  error
)

// interrupt ends when the tests are interrupted, so that the containers they run are removed and
// the cache is too. A second interrupt ends them at once.
var interrupt context.Context

func TestMain(m *testing.M) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	interrupt = ctx
	context.AfterFunc(interrupt, stop)
	code := m.Run()
	stop()
	if cacheDir != "" {
		if err := os.RemoveAll(cacheDir); err != nil {
			fmt.Fprintf(os.Stderr, "remove the cache: %v\n", err)
		}
	}
	os.Exit(code)
}

func preparedCache(t *testing.T) string {
	t.Helper()
	cacheOnce.Do(func() {
		if cacheDir, cacheErr = os.MkdirTemp(os.Getenv("TRIPCOIL_TEST_CACHE_PARENT"), "tripcoil-cache-"); cacheErr != nil {
			return
		}
		if _, _, cacheErr = audit.NewGrype(cacheDir).Prepare(interrupt); cacheErr != nil {
			return
		}
		_, cacheErr = kernelcna.NewSource(cacheDir).Load(interrupt, time.Now(), 48*time.Hour)
	})
	if cacheErr != nil {
		t.Fatalf("prepare the cache: %v", cacheErr)
	}
	return cacheDir
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// writeJar writes a jar that holds only the Maven metadata of log4j-core 2.14.1.
func writeJar(t *testing.T, path string) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range [][2]string{
		{"META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n"},
		{"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties", "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"},
	} {
		f, err := w.Create(e[0])
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(f, e[1])
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestAuditFixtures audits the deliberately vulnerable fixtures with the real Grype and the real
// kernel CNA data: a Go binary that calls golang.org/x/text v0.3.5's vulnerable parsers, a Node
// app directory with lodash 4.17.20, a jar of log4j-core 2.14.1, a redis-server of Redis 2.8.23, a
// package of this machine, and Linux 6.1.1. Syft catalogs the jar and redis-server only under
// their file names.
func TestAuditFixtures(t *testing.T) {
	cache := preparedCache(t)
	ctx := interrupt
	gobin := filepath.Join(t.TempDir(), "gobin")
	build := exec.Command("go", "build", "-o", gobin, ".")
	build.Dir = "../../testdata/audit/gobin"
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	app, _ := filepath.Abs("../../testdata/audit/npm-vulnerable")
	jar := filepath.Join(t.TempDir(), "log4j-core-2.14.1.jar")
	writeJar(t, jar)
	// The version string Redis 2.8 logs at startup, which Syft looks for in a file named redis-server.
	redis := filepath.Join(t.TempDir(), "redis-server")
	if err := os.WriteFile(redis, []byte("Server started, Redis version 2.8.23\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel, err := osrel.Read("/")
	if err != nil {
		t.Fatal(err)
	}
	env, err := filepath.EvalSymlinks("/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	owners, err := pkgtool.New(rel.Family().PackageType(), pkgtool.Exec).Owners(ctx, []string{env})
	if err != nil || len(owners) != 1 {
		t.Fatalf("owner of %s: %v %v", env, owners, err)
	}
	pkg := owners[env]
	distro := inventory.Distro{ID: rel.ID, VersionID: rel.VersionID, Family: string(rel.Family())}
	pkgID := inventory.PackageOriginID(distro, pkg)
	binID := inventory.BinaryOriginID(sha256File(t, gobin))
	appID := inventory.AppDirOriginID(app)
	jarID := inventory.AppDirOriginID(jar)
	redisID := inventory.BinaryOriginID(sha256File(t, redis))
	kernelID := inventory.KernelUpstreamOriginID("6.1.1")
	inv := &inventory.Inventory{
		Host: inventory.Host{Distro: distro},
		Items: []inventory.Item{
			{ID: "kernel", Kind: inventory.KindKernel, Name: "kernel", Origins: []string{kernelID}},
			{ID: "proc:env", Kind: inventory.KindProcess, Name: "env", Origins: []string{pkgID}},
			{ID: "proc:gobin", Kind: inventory.KindProcess, Name: "gobin", Origins: []string{binID}},
			{ID: "proc:node", Kind: inventory.KindProcess, Name: "node", Origins: []string{appID}},
			{ID: "proc:java", Kind: inventory.KindProcess, Name: "java", Origins: []string{jarID}},
			{ID: "proc:redis-server", Kind: inventory.KindProcess, Name: "redis-server", Origins: []string{redisID}},
		},
		Origins: []inventory.Origin{
			{ID: kernelID, Kind: inventory.OriginKernelUpstream, UpstreamVersion: "6.1.1"},
			{ID: pkgID, Kind: inventory.OriginPackage, Name: pkg.Name, Version: pkg.Version, Epoch: pkg.Epoch, Arch: pkg.Arch, Type: pkg.Type},
			{ID: binID, Kind: inventory.OriginBinary, SHA256: strings.TrimPrefix(binID, "binary:"), Paths: []string{gobin}},
			{ID: appID, Kind: inventory.OriginAppDir, Path: app},
			{ID: jarID, Kind: inventory.OriginAppDir, Path: jar, Jar: true},
			{ID: redisID, Kind: inventory.OriginBinary, SHA256: strings.TrimPrefix(redisID, "binary:"), Paths: []string{redis}},
		},
	}
	runDir := t.TempDir()
	d := audit.Deps{Root: "/", CacheDir: cache, RunDir: runDir, Family: rel.Family(), MaxAge: 48 * time.Hour, Now: time.Now,
		Grype: audit.NewGrype(cache), Kernel: kernelcna.NewSource(cache)}
	a := audit.Run(ctx, d, inv)
	if a.Status != audit.Complete || len(a.Errors) != 0 {
		t.Fatalf("audit %s: %+v", a.Status, a.Errors)
	}
	for _, o := range a.Origins {
		if o.Status != audit.Scanned || o.Packages == 0 {
			t.Errorf("origin %+v", o)
		}
	}
	found := map[string]audit.Finding{}
	kernel, redisFindings := 0, 0
	for _, f := range a.Findings {
		found[f.Vulnerability.ID+" "+f.Package.Name] = f
		for _, alias := range f.Vulnerability.Aliases {
			found[alias+" "+f.Package.Name] = f
		}
		switch f.Origin {
		case kernelID:
			kernel++
		case redisID:
			redisFindings++
		}
	}
	for _, want := range []string{"GHSA-35jh-r3h4-6jhm lodash", "GHSA-69ch-w2m2-3vjp golang.org/x/text", "GHSA-ppp9-7jff-5vj2 golang.org/x/text",
		"CVE-2021-44228 log4j-core", "CVE-2024-53104 linux"} {
		if _, ok := found[want]; !ok {
			t.Errorf("no finding %s", want)
		}
	}
	if redisFindings == 0 {
		t.Error("no finding on Redis 2.8.23")
	}
	// CVE-2024-53104 (uvcvideo) is on the CISA KEV list and was fixed in 6.1.117.
	if f := found["CVE-2024-53104 linux"]; f.Risk != audit.RiskCritical || len(f.Fix.Versions) != 1 || f.Fix.Versions[0] != "6.1.117" {
		t.Errorf("CVE-2024-53104 %+v", f)
	}
	if kernel < 1000 {
		t.Errorf("%d kernel findings for Linux 6.1.1; thousands of CVEs affect it", kernel)
	}
	upgraded := false
	for _, u := range a.Upgrades {
		upgraded = upgraded || (u.Package == "lodash" && u.Path == app)
	}
	if !upgraded {
		t.Errorf("no upgrade line for lodash: %+v", a.Upgrades)
	}
	t.Logf("%d findings (%d kernel), Grype database built %s, kernel CNA data at %.12s", len(a.Findings), kernel, a.Grype.DBBuilt, a.KernelData.Commit)

	// The app directory's SBOM is cached; the Go binary's never is, because Grype keeps only the Go
	// matches whose code is linked into it. (The package database's is, except on Arch Linux,
	// whose SBOM loses the distribution.)
	appSBOMs, _ := filepath.Glob(filepath.Join(cache, "sbom", grype.Version, "appdir-*.cdx.json"))
	if len(appSBOMs) != 1 {
		t.Fatalf("cached app directory SBOMs %v", appSBOMs)
	}
	sboms, _ := filepath.Glob(filepath.Join(cache, "sbom", grype.Version, "binary-*.cdx.json"))
	for _, sbom := range sboms {
		if data, _ := os.ReadFile(sbom); bytes.Contains(data, []byte("pkg:golang/")) {
			t.Errorf("cached Go binary SBOM %s", sbom)
		}
	}

	// The second run matches the cached SBOM, which marks it used, and finds the same. The jar's
	// cached SBOM is replaced by one that Grype cannot decode: the second run drops it and catalogs
	// the jar again.
	used := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(appSBOMs[0], used, used); err != nil {
		t.Fatal(err)
	}
	jarSBOMs, _ := filepath.Glob(filepath.Join(cache, "sbom", grype.Version, "jar-*.cdx.json"))
	if len(jarSBOMs) != 1 {
		t.Fatalf("cached jar SBOMs %v", jarSBOMs)
	}
	if err := os.WriteFile(jarSBOMs[0], []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(appSBOMs[0])
	if err != nil {
		t.Fatal(err)
	}
	again := audit.Run(ctx, d, inv)
	if again.Status != audit.Complete || len(again.Errors) != 0 {
		t.Fatalf("second run %s: %+v", again.Status, again.Errors)
	}
	if fi, err := os.Stat(appSBOMs[0]); err != nil {
		t.Errorf("the cached app directory SBOM is gone: %v", err)
	} else if !os.SameFile(before, fi) {
		t.Error("the second run replaced the cached app directory SBOM instead of matching it")
	} else if !fi.ModTime().After(used) {
		t.Errorf("the second run did not use the cached app directory SBOM, last used %s", fi.ModTime())
	}
	for _, o := range again.Origins {
		if o.Status != audit.Scanned || o.Packages == 0 {
			t.Errorf("second run's origin %+v", o)
		}
	}
	if data, err := os.ReadFile(jarSBOMs[0]); err != nil {
		t.Errorf("the jar's SBOM is not cached again: %v", err)
	} else if pkgs, err := grype.SBOMPackages(data); err != nil || len(pkgs) == 0 {
		t.Errorf("the jar's malformed cached SBOM was not replaced: %.200s", data)
	}
	first := map[string]bool{}
	for _, f := range a.Findings {
		first[f.ID] = true
	}
	var diff []string
	for _, f := range again.Findings {
		if !first[f.ID] {
			diff = append(diff, "+"+f.ID)
		}
		delete(first, f.ID)
	}
	for id := range first {
		diff = append(diff, "-"+id)
	}
	if len(diff) != 0 {
		t.Errorf("second run's findings differ from the first's: %v", diff)
	}
}

// TestAuditImage scans a small, old image by its ID from the local Docker daemon.
func TestAuditImage(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	cache := preparedCache(t)
	const ref = "alpine:3.18.0"
	if out, err := exec.CommandContext(interrupt, "docker", "pull", "-q", ref).CombinedOutput(); err != nil {
		t.Fatalf("docker pull: %v\n%s", err, out)
	}
	out, err := exec.Command("docker", "image", "inspect", "-f", "{{.Id}}", ref).Output()
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(string(out))
	imgID := inventory.ImageOriginID(id)
	inv := &inventory.Inventory{
		Items:   []inventory.Item{{ID: "container:old", Kind: inventory.KindContainer, Name: "old", Origins: []string{imgID}}},
		Origins: []inventory.Origin{{ID: imgID, Kind: inventory.OriginImage, ImageID: id, Ref: ref}},
	}
	a := audit.Run(interrupt, audit.Deps{Root: "/", CacheDir: cache, RunDir: t.TempDir(), Family: osrel.Alpine,
		MaxAge: 48 * time.Hour, Now: time.Now, Grype: audit.NewGrype(cache), Kernel: kernelcna.NewSource(cache)}, inv)
	if a.Status != audit.Complete || len(a.Origins) != 1 || a.Origins[0].Packages < 10 || len(a.Findings) == 0 {
		t.Fatalf("audit %s %+v, %d findings, errors %+v", a.Status, a.Origins, len(a.Findings), a.Errors)
	}
	if !strings.Contains(a.Findings[0].Remediation, "Rebuild alpine:3.18.0 or pull a newer image") && a.Findings[0].Fix.State == "fixed" {
		t.Errorf("remediation %q", a.Findings[0].Remediation)
	}
}
