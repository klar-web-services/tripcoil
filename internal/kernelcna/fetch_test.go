package kernelcna

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	commitA = "84a53c896276bc79eb2c0b9864fc2a53afe270b8"
	commitB = "1111111111111111111111111111111111111111"
)

// snapshotOf packs the test records as kernel.org's snapshot of commit, with the files a real
// snapshot also holds around them.
func snapshotOf(t *testing.T, commit string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name string, body []byte, typ byte) {
		hdr := &tar.Header{Name: "vulns-" + commit + "/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: typ}
		if typ == tar.TypeSymlink {
			hdr.Size, hdr.Linkname = 0, "../x"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write(body)
		}
	}
	paths, _ := filepath.Glob("../../testdata/kernelcna/cve/published/*/CVE-*.json")
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rel := strings.TrimPrefix(p, "../../testdata/kernelcna/")
		add(rel, data, tar.TypeReg)
		add(strings.TrimSuffix(rel, ".json")+".dyad", []byte("6.5:abc:6.8:def\n"), tar.TypeReg)
	}
	add("cve/rejected/2024/CVE-2024-99999.json", []byte(`{"cveMetadata":{"cveId":"CVE-2024-99999","state":"PUBLISHED"}}`), tar.TypeReg)
	add("cve/testing/published/2024/CVE-2024-1.json", []byte(`not even json`), tar.TypeReg)
	add("cve/published/2024/CVE-2024-0000.json", nil, tar.TypeSymlink)
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

type fakeKernelOrg struct {
	commit   atomic.Value
	snapshot atomic.Value // []byte
	refs     atomic.Int32
	snaps    atomic.Int32
	down     atomic.Bool
}

func serve(t *testing.T, k *fakeKernelOrg) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("%s request: kernel.org must only get GET", r.Method)
		}
		if k.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		commit := k.commit.Load().(string)
		switch r.URL.Path {
		case "/info/refs":
			k.refs.Add(1)
			w.Write([]byte(commitB + "\trefs/heads/sasha-cve\n" + commit + "\trefs/heads/master\n"))
		case "/snapshot/vulns-" + commit + ".tar.gz":
			k.snaps.Add(1)
			w.Write(k.snapshot.Load().([]byte))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newSource(t *testing.T) (*Source, *fakeKernelOrg) {
	k := &fakeKernelOrg{}
	k.commit.Store(commitA)
	k.snapshot.Store(snapshotOf(t, commitA))
	srv := serve(t, k)
	return &Source{CacheDir: filepath.Join(t.TempDir(), "cache"), BaseURL: srv.URL, Client: srv.Client(), MinRecords: 29}, k
}

var t0 = time.Date(2026, 11, 14, 6, 0, 0, 0, time.UTC)

func TestLoadFetchesAndCaches(t *testing.T) {
	s, k := newSource(t)
	d, err := s.Load(context.Background(), t0, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if d.Commit != commitA || !d.Checked.Equal(t0) || len(d.Records) != 29 || d.Records[0].ID != "CVE-2019-25160" {
		t.Fatalf("data %s %v %d records", d.Commit, d.Checked, len(d.Records))
	}
	if fi, err := os.Stat(filepath.Join(s.CacheDir, "kernel-cna.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache file %v %v", fi, err)
	}
	// Within a day the cache is used as it is.
	if _, err := s.Load(context.Background(), t0.Add(23*time.Hour), 48*time.Hour); err != nil || k.refs.Load() != 1 {
		t.Fatalf("refs %d, %v", k.refs.Load(), err)
	}
	// A day later the commit is checked; the same commit is not downloaded again.
	d, err = s.Load(context.Background(), t0.Add(25*time.Hour), 48*time.Hour)
	if err != nil || k.refs.Load() != 2 || k.snaps.Load() != 1 || !d.Checked.Equal(t0.Add(25*time.Hour)) {
		t.Fatalf("refs %d snapshots %d checked %v: %v", k.refs.Load(), k.snaps.Load(), d.Checked, err)
	}
	// A new commit is.
	k.commit.Store(commitB)
	k.snapshot.Store(snapshotOf(t, commitB))
	if d, err = s.Load(context.Background(), t0.Add(50*time.Hour), 48*time.Hour); err != nil || d.Commit != commitB || k.snaps.Load() != 2 {
		t.Fatalf("commit %s, snapshots %d: %v", d.Commit, k.snaps.Load(), err)
	}
}

func TestLoadChecksWithinMaxAge(t *testing.T) {
	// With audit.maxDatabaseAgeHours below a day, data is checked before it gets that old.
	s, k := newSource(t)
	if _, err := s.Load(context.Background(), t0, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(context.Background(), t0.Add(13*time.Hour), 12*time.Hour); err != nil || k.refs.Load() != 2 {
		t.Fatalf("refs %d: %v", k.refs.Load(), err)
	}
}

func TestLoadWhenKernelOrgFails(t *testing.T) {
	s, k := newSource(t)
	k.down.Store(true)
	if _, err := s.Load(context.Background(), t0, 48*time.Hour); err == nil || !strings.Contains(err.Error(), "cannot be fetched") || !strings.Contains(err.Error(), "503") {
		t.Fatalf("no cache: %v", err)
	}
	k.down.Store(false)
	if _, err := s.Load(context.Background(), t0, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	k.down.Store(true)
	if d, err := s.Load(context.Background(), t0.Add(47*time.Hour), 48*time.Hour); err != nil || d.Commit != commitA {
		t.Fatalf("data checked within maxAge must be used: %v", err)
	}
	if _, err := s.Load(context.Background(), t0.Add(49*time.Hour), 48*time.Hour); err == nil || !strings.Contains(err.Error(), "last checked 49 hours ago") {
		t.Fatalf("stale: %v", err)
	}
}

func TestLoadRejectsBrokenSnapshots(t *testing.T) {
	for name, body := range map[string][]byte{
		"empty body":   {}, // what kernel.org's cache once served for a snapshot
		"not gzip":     []byte("<html>"),
		"cut short":    snapshotOf(t, commitA)[:2000],
		"other commit": snapshotOf(t, commitB),
	} {
		t.Run(name, func(t *testing.T) {
			s, k := newSource(t)
			k.snapshot.Store(body)
			if _, err := s.Load(context.Background(), t0, 48*time.Hour); err == nil {
				t.Fatal("a broken snapshot was accepted")
			}
			if _, err := os.Stat(filepath.Join(s.CacheDir, "kernel-cna.json")); !os.IsNotExist(err) {
				t.Fatal("a broken snapshot reached the cache")
			}
		})
	}
	s, _ := newSource(t)
	s.MinRecords = 30
	if _, err := s.Load(context.Background(), t0, 48*time.Hour); err == nil || !strings.Contains(err.Error(), "holds 29 published records, fewer than the 30 expected") {
		t.Fatalf("too few records: %v", err)
	}
}
