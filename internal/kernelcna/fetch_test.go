package kernelcna

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
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

type file struct {
	name string
	body []byte
}

// snapshotOf packs the test records as kernel.org's snapshot of commit, with the files a real
// snapshot also holds around them, and the extra files.
func snapshotOf(t *testing.T, commit string, extra ...file) []byte {
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
	for _, f := range extra {
		add(f.name, f.body, tar.TypeReg)
	}
	add("cve/rejected/2024/CVE-2024-99999.json", []byte(`{"cveMetadata":{"cveId":"CVE-2024-99999","state":"PUBLISHED"}}`), tar.TypeReg)
	add("cve/testing/published/2024/CVE-2024-1.json", []byte(`not even json`), tar.TypeReg)
	add("cve/published/2024/CVE-2024-0000.json", nil, tar.TypeSymlink)
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func unpack(t *testing.T, snapshot []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// cutBefore packs a snapshot again without its entries from the nth on: a download cut at a file
// boundary, with a valid gzip stream around it.
func cutBefore(t *testing.T, snapshot []byte, n int) []byte {
	t.Helper()
	raw := unpack(t, snapshot)
	br := bytes.NewReader(raw)
	tr := tar.NewReader(br)
	for range n {
		if _, err := tr.Next(); err != nil {
			t.Fatal(err)
		}
	}
	cut := len(raw) - br.Len() - 512 // the nth header's block; the names need no PAX header
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(raw[:cut])
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
	if _, err := s.Load(context.Background(), t0.Add(49*time.Hour), 48*time.Hour); err == nil || !strings.Contains(err.Error(), "last checked 49.0 hours ago") {
		t.Fatalf("stale: %v", err)
	}
	if _, err := s.Load(context.Background(), t0.Add(48*time.Hour+time.Second), 48*time.Hour); err == nil || !strings.Contains(err.Error(), "last checked 48.1 hours ago, which is older than audit.maxDatabaseAgeHours (48)") {
		t.Fatalf("just stale: %v", err)
	}
}

func TestLoadDistrustsCheckTimeInFuture(t *testing.T) {
	// Data checked while the clock was a year ahead is not fresh once the clock is right.
	s, k := newSource(t)
	if _, err := s.Load(context.Background(), t0.AddDate(1, 0, 0), 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	k.down.Store(true)
	if _, err := s.Load(context.Background(), t0, 48*time.Hour); err == nil || !strings.Contains(err.Error(), "last checked at 2027-11-14T06:00:00Z, which is in the future") {
		t.Fatalf("future check time: %v", err)
	}
	k.down.Store(false)
	if d, err := s.Load(context.Background(), t0, 48*time.Hour); err != nil || !d.Checked.Equal(t0) {
		t.Fatalf("checked again: %v", err)
	}
}

func TestLoadIgnoresCorruptCache(t *testing.T) {
	s, k := newSource(t)
	if _, err := s.Load(context.Background(), t0, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.CacheDir, "kernel-cna.json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data[:len(data)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	k.down.Store(true)
	if _, err := s.Load(context.Background(), t0.Add(time.Hour), 48*time.Hour); err == nil || !strings.Contains(err.Error(), "cannot be fetched") {
		t.Fatalf("a corrupt cache must count as none: %v", err)
	}
}

func TestLoadCancelled(t *testing.T) {
	s, _ := newSource(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Load(ctx, t0, 48*time.Hour); err != context.Canceled {
		t.Fatalf("no cache: %v", err)
	}
	if _, err := s.Load(context.Background(), t0, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, t0.Add(25*time.Hour), 48*time.Hour); err != context.Canceled {
		t.Fatalf("data within maxAge: %v", err)
	}
}

func TestLoadWhenCacheUnwritable(t *testing.T) {
	// The cache only saves work: what was checked or downloaded is used even when it cannot be saved.
	if os.Geteuid() == 0 {
		t.Skip("root writes anyway")
	}
	s, k := newSource(t)
	if _, err := s.Load(context.Background(), t0, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.CacheDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(s.CacheDir, 0o700) })
	if d, err := s.Load(context.Background(), t0.Add(25*time.Hour), 48*time.Hour); err != nil || !d.Checked.Equal(t0.Add(25*time.Hour)) {
		t.Fatalf("checked: %v", err)
	}
	k.commit.Store(commitB)
	k.snapshot.Store(snapshotOf(t, commitB))
	if d, err := s.Load(context.Background(), t0.Add(26*time.Hour), 48*time.Hour); err != nil || d.Commit != commitB || k.snaps.Load() != 2 {
		t.Fatalf("downloaded: %v", err)
	}
}

func TestSaveRemovesLeftovers(t *testing.T) {
	// A run killed between creating and renaming its temporary file leaves it behind.
	s, _ := newSource(t)
	leftover := filepath.Join(s.CacheDir, ".kernel-cna-123")
	if err := os.MkdirAll(s.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leftover, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(context.Background(), t0, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("leftover: %v", err)
	}
}

func TestLoadRejectsBrokenSnapshots(t *testing.T) {
	good := snapshotOf(t, commitA)
	badCRC := bytes.Clone(good)
	for i := len(badCRC) - 8; i < len(badCRC)-4; i++ {
		badCRC[i] ^= 0xff
	}
	for name, c := range map[string]struct {
		body []byte
		want string
	}{
		"empty body":             {[]byte{}, "not a gzip archive"}, // what kernel.org's cache once served for a snapshot
		"not gzip":               {[]byte("<html>"), "not a gzip archive"},
		"cut short":              {good[:2000], "damaged: unexpected EOF"},
		"cut at a file boundary": {cutBefore(t, good, 45), "ends early"}, // 22 of the 29 records
		"gzip checksum wrong":    {badCRC, "damaged: gzip: invalid checksum"},
		"gzip trailer missing":   {good[:len(good)-8], "damaged: unexpected EOF"},
		"other commit":           {snapshotOf(t, commitB), "holds 0 published records"},
		"record too large": {snapshotOf(t, commitA, file{"cve/published/2024/CVE-2024-99998.json", bytes.Repeat([]byte(" "), maxRecordBytes+1)}),
			"CVE-2024-99998.json is unexpectedly large"},
	} {
		t.Run(name, func(t *testing.T) {
			s, k := newSource(t)
			s.MinRecords = 1 // rejected for what is wrong, not for the count
			k.snapshot.Store(c.body)
			if _, err := s.Load(context.Background(), t0, 48*time.Hour); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
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

func TestLoadKeepsOldDataWhenSnapshotMalformed(t *testing.T) {
	// A snapshot with a malformed record is rejected whole, and the old data stays in use until it
	// is too old.
	s, k := newSource(t)
	if _, err := s.Load(context.Background(), t0, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	k.commit.Store(commitB)
	k.snapshot.Store(snapshotOf(t, commitB, file{"cve/published/2024/CVE-2024-99997.json", []byte(`{"cveMetadata":`)}))
	if d, err := s.Load(context.Background(), t0.Add(25*time.Hour), 48*time.Hour); err != nil || d.Commit != commitA || !d.Checked.Equal(t0) {
		t.Fatalf("old data within maxAge: %v", err)
	}
	if _, err := s.Load(context.Background(), t0.Add(49*time.Hour), 48*time.Hour); err == nil || !strings.Contains(err.Error(), "last checked 49.0 hours ago") || !strings.Contains(err.Error(), "CVE-2024-99997.json") {
		t.Fatalf("old data after maxAge: %v", err)
	}
}

func TestLoadLimits(t *testing.T) {
	body := snapshotOf(t, commitA)
	t.Cleanup(func() { snapshotCap, snapshotTarCap, recordsCap = maxSnapshotBytes, maxSnapshotTarBytes, maxRecords })
	snapshotCap, snapshotTarCap, recordsCap = int64(len(body)), int64(len(unpack(t, body))), 29
	load := func() error {
		s, k := newSource(t)
		k.snapshot.Store(body)
		_, err := s.Load(context.Background(), t0, 48*time.Hour)
		return err
	}
	if err := load(); err != nil {
		t.Fatalf("a snapshot at every limit: %v", err)
	}
	snapshotCap--
	if err := load(); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("cannot be fetched: the snapshot is larger than %d bytes", snapshotCap)) {
		t.Fatalf("compressed: %v", err)
	}
	snapshotCap++
	snapshotTarCap--
	if err := load(); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("cannot be fetched: the unpacked snapshot is larger than %d bytes", snapshotTarCap)) {
		t.Fatalf("unpacked: %v", err)
	}
	snapshotTarCap++
	recordsCap--
	if err := load(); err == nil || !strings.Contains(err.Error(), "the snapshot holds more than 28 records") {
		t.Fatalf("records: %v", err)
	}
}
