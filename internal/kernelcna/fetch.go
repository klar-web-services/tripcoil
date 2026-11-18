package kernelcna

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const DefaultBaseURL = "https://git.kernel.org/pub/scm/linux/security/vulns.git"

const (
	refreshAfter        = 24 * time.Hour
	minRecords          = 15000 // a snapshot holds about 18,000; fewer means a broken download
	maxRecords          = 100000
	maxSnapshotBytes    = 256 << 20
	maxSnapshotTarBytes = 2 << 30
	maxRecordBytes      = 4 << 20
	maxRanges           = 2000000
	maxTextBytes        = 64 << 20
)

var (
	snapshotCap    int64 = maxSnapshotBytes
	snapshotTarCap int64 = maxSnapshotTarBytes
	recordsCap           = maxRecords
	rangesCap            = maxRanges
	textCap              = maxTextBytes
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Source struct {
	CacheDir   string
	BaseURL    string
	Client     *http.Client
	MinRecords int
}

func NewSource(cacheDir string) *Source {
	return &Source{CacheDir: cacheDir, BaseURL: DefaultBaseURL, Client: &http.Client{Timeout: 10 * time.Minute}, MinRecords: minRecords}
}

func (s *Source) path() string { return filepath.Join(s.CacheDir, "kernel-cna.json") }

func (s *Source) Load(ctx context.Context, now time.Time, maxAge time.Duration) (*Data, error) {
	old := s.read()
	if old != nil && now.Sub(old.Checked) < min(refreshAfter, maxAge) && !old.Checked.After(now) {
		return old, nil
	}
	fresh, err := s.refresh(ctx, old, now)
	switch {
	case err == nil:
		return fresh, nil
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case old == nil:
		return nil, fmt.Errorf("the kernel CNA data cannot be fetched: %w", err)
	case old.Checked.After(now):
		return nil, fmt.Errorf("the kernel CNA data was last checked at %s, which is in the future, and checking it again failed: %w",
			old.Checked.Format(time.RFC3339), err)
	case now.Sub(old.Checked) <= maxAge:
		old.RefreshErr = err
		return old, nil
	}
	// Rounded up to a tenth, so the age never prints as the limit it exceeds.
	return nil, fmt.Errorf("the kernel CNA data was last checked %.1f hours ago, which is older than audit.maxDatabaseAgeHours (%.0f), and checking it again failed: %w",
		math.Ceil(now.Sub(old.Checked).Hours()*10)/10, maxAge.Hours(), err)
}

func (s *Source) read() *Data {
	data, err := os.ReadFile(s.path())
	if err != nil {
		return nil
	}
	var d Data
	if err := json.Unmarshal(data, &d); err != nil || !commitPattern.MatchString(d.Commit) {
		return nil
	}
	return &d
}

func (s *Source) refresh(ctx context.Context, old *Data, now time.Time) (*Data, error) {
	commit, err := s.masterCommit(ctx)
	if err != nil {
		return nil, err
	}
	if old != nil && old.Commit == commit {
		d := *old
		d.Checked = now
		_ = s.save(&d)
		return &d, nil
	}
	records, err := s.snapshot(ctx, commit)
	if err != nil {
		return nil, err
	}
	d := &Data{Commit: commit, Checked: now, Records: records}
	_ = s.save(d)
	return d, nil
}

// get fetches a URL with GET. A HEAD request once left kernel.org's cache serving empty
// snapshots, so none is ever sent, and every body is checked.
func (s *Source) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return resp, nil
}

func (s *Source) masterCommit(ctx context.Context) (string, error) {
	resp, err := s.get(ctx, s.BaseURL+"/info/refs")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		sha, ref, ok := strings.Cut(sc.Text(), "\t")
		if ok && ref == "refs/heads/master" && commitPattern.MatchString(sha) {
			return sha, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("the vulns repository lists no master commit")
}

func (s *Source) snapshot(ctx context.Context, commit string) ([]Record, error) {
	resp, err := s.get(ctx, s.BaseURL+"/snapshot/vulns-"+commit+".tar.gz")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(&limited{r: resp.Body, max: snapshotCap, what: "the snapshot"})
	if err != nil {
		return nil, fmt.Errorf("the snapshot is not a gzip archive: %w", err)
	}
	published := regexp.MustCompile(`^vulns-` + commit + `/cve/published/[0-9]{4}/CVE-[0-9]{4}-[0-9]+\.json$`)
	unpacked := &limited{r: gz, max: snapshotTarCap, what: "the unpacked snapshot"}
	tr := tar.NewReader(unpacked)
	var records []Record
	ranges, text := 0, 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, damaged(err)
		}
		if hdr.Typeflag != tar.TypeReg || !published.MatchString(hdr.Name) {
			continue
		}
		if hdr.Size > maxRecordBytes {
			return nil, fmt.Errorf("%s is unexpectedly large", hdr.Name)
		}
		if len(records) == recordsCap {
			return nil, fmt.Errorf("the snapshot holds more than %d records", recordsCap)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, damaged(err)
		}
		r, err := ParseRecord(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", hdr.Name, err)
		}
		for _, e := range r.Affected {
			ranges += len(e.Versions)
		}
		if ranges > rangesCap {
			return nil, fmt.Errorf("the snapshot holds more than %d version ranges", rangesCap)
		}
		if text += textBytes(r); text > textCap {
			return nil, fmt.Errorf("the snapshot keeps more than %d bytes of text", textCap)
		}
		records = append(records, r)
	}
	// archive/tar also stops at a file boundary when the stream ends there, without the two zero
	// blocks that end an archive; gzip's checksum is only read once the stream is drained.
	if unpacked.zeros < 2*512 {
		return nil, errors.New("the snapshot ends early")
	}
	if _, err := io.Copy(io.Discard, unpacked); err != nil {
		return nil, damaged(err)
	}
	if len(records) < s.MinRecords {
		return nil, fmt.Errorf("the snapshot holds %d published records, fewer than the %d expected", len(records), s.MinRecords)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func textBytes(r Record) int {
	n := len(r.ID)
	for _, e := range r.Affected {
		n += len(e.DefaultStatus)
		for _, v := range e.Versions {
			n += len(v.Version) + len(v.LessThan) + len(v.LessThanOrEqual) + len(v.Status) + len(v.VersionType)
		}
	}
	if r.CVSS != nil {
		n += len(r.CVSS.Vector) + len(r.CVSS.Severity)
	}
	return n
}

type limited struct {
	r     io.Reader
	n     int64
	max   int64
	what  string
	zeros int64
}

func (l *limited) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += int64(n)
	if l.n > l.max {
		return 0, &tooLarge{l.what, l.max}
	}
	for i := n - 1; i >= 0; i-- {
		if p[i] != 0 {
			l.zeros = int64(n - 1 - i)
			return n, err
		}
	}
	l.zeros += int64(n)
	return n, err
}

type tooLarge struct {
	what string
	max  int64
}

func (e *tooLarge) Error() string { return fmt.Sprintf("%s is larger than %d bytes", e.what, e.max) }

func damaged(err error) error {
	var big *tooLarge
	if errors.As(err, &big) {
		return big
	}
	return fmt.Errorf("the snapshot is damaged: %w", err)
}

func (s *Source) save(d *Data) error {
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.CacheDir, 0o700); err != nil {
		return err
	}
	leftovers, _ := filepath.Glob(filepath.Join(s.CacheDir, ".kernel-cna-*"))
	for _, f := range leftovers {
		_ = os.Remove(f)
	}
	tmp, err := os.CreateTemp(s.CacheDir, ".kernel-cna-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path())
}
