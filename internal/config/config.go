package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/klar-web-services/tripcoil/internal/zosia"
)

const DefaultPath = "/etc/tripcoil/tripcoil.yaml"

const docsURL = "https://github.com/klar-web-services/tripcoil#configuration"

type Config struct {
	Version   WholeNumber `yaml:"version"`
	Interval  Duration    `yaml:"interval"`
	Review    Review      `yaml:"review"`
	Audit     Audit       `yaml:"audit"`
	Retention Retention   `yaml:"retention"`
	Zosia     Zosia       `yaml:"zosia"`
	Exposure  Exposure    `yaml:"exposure"`

	Path    string `yaml:"-"`
	Missing bool   `yaml:"-"`
}

type Review struct {
	Agent          string   `yaml:"agent"`
	Command        string   `yaml:"command"`
	Model          string   `yaml:"model"`
	ExtraArgs      []string `yaml:"extraArgs"`
	Timeout        Duration `yaml:"timeout"`
	MaxAge         Duration `yaml:"maxAge"`
	EnvFile        string   `yaml:"envFile"`
	MemoryMax      string   `yaml:"memoryMax"`
	CPUQuota       string   `yaml:"cpuQuota"`
	AllowAddresses []string `yaml:"allowAddresses"`
}

type Audit struct {
	MaxDatabaseAgeHours WholeNumber `yaml:"maxDatabaseAgeHours"`
	// NewImages: when an image's tag points to a newer image, download and scan that one too, so
	// that the report says what the update brings. On unless set to false.
	NewImages bool `yaml:"newImages"`
}

type Retention struct {
	KeepRuns WholeNumber `yaml:"keepRuns"`
}

// Exposure is what the owner states about who can reach this machine. Both keys are optional.
type Exposure struct {
	// LAN says how findings on services that only the LAN can reach count: lower, trusted or untrusted.
	LAN string `yaml:"lan"`
	// InternetPorts, when set, are exactly the ports of this machine the internet can reach.
	InternetPorts *[]WholeNumber `yaml:"internetPorts"`
}

const (
	LANLower     = "lower"
	LANTrusted   = "trusted"
	LANUntrusted = "untrusted"
)

// Ports is InternetPorts as plain numbers; nil when the owner states nothing.
func (e Exposure) Ports() *[]int {
	if e.InternetPorts == nil {
		return nil
	}
	out := make([]int, len(*e.InternetPorts))
	for i, p := range *e.InternetPorts {
		out[i] = int(p)
	}
	return &out
}

const DefaultZosiaSecretFile = "/etc/tripcoil/zosia.secret"

type Zosia struct {
	SecretFile string `yaml:"secretFile"`
	URL        string `yaml:"url"`
	Key        string `yaml:"key"`
}

func Default() Config {
	return Config{
		Version:  1,
		Interval: Duration(6 * time.Hour),
		Review: Review{
			Agent:     "claude",
			Timeout:   Duration(60 * time.Minute),
			MaxAge:    Duration(168 * time.Hour),
			MemoryMax: "2G",
			CPUQuota:  "100%",
		},
		Audit:     Audit{MaxDatabaseAgeHours: 48, NewImages: true},
		Retention: Retention{KeepRuns: 30},
		Zosia:     Zosia{SecretFile: DefaultZosiaSecretFile},
		Exposure:  Exposure{LAN: LANLower},
	}
}

type FileError struct {
	Path     string
	Problems []string
}

func (e *FileError) Error() string {
	return fmt.Sprintf("invalid configuration in %s:\n  - %s\nSee %s for the format of tripcoil.yaml.",
		e.Path, strings.Join(e.Problems, "\n  - "), docsURL)
}

type FileInfo struct {
	UID     uint32
	Mode    fs.FileMode
	Regular bool
}

type StatFunc func(path string) (FileInfo, error)

func osStat(path string) (FileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileInfo{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileInfo{}, fmt.Errorf("cannot read the owner of %s", path)
	}
	return FileInfo{UID: st.Uid, Mode: fi.Mode().Perm(), Regular: fi.Mode().IsRegular()}, nil
}

func OSStat(path string) (FileInfo, error) { return osStat(path) }

func Load(path string) (Config, error) {
	return load(path, os.ReadFile, osStat)
}

func load(path string, read func(string) ([]byte, error), stat StatFunc) (Config, error) {
	data, err := read(path)
	if errors.Is(err, fs.ErrNotExist) {
		c := Default()
		c.Path, c.Missing = path, true
		return c, nil
	}
	if err != nil {
		return Config{}, &FileError{Path: path, Problems: []string{fmt.Sprintf("cannot read the file: %v", err)}}
	}
	return Parse(path, data, stat)
}

func Parse(path string, data []byte, stat StatFunc) (Config, error) {
	c := Default()
	c.Version = 0
	c.Path = path
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(&c)
	if errors.Is(err, io.EOF) {
		return Config{}, &FileError{Path: path, Problems: []string{"the file is empty; it needs at least version: 1"}}
	}
	if err != nil {
		return Config{}, &FileError{Path: path, Problems: yamlProblems(err)}
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, &FileError{Path: path, Problems: []string{"the file holds more than one YAML document; keep only one"}}
	}
	var root yaml.Node
	_ = yaml.Unmarshal(data, &root)
	if problems := validate(c, &root, stat); len(problems) > 0 {
		return Config{}, &FileError{Path: path, Problems: problems}
	}
	return c, nil
}

var (
	memoryPattern = regexp.MustCompile(`^[1-9][0-9]*[KMGT]?$`)
	cpuPattern    = regexp.MustCompile(`^[1-9][0-9]*%$`)
)

func validate(c Config, root *yaml.Node, stat StatFunc) []string {
	var p []string
	at := func(keys ...string) string {
		if l := lineOf(root, keys...); l > 0 {
			return fmt.Sprintf("line %d: ", l)
		}
		return ""
	}
	switch c.Version {
	case 0:
		p = append(p, "version is missing; add version: 1 at the top")
	case 1:
	default:
		p = append(p, at("version")+fmt.Sprintf("version must be 1, found %d", c.Version))
	}
	if c.Review.Timeout.Std() < time.Second { // systemd reads RuntimeMaxSec=0 as no limit
		p = append(p, at("review", "timeout")+fmt.Sprintf("review.timeout must be at least 1s, found %s", c.Review.Timeout.Std()))
	}
	if c.Interval.Std() < 15*time.Minute {
		p = append(p, at("interval")+fmt.Sprintf("interval must be at least 15m, found %s", c.Interval.Std()))
	}
	r := c.Review
	switch r.Agent {
	case "claude", "codex", "none":
	default:
		p = append(p, at("review", "agent")+fmt.Sprintf("review.agent must be claude, codex or none, found %q", r.Agent))
	}
	if r.Command != "" && !filepath.IsAbs(r.Command) {
		p = append(p, at("review", "command")+fmt.Sprintf("review.command must be an absolute path, found %q", r.Command))
	}
	if !memoryPattern.MatchString(r.MemoryMax) {
		p = append(p, at("review", "memoryMax")+fmt.Sprintf("review.memoryMax must be a size such as 2G or 512M, found %q", r.MemoryMax))
	}
	if !cpuPattern.MatchString(r.CPUQuota) {
		p = append(p, at("review", "cpuQuota")+fmt.Sprintf("review.cpuQuota must be a percentage such as 100%%, found %q", r.CPUQuota))
	}
	for i, a := range r.AllowAddresses {
		if _, err := netip.ParsePrefix(a); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(a); err == nil {
			continue
		}
		p = append(p, at("review", "allowAddresses")+fmt.Sprintf("review.allowAddresses[%d]: %q is not an IP address or CIDR range", i, a))
	}
	if r.EnvFile != "" {
		p = append(p, checkEnvFile(r.EnvFile, at("review", "envFile"), stat)...)
	}
	if c.Audit.MaxDatabaseAgeHours < 1 {
		p = append(p, at("audit", "maxDatabaseAgeHours")+"audit.maxDatabaseAgeHours must be at least 1")
	}
	if c.Retention.KeepRuns < 1 {
		p = append(p, at("retention", "keepRuns")+"retention.keepRuns must be at least 1")
	}
	if z := c.Zosia; z.SecretFile != "" && !filepath.IsAbs(z.SecretFile) {
		p = append(p, at("zosia", "secretFile")+"zosia.secretFile must be an absolute path")
	}
	if u := c.Zosia.URL; u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		p = append(p, at("zosia", "url")+"zosia.url must start with https:// (or http:// for a local test server)")
	}
	if k := c.Zosia.Key; k != "" {
		if _, err := zosia.ParseKey(k); err != nil {
			p = append(p, at("zosia", "key")+"zosia.key: "+err.Error())
		}
	}
	switch c.Exposure.LAN {
	case LANLower, LANTrusted, LANUntrusted:
	default:
		p = append(p, at("exposure", "lan")+fmt.Sprintf("exposure.lan must be lower, trusted or untrusted, found %q", c.Exposure.LAN))
	}
	if ports := c.Exposure.InternetPorts; ports != nil {
		for i, port := range *ports {
			if port < 1 || port > 65535 {
				p = append(p, at("exposure", "internetPorts")+fmt.Sprintf("exposure.internetPorts[%d]: %d is not a port (1 to 65535)", i, port))
			}
		}
	}
	return p
}

// Stat is the StatFunc config uses on the real file system.
func Stat(path string) (FileInfo, error) { return osStat(path) }

func checkEnvFile(path, at string, stat StatFunc) []string {
	if !filepath.IsAbs(path) {
		return []string{at + "review.envFile must be an absolute path"}
	}
	return CheckRootFile(path, "review.envFile", at, stat)
}

// CheckRootFile checks that path is a regular file owned by root that only root can read.
func CheckRootFile(path, field, at string, stat StatFunc) []string {
	fi, err := stat(path)
	if err != nil {
		return []string{at + fmt.Sprintf("%s %s cannot be read: %v", field, path, err)}
	}
	var p []string
	if !fi.Regular {
		p = append(p, at+fmt.Sprintf("%s %s is not a regular file", field, path))
	}
	if fi.UID != 0 {
		p = append(p, at+fmt.Sprintf("%s %s must be owned by root", field, path))
	}
	if fi.Mode&0o077 != 0 {
		p = append(p, at+fmt.Sprintf("%s %s must not be readable by group or others (chmod 600 %s)", field, path, path))
	}
	return p
}

func lineOf(root *yaml.Node, keys ...string) int {
	n := root
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	line := 0
	for _, k := range keys {
		if n.Kind != yaml.MappingNode {
			return line
		}
		found := false
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == k {
				line, n, found = n.Content[i].Line, n.Content[i+1], true
				break
			}
		}
		if !found {
			return line
		}
	}
	return line
}

type Duration time.Duration

func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!str" {
		if v, err := time.ParseDuration(n.Value); err == nil && v > 0 {
			*d = Duration(v)
			return nil
		}
	}
	return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: expected a duration such as 6h or 30m, found %s", n.Line, describe(n))}}
}

type WholeNumber int

func (w *WholeNumber) UnmarshalYAML(n *yaml.Node) error {
	var i int
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!int" && n.Decode(&i) == nil {
		*w = WholeNumber(i)
		return nil
	}
	return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: expected a whole number, found %s", n.Line, describe(n))}}
}
