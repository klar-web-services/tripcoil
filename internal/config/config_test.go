package config

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"
)

func noStat(string) (FileInfo, error) { return FileInfo{}, errors.New("stat must not be called") }

func TestMissingFileGivesDefaults(t *testing.T) {
	c, err := load("/etc/tripcoil/tripcoil.yaml", func(string) ([]byte, error) { return nil, fs.ErrNotExist }, noStat)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Missing || c.Path != "/etc/tripcoil/tripcoil.yaml" {
		t.Fatalf("Missing %v Path %q", c.Missing, c.Path)
	}
	if c.Interval.Std() != 6*time.Hour || c.Review.Agent != "claude" || c.Review.Timeout.Std() != time.Hour ||
		c.Review.MaxAge.Std() != 168*time.Hour || c.Review.MemoryMax != "2G" || c.Review.CPUQuota != "100%" ||
		c.Audit.MaxDatabaseAgeHours != 48 || c.Retention.KeepRuns != 30 {
		t.Fatalf("defaults %+v", c)
	}
}

func TestFullFile(t *testing.T) {
	data := `version: 1
interval: 4h
review:
  agent: codex
  command: /usr/local/bin/codex
  model: gpt-5.2
  extraArgs: ["--foo"]
  timeout: 45m
  maxAge: 72h
  envFile: /etc/tripcoil/agent.env
  memoryMax: 1G
  cpuQuota: 50%
  allowAddresses: [10.0.0.5, 192.168.0.0/16, "fd00::1"]
audit:
  maxDatabaseAgeHours: 24
retention:
  keepRuns: 10
`
	stat := func(string) (FileInfo, error) { return FileInfo{UID: 0, Mode: 0o600, Regular: true}, nil }
	c, err := Parse("/etc/tripcoil/tripcoil.yaml", []byte(data), stat)
	if err != nil {
		t.Fatal(err)
	}
	r := c.Review
	if c.Interval.Std() != 4*time.Hour || r.Agent != "codex" || r.Command != "/usr/local/bin/codex" || r.Model != "gpt-5.2" ||
		len(r.ExtraArgs) != 1 || r.Timeout.Std() != 45*time.Minute || r.MaxAge.Std() != 72*time.Hour ||
		r.EnvFile != "/etc/tripcoil/agent.env" || r.MemoryMax != "1G" || r.CPUQuota != "50%" || len(r.AllowAddresses) != 3 ||
		c.Audit.MaxDatabaseAgeHours != 24 || c.Retention.KeepRuns != 10 || c.Missing {
		t.Fatalf("parsed %+v", c)
	}
}

func TestPartialFileKeepsDefaults(t *testing.T) {
	c, err := Parse("x.yaml", []byte("version: 1\nreview:\n  agent: none\n"), noStat)
	if err != nil {
		t.Fatal(err)
	}
	if c.Review.Agent != "none" || c.Review.Timeout.Std() != time.Hour || c.Review.MemoryMax != "2G" || c.Interval.Std() != 6*time.Hour {
		t.Fatalf("parsed %+v", c)
	}
}

func TestProblems(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"unknown field", "version: 1\nintervall: 6h\n", `line 2: unknown field "intervall" (check its spelling and indentation)`},
		{"short interval", "version: 1\ninterval: 5m\n", "line 2: interval must be at least 15m, found 5m0s"},
		{"interval not a duration", "version: 1\ninterval: 6\n", `line 2: expected a duration such as 6h or 30m, found "6"`},
		{"bad agent", "version: 1\nreview:\n  agent: gpt\n", `line 3: review.agent must be claude, codex or none, found "gpt"`},
		{"version missing", "interval: 6h\n", "version is missing; add version: 1 at the top"},
		{"version fraction", "version: 1.5\n", `line 1: expected a whole number, found "1.5"`},
		{"version quoted", "version: '1'\n", `line 1: expected a whole number, found "1"`},
		{"version 2", "version: 2\n", "line 1: version must be 1, found 2"},
		{"bad address", "version: 1\nreview:\n  allowAddresses: [10.0.0.5, nope]\n", `line 3: review.allowAddresses[1]: "nope" is not an IP address or CIDR range`},
		{"memory", "version: 1\nreview:\n  memoryMax: 2GB\n", `line 3: review.memoryMax must be a size such as 2G or 512M, found "2GB"`},
		{"cpu", "version: 1\nreview:\n  cpuQuota: \"100\"\n", `line 3: review.cpuQuota must be a percentage such as 100%, found "100"`},
		{"short timeout", "version: 1\nreview:\n  timeout: 500ms\n", "line 3: review.timeout must be at least 1s, found 500ms"},
		{"relative command", "version: 1\nreview:\n  command: claude\n", `line 3: review.command must be an absolute path, found "claude"`},
		{"keepRuns", "version: 1\nretention:\n  keepRuns: 0\n", "line 3: retention.keepRuns must be at least 1"},
		{"db age", "version: 1\naudit:\n  maxDatabaseAgeHours: 0\n", "line 3: audit.maxDatabaseAgeHours must be at least 1"},
		{"lan", "version: 1\nexposure:\n  lan: open\n", `line 3: exposure.lan must be lower, trusted or untrusted, found "open"`},
		{"port", "version: 1\nexposure:\n  internetPorts: [443, 70000]\n", "line 3: exposure.internetPorts[1]: 70000 is not a port (1 to 65535)"},
		{"port not a number", "version: 1\nexposure:\n  internetPorts: [https]\n", `line 3: expected a whole number, found "https"`},
		{"two documents", "version: 1\n---\nversion: 1\n", "the file holds more than one YAML document; keep only one"},
		{"empty", "", "the file is empty; it needs at least version: 1"},
		{"syntax", "version: 1\nreview: [\n", "not valid YAML"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("/etc/tripcoil/tripcoil.yaml", []byte(tc.yaml), noStat)
			if err == nil {
				t.Fatal("no error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
			if !strings.HasPrefix(err.Error(), "invalid configuration in /etc/tripcoil/tripcoil.yaml:\n") {
				t.Fatalf("error does not name the file: %q", err)
			}
		})
	}
}

func TestAllProblemsAtOnce(t *testing.T) {
	_, err := Parse("x.yaml", []byte("version: 1\ninterval: 1m\nreview:\n  agent: gpt\n"), noStat)
	var fe *FileError
	if !errors.As(err, &fe) || len(fe.Problems) != 2 {
		t.Fatalf("want 2 problems, got %v", err)
	}
}

func TestEnvFileChecks(t *testing.T) {
	const yaml = "version: 1\nreview:\n  envFile: /etc/tripcoil/agent.env\n"
	cases := []struct {
		name string
		info FileInfo
		err  error
		want string
	}{
		{"ok", FileInfo{UID: 0, Mode: 0o600, Regular: true}, nil, ""},
		{"not root", FileInfo{UID: 1000, Mode: 0o600, Regular: true}, nil, "line 3: review.envFile /etc/tripcoil/agent.env must be owned by root"},
		{"group readable", FileInfo{UID: 0, Mode: 0o640, Regular: true}, nil, "must not be readable by group or others (chmod 600 /etc/tripcoil/agent.env)"},
		{"directory", FileInfo{UID: 0, Mode: 0o700}, nil, "is not a regular file"},
		{"unreadable", FileInfo{}, fs.ErrNotExist, "review.envFile /etc/tripcoil/agent.env cannot be read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stat := func(string) (FileInfo, error) { return tc.info, tc.err }
			_, err := Parse("x.yaml", []byte(yaml), stat)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
	_, err := Parse("x.yaml", []byte("version: 1\nreview:\n  envFile: agent.env\n"), noStat)
	if err == nil || !strings.Contains(err.Error(), "review.envFile must be an absolute path") {
		t.Fatalf("relative envFile: %v", err)
	}
}

func TestExposure(t *testing.T) {
	c, err := Parse("/etc/tripcoil/tripcoil.yaml", []byte("version: 1\n"), noStat)
	if err != nil || c.Exposure.LAN != LANLower || c.Exposure.Ports() != nil {
		t.Fatalf("defaults: %+v, %v", c.Exposure, err)
	}
	c, err = Parse("/etc/tripcoil/tripcoil.yaml", []byte("version: 1\nexposure:\n  lan: trusted\n  internetPorts: []\n"), noStat)
	if err != nil || c.Exposure.LAN != LANTrusted || c.Exposure.Ports() == nil || len(*c.Exposure.Ports()) != 0 {
		t.Fatalf("an empty list is a statement that no port is public: %+v, %v", c.Exposure, err)
	}
	c, err = Parse("/etc/tripcoil/tripcoil.yaml", []byte("version: 1\nexposure:\n  internetPorts: [80, 443]\n"), noStat)
	if err != nil || c.Exposure.LAN != LANLower || !slices.Equal(*c.Exposure.Ports(), []int{80, 443}) {
		t.Fatalf("ports: %+v, %v", c.Exposure, err)
	}
}
