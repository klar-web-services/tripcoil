package facts

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Processes struct {
	Processes  []ProcessFact `json:"processes"`
	Units      []UnitFact    `json:"units"`
	UnitsError string        `json:"unitsError,omitempty"`
}

type ProcessFact struct {
	PID        int    `json:"pid"`
	Item       string `json:"item"`
	UID        int    `json:"uid"`
	GID        int    `json:"gid"`
	CapEff     string `json:"capEff"`
	NoNewPrivs bool   `json:"noNewPrivs"`
	Seccomp    int    `json:"seccomp"`
}

type UnitFact struct {
	Unit       string            `json:"unit"`
	Properties map[string]string `json:"properties"`
}

var unitProperties = []string{"User", "NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "CapabilityBoundingSet", "RestrictNamespaces", "SystemCallFilter"}

var unitName = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+\.(service|scope|socket)$`)

func (c collector) processes() (Processes, error) {
	out := Processes{Processes: []ProcessFact{}, Units: []UnitFact{}}
	var units []string
	for _, it := range c.inv.Items {
		for _, p := range it.Processes {
			if f, ok := c.processFact(p.PID); ok {
				f.Item = it.ID
				out.Processes = append(out.Processes, f)
			}
		}
		for _, u := range it.Units {
			if unitName.MatchString(u) && !slices.Contains(units, u) {
				units = append(units, u)
			}
		}
	}
	slices.SortFunc(out.Processes, func(a, b ProcessFact) int { return a.PID - b.PID })
	slices.Sort(units)
	if len(units) == 0 || c.inv.Host.Init != "systemd" {
		return out, nil
	}
	for start := 0; start < len(units); start += 100 {
		batch := units[start:min(start+100, len(units))]
		args := append([]string{"show", "-p", "Id," + strings.Join(unitProperties, ","), "--"}, batch...)
		data, err := c.d.Run(c.ctx, "systemctl", args...)
		if err != nil {
			out.Units, out.UnitsError = []UnitFact{}, err.Error()
			return out, nil
		}
		out.Units = append(out.Units, parseUnits(data)...)
	}
	return out, nil
}

func (c collector) processFact(pid int) (ProcessFact, bool) {
	f, err := os.Open(filepath.Join(c.d.Root, "proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return ProcessFact{}, false
	}
	defer f.Close()
	pf := ProcessFact{PID: pid}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		switch k {
		case "Uid":
			if len(fields) > 1 {
				pf.UID, _ = strconv.Atoi(fields[1])
			}
		case "Gid":
			if len(fields) > 1 {
				pf.GID, _ = strconv.Atoi(fields[1])
			}
		case "CapEff":
			pf.CapEff = fields[0]
		case "NoNewPrivs":
			pf.NoNewPrivs = fields[0] == "1"
		case "Seccomp":
			pf.Seccomp, _ = strconv.Atoi(fields[0])
		}
	}
	return pf, true
}

func parseUnits(data []byte) []UnitFact {
	var out []UnitFact
	cur := UnitFact{Properties: map[string]string{}}
	flush := func() {
		if cur.Unit != "" {
			out = append(out, cur)
		}
		cur = UnitFact{Properties: map[string]string{}}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == "Id" {
			cur.Unit = v
		} else {
			cur.Properties[k] = v
		}
	}
	flush()
	return out
}
