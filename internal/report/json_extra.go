package report

import (
	"time"

	"github.com/klar-web-services/tripcoil/internal/audit"
	"github.com/klar-web-services/tripcoil/internal/inventory"
	"github.com/klar-web-services/tripcoil/internal/review"
)

type JSONHost struct {
	Hostname string `json:"hostname"`
	Distro   string `json:"distro"`
	Kernel   string `json:"kernel"`
}

type JSONNames struct {
	Items   map[string]string `json:"items"`
	Origins map[string]string `json:"origins"`
}

type JSONRestart struct {
	Item          string   `json:"item"`
	Name          string   `json:"name"`
	Units         []string `json:"units,omitempty"`
	RestartNeeded []string `json:"restartNeeded,omitempty"`
	RebootPending bool     `json:"rebootPending,omitempty"`
	RebootReasons []string `json:"rebootReasons,omitempty"`
}

type JSONFreshness struct {
	Grype             string    `json:"grype"`
	DBBuilt           time.Time `json:"dbBuilt,omitzero"`
	KernelDataChecked time.Time `json:"kernelDataChecked,omitzero"`
}

func jsonHost(inv *inventory.Inventory) *JSONHost {
	if inv == nil {
		return nil
	}
	h := &JSONHost{Hostname: inv.Host.Hostname, Distro: distroName(inv.Host.Distro)}
	for _, it := range inv.Items {
		if it.Kind == inventory.KindKernel {
			h.Kernel = it.Release
		}
	}
	return h
}

// jsonNames names the items and origins the findings and added findings refer to.
func jsonNames(inv *inventory.Inventory, aud *audit.Audit, added []review.Entry) JSONNames {
	n := JSONNames{Items: map[string]string{}, Origins: map[string]string{}}
	if inv == nil {
		return n
	}
	items, origins, users := itemNamesByID(inv), originsByID(inv), itemNames(inv)
	if aud != nil {
		for _, f := range aud.Findings {
			for _, id := range f.Items {
				if name, ok := items[id]; ok {
					n.Items[id] = name
				}
			}
			if o, ok := origins[f.Origin]; ok {
				n.Origins[f.Origin] = describe(o, users[o.ID])
			}
		}
	}
	for _, e := range added {
		if name, ok := items[e.Item]; ok {
			n.Items[e.Item] = name
		}
	}
	return n
}

func jsonRestarts(inv *inventory.Inventory) []JSONRestart {
	out := []JSONRestart{}
	if inv == nil {
		return out
	}
	for _, it := range inv.Items {
		reboot := it.RebootPending != nil && *it.RebootPending
		if len(it.RestartNeeded) == 0 && !reboot {
			continue
		}
		out = append(out, JSONRestart{Item: it.ID, Name: it.Name, Units: it.Units, RestartNeeded: it.RestartNeeded,
			RebootPending: reboot, RebootReasons: it.RebootReasons})
	}
	return out
}

func jsonFreshness(aud *audit.Audit) *JSONFreshness {
	if aud == nil {
		return nil
	}
	f := &JSONFreshness{Grype: aud.Grype.Version, DBBuilt: aud.Grype.DBBuilt}
	if aud.KernelData != nil {
		f.KernelDataChecked = aud.KernelData.Checked
	}
	return f
}

// Payload is JSON(in) for Zosia: each finding without its advisory text, CPEs and raw file name,
// which Zosia does not show.
func Payload(in Input) JSONReport {
	out := JSON(in)
	for i := range out.Findings {
		f := &out.Findings[i]
		f.Vulnerability.Description = ""
		f.Package.CPEs = nil
		f.Raw = ""
	}
	return out
}
