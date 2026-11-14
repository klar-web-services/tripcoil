package inventory

import (
	"slices"
	"sort"
)

// itemBuilder merges processes into items and origins into one deduplicated set.
type itemBuilder struct {
	items   map[string]*draft
	origins map[string]*Origin
}

type draft struct {
	item    Item
	units   map[string]bool
	restart map[string]bool
	notes   map[string]bool
	origins map[string]bool
}

func newBuilder() *itemBuilder {
	return &itemBuilder{items: map[string]*draft{}, origins: map[string]*Origin{}}
}

// process returns the draft of the host process item keyed by key and appDir, creating it on
// first use. key is the executable, or for a process whose origin is unresolved "unresolved:<exe>",
// or "unresolved:command:<name>" when its executable cannot be read.
func (b *itemBuilder) process(key, exe, appDir, name string) *draft {
	id := ProcessItemID(key, appDir)
	d, ok := b.items[id]
	if !ok {
		d = &draft{
			item:  Item{ID: id, Kind: KindProcess, Name: name, Exe: exe, AppDir: appDir},
			units: map[string]bool{}, restart: map[string]bool{}, notes: map[string]bool{}, origins: map[string]bool{},
		}
		b.items[id] = d
	}
	return d
}

func (d *draft) addProcess(p Process, unit string) {
	d.item.Processes = append(d.item.Processes, p)
	if unit != "" {
		d.units[unit] = true
	}
}

func (d *draft) restartNeeded(path string) { d.restart[path] = true }

func (d *draft) note(code string) { d.notes[code] = true }

// link attaches an origin to the item, merging it into an origin with the same ID.
func (b *itemBuilder) link(d *draft, o Origin) {
	if have, ok := b.origins[o.ID]; ok {
		have.RunningOlderCopy = have.RunningOlderCopy || o.RunningOlderCopy
		for _, p := range o.Paths {
			if !slices.Contains(have.Paths, p) {
				have.Paths = append(have.Paths, p)
			}
		}
		if have.Copy == "" {
			have.Copy = o.Copy
		}
	} else {
		c := o
		c.Paths = slices.Clone(o.Paths)
		b.origins[o.ID] = &c
	}
	d.origins[o.ID] = true
}

// result returns the items sorted by name, then ID, and the origins sorted by ID.
func (b *itemBuilder) result() ([]Item, []Origin) {
	items := make([]Item, 0, len(b.items))
	for _, d := range b.items {
		it := d.item
		sort.Slice(it.Processes, func(i, j int) bool { return it.Processes[i].PID < it.Processes[j].PID })
		it.Units, it.RestartNeeded, it.Notes, it.Origins = sortedKeys(d.units), sortedKeys(d.restart), sortedKeys(d.notes), sortedKeys(d.origins)
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].ID < items[j].ID
	})
	origins := make([]Origin, 0, len(b.origins))
	for _, o := range b.origins {
		sort.Strings(o.Paths)
		origins = append(origins, *o)
	}
	sort.Slice(origins, func(i, j int) bool { return origins[i].ID < origins[j].ID })
	return items, origins
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
