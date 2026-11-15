// Package fingerprint computes the change check's fingerprint (spec section 8.6): what decides
// whether a run needs a new review, or can carry the last one forward.
package fingerprint

import (
	"regexp"
	"strings"
)

// NormalizeFirewall turns facts/firewall.txt into the part of the ruleset that says what is
// exposed, leaving out what changes on its own (spec section 8.6):
//   - fail2ban's and CrowdSec's tables and chains (names starting with f2b- or crowdsec), whose bans
//     change constantly;
//   - the elements of sets with the dynamic or timeout flag;
//   - counters, and iptables-save's comment lines, which carry the time it ran;
//   - Docker's own chains (names starting with DOCKER, except DOCKER-USER), whose exposure the
//     containers' published ports already cover, and the rules Docker writes into the raw and nat
//     tables' built-in chains, which name a Docker bridge and container addresses or subnets: they
//     change whenever a container or a Compose network is recreated.
func NormalizeFirewall(text string) string {
	var out []string
	var part []string
	kind := ""
	flush := func() {
		switch kind {
		case "nft":
			out = append(out, normalizeNft(part)...)
		case "iptables":
			out = append(out, normalizeIptables(part)...)
		default:
			for _, l := range part {
				if strings.TrimSpace(l) != "" {
					out = append(out, l)
				}
			}
		}
		part = nil
	}
	for _, line := range strings.Split(text, "\n") {
		if cmd, ok := strings.CutPrefix(line, "### "); ok {
			flush()
			out = append(out, line)
			kind = "iptables"
			if strings.HasPrefix(cmd, "nft") {
				kind = "nft"
			}
			continue
		}
		part = append(part, line)
	}
	flush()
	return strings.Join(out, "\n") + "\n"
}

var (
	// churnName is a table or chain whose contents change on their own.
	churnName = regexp.MustCompile(`^(f2b-|crowdsec)`)
	// dockerBridge names a Docker bridge interface: docker0, or br- and 12 hex digits of a network ID.
	dockerBridge = regexp.MustCompile(`\b(docker0|br-[0-9a-f]{12})\b`)
	nftCounter   = regexp.MustCompile(`\s*\bcounter( packets \d+ bytes \d+)?`)
	iptCounters  = regexp.MustCompile(`\[\d+:\d+\]`)
)

func dockerChain(name string) bool { return strings.HasPrefix(name, "DOCKER") && name != "DOCKER-USER" }

// dockerTable is a table into whose built-in chains Docker writes rules for its bridges.
func dockerTable(name string) bool { return name == "raw" || name == "nat" }

// braces counts a line's opening and closing braces outside quoted strings.
func braces(line string) int {
	n, quoted := 0, false
	for _, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
		case quoted:
		case r == '{':
			n++
		case r == '}':
			n--
		}
	}
	return n
}

// normalizeNft normalizes `nft -s list ruleset` output: tables at the start of a line, holding
// sets, maps, chains and other blocks, each closed by its own "}" line.
func normalizeNft(lines []string) []string {
	var out []string
	var table string
	var block []string
	depth := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		before := depth
		depth += braces(line)
		switch {
		case before == 0: // a table header (or a stray line)
			f := strings.Fields(line)
			table = ""
			if len(f) >= 3 && f[0] == "table" {
				table = f[len(f)-2] // table <family> <name> {
			}
			if !churnName.MatchString(table) {
				out = append(out, line)
			}
		case before == 1 && depth >= 2: // a block in the table opens
			block = []string{line}
		case before >= 2: // inside a block
			block = append(block, line)
			if depth == 1 {
				if !churnName.MatchString(table) {
					out = append(out, normalizeBlock(table, block)...)
				}
				block = nil
			}
		default: // a one-line statement in the table, or the table's closing brace
			if !churnName.MatchString(table) {
				out = append(out, line)
			}
		}
	}
	return out
}

// normalizeBlock normalizes one set, map or chain of an nft table.
func normalizeBlock(table string, block []string) []string {
	f := strings.Fields(block[0])
	if len(f) < 2 {
		return block
	}
	kind, name := f[0], f[1]
	switch kind {
	case "chain":
		if churnName.MatchString(name) || dockerChain(name) {
			return nil
		}
		var out []string
		for _, l := range block {
			if dockerTable(table) && dockerBridge.MatchString(l) {
				continue
			}
			out = append(out, nftCounter.ReplaceAllString(l, ""))
		}
		return out
	case "set", "map":
		churn := false
		for _, l := range block[1:] {
			if flags, ok := strings.CutPrefix(strings.TrimSpace(l), "flags "); ok && (strings.Contains(flags, "dynamic") || strings.Contains(flags, "timeout")) {
				churn = true
			}
		}
		if !churn {
			return block
		}
		var out []string
		depth := 0
		for i, l := range block {
			if i > 0 && depth == 0 && strings.HasPrefix(strings.TrimSpace(l), "elements = {") {
				depth = braces(l)
				continue
			}
			if depth > 0 {
				depth += braces(l)
				continue
			}
			out = append(out, l)
		}
		return out
	}
	return block
}

// normalizeIptables normalizes iptables-save output.
func normalizeIptables(lines []string) []string {
	var out []string
	table := ""
	for _, line := range lines {
		switch {
		case strings.TrimSpace(line) == "", strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "*"):
			table = line[1:]
		case strings.HasPrefix(line, ":"):
			name := strings.Fields(line[1:])[0]
			if churnName.MatchString(name) || dockerChain(name) {
				continue
			}
			line = strings.TrimSpace(iptCounters.ReplaceAllString(line, ""))
		case strings.HasPrefix(line, "-A "):
			f := strings.Fields(line)
			if len(f) < 2 || churnName.MatchString(f[1]) || dockerChain(f[1]) || dockerTable(table) && dockerBridge.MatchString(line) {
				continue
			}
		}
		out = append(out, iptCounters.ReplaceAllString(line, ""))
	}
	return out
}
