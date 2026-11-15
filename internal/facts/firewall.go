package facts

import (
	"errors"
	"fmt"
	"strings"
)

// firewall is facts/firewall.txt: the stateless nftables ruleset, or iptables' rules when there is
// no nft, plus the iptables-legacy rules when there are any (spec section 7.1). Each part starts
// with a "### <command>" line. Tripcoil's own table, inet tripcoil, is left out.
func (c collector) firewall() (string, error) {
	var b strings.Builder
	part := func(cmd, out string) {
		b.WriteString("### " + cmd + "\n" + out)
		if !strings.HasSuffix(out, "\n") {
			b.WriteString("\n")
		}
	}
	rules := false
	out, nftErr := c.d.Run(c.ctx, "nft", "-s", "list", "ruleset")
	if nftErr == nil {
		out := string(WithoutNftTable(out, "inet", "tripcoil"))
		part("nft -s list ruleset", out)
		rules = strings.TrimSpace(out) != ""
	} else {
		// No nft, or nft failed (no nf_tables in the kernel, a netlink error): iptables' own tools
		// may still read the rules.
		if !errors.Is(nftErr, errNotFound) {
			b.WriteString("# nft -s list ruleset failed: " + oneLine(nftErr.Error()) + "\n")
		}
		saved := false
		for _, cmd := range []string{"iptables-save", "ip6tables-save"} {
			out, err := c.d.Run(c.ctx, cmd)
			if errors.Is(err, errNotFound) {
				continue
			}
			if err != nil {
				if !errors.Is(nftErr, errNotFound) {
					return "", fmt.Errorf("%v; %v", nftErr, err)
				}
				return "", err
			}
			part(cmd, string(out))
			saved = true
			rules = rules || hasIptablesRules(out)
		}
		if !saved && !errors.Is(nftErr, errNotFound) {
			return "", nftErr // nothing could read the rules nft holds
		}
	}
	for _, cmd := range []string{"iptables-legacy-save", "ip6tables-legacy-save"} {
		out, err := c.d.Run(c.ctx, cmd)
		if err != nil || !hasIptablesRules(out) {
			continue // no legacy tool, or no legacy rules
		}
		part(cmd, string(out))
		rules = true
	}
	switch {
	case !rules && nftErr != nil && !errors.Is(nftErr, errNotFound):
		b.WriteString("# iptables shows no rules, but nftables could not be read.\n")
	case !rules:
		b.WriteString("# No firewall rules are loaded.\n")
	}
	return b.String(), nil
}

// oneLine keeps a tool's message on one line of firewall.txt.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func hasIptablesRules(out []byte) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "-A ") {
			return true
		}
	}
	return false
}

// WithoutNftTable removes one table from `nft list ruleset` output. nft prints each table from a
// "table <family> <name> {" line at the start of a line to its closing "}" at the start of a line.
func WithoutNftTable(out []byte, family, name string) []byte {
	var b strings.Builder
	skip := false
	for _, line := range strings.SplitAfter(string(out), "\n") {
		switch {
		case !skip && strings.TrimRight(line, "\n") == "table "+family+" "+name+" {":
			skip = true
		case skip:
			if strings.TrimRight(line, "\n") == "}" {
				skip = false
			}
		default:
			b.WriteString(line)
		}
	}
	return []byte(b.String())
}
