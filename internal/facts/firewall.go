package facts

import (
	"errors"
	"fmt"
	"strings"
)

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
			return "", nftErr
		}
	}
	for _, cmd := range []string{"iptables-legacy-save", "ip6tables-legacy-save"} {
		out, err := c.d.Run(c.ctx, cmd)
		if err != nil || !hasIptablesRules(out) {
			continue
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

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func hasIptablesRules(out []byte) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "-A ") {
			return true
		}
	}
	return false
}

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
