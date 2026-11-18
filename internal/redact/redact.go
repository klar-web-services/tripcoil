package redact

import (
	"regexp"
	"strings"
)

const Mask = "<redacted>"

var secretFlags = map[string]bool{
	"--password": true, "--passwd": true, "--token": true, "--secret": true, "--api-key": true, "--key": true,
}

var (
	keyValue = regexp.MustCompile(`(?i)\b([\w.-]*(?:password|token|secret|api[-_]?key)[\w.-]*)=(\S+)`)
	urlCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]*):([^/\s@]+)@`)
)

func Cmdline(args []string) []string {
	out := make([]string, len(args))
	maskNext := false
	for i, a := range args {
		if maskNext {
			out[i], maskNext = Mask, false
			continue
		}
		lower := strings.ToLower(a)
		if secretFlags[lower] {
			out[i], maskNext = a, true
			continue
		}
		if flag, _, ok := strings.Cut(lower, "="); ok && secretFlags[flag] {
			out[i] = a[:len(flag)] + "=" + Mask
			continue
		}
		a = urlCreds.ReplaceAllString(a, "${1}${2}:"+Mask+"@")
		a = keyValue.ReplaceAllString(a, "${1}="+Mask)
		out[i] = a
	}
	return out
}
