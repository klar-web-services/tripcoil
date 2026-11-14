// Package redact removes secrets from command lines before Tripcoil writes them anywhere
// (spec section 7.2).
package redact

import (
	"regexp"
	"strings"
)

// Mask replaces a secret value.
const Mask = "<redacted>"

// secretFlags take their secret as --flag=value or as the next argument.
var secretFlags = map[string]bool{
	"--password": true, "--passwd": true, "--token": true, "--secret": true, "--api-key": true, "--key": true,
}

var (
	// keyValue matches key=value where the key names a secret, also inside a longer argument
	// (a process title such as "postgres: shop password=x idle").
	keyValue = regexp.MustCompile(`(?i)\b([\w.-]*(?:password|token|secret|api[-_]?key)[\w.-]*)=(\S+)`)
	// urlCreds matches the password in scheme://user:password@host; the user may be empty (redis://:password@host).
	urlCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]*):([^/\s@]+)@`)
)

// Cmdline returns a copy of args with secret values replaced by Mask.
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
