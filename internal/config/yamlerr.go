package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

var (
	yamlUnknownField = regexp.MustCompile(`^line (\d+): field (\S+) not found in type \S+$`)
	yamlWrongType    = regexp.MustCompile("^line (\\d+): cannot unmarshal !!(\\w+)(?: `([^`]*)`)? into (\\S+)$")
	yamlSyntax       = regexp.MustCompile(`^yaml: line (\d+): (.+)$`)
	yamlGoType       = regexp.MustCompile(` (?:into|in type) \S+`)
)

// yamlProblems translates a YAML decoding error into problems in the user's terms, never Go types.
func yamlProblems(err error) []string {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		problems := make([]string, 0, len(te.Errors))
		for _, e := range te.Errors {
			problems = append(problems, yamlProblem(e))
		}
		return problems
	}
	msg := err.Error()
	if m := yamlSyntax.FindStringSubmatch(msg); m != nil {
		return []string{fmt.Sprintf("line %s: not valid YAML (%s); check the indentation and quotes", m[1], m[2])}
	}
	return []string{fmt.Sprintf("not valid YAML (%s); check the indentation and quotes", strings.TrimPrefix(msg, "yaml: "))}
}

func yamlProblem(e string) string {
	if m := yamlUnknownField.FindStringSubmatch(e); m != nil {
		return fmt.Sprintf("line %s: unknown field %q (check its spelling and indentation)", m[1], m[2])
	}
	if m := yamlWrongType.FindStringSubmatch(e); m != nil {
		return fmt.Sprintf("line %s: expected %s, found %s", m[1], expectedKind(m[4]), foundKind(m[2], m[3]))
	}
	return yamlGoType.ReplaceAllString(e, "")
}

// expectedKind names what a Go type accepts in YAML terms.
func expectedKind(goType string) string {
	switch {
	case strings.HasPrefix(goType, "[]"):
		return "a list"
	case strings.HasPrefix(goType, "map["), strings.Contains(goType, "."):
		return "a mapping"
	case goType == "bool":
		return "true or false"
	case goType == "string":
		return "a text value"
	case strings.HasPrefix(goType, "int"), strings.HasPrefix(goType, "uint"):
		return "a whole number"
	case strings.HasPrefix(goType, "float"):
		return "a number"
	}
	return "a different kind of value"
}

// foundKind names what the YAML held.
func foundKind(tag, value string) string {
	switch {
	case tag == "seq":
		return "a list"
	case tag == "map":
		return "a mapping"
	case tag == "null" || value == "":
		return "an empty value"
	}
	return strconv.Quote(value)
}

// describe names a YAML node for the custom types' messages.
func describe(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	}
	if n.ShortTag() == "!!null" {
		return "an empty value"
	}
	return strconv.Quote(n.Value)
}
