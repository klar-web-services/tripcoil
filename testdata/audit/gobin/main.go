// Command gobin is a deliberately vulnerable test fixture: it links golang.org/x/text v0.3.5 and
// calls the language parsers that have known vulnerabilities, so Grype keeps their matches.
package main

import (
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func main() {
	tags, _, err := language.ParseAcceptLanguage(os.Getenv("ACCEPT_LANGUAGE"))
	tag, err2 := language.Parse("en-US")
	fmt.Println(tags, err, tag, err2)
}
