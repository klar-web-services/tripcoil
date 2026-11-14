// Command tripcoil watches a running Linux server for vulnerable software.
package main

import (
	"os"

	"github.com/klar-web-services/tripcoil/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
