package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/klar-web-services/tripcoil/internal/buildinfo"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/osrel"
	"github.com/klar-web-services/tripcoil/internal/setup"
	"github.com/klar-web-services/tripcoil/internal/zosia"
)

const zosiaUsage = `Usage: tripcoil zosia connect [--replace]

Connect this machine to Zosia (https://zosiasec.com), as root: it prints a code and a link, you
approve the code in a browser where you are logged in to Zosia, and Tripcoil stores the secret it
receives in /etc/tripcoil/zosia.secret. From then on every finished run sends its report.

Flags:
  -replace
    	connect again although a secret file exists
`

func runZosia(args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, zosiaUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] != "connect" {
		fmt.Fprintf(stderr, "tripcoil zosia: unknown command %q\n\n%s", args[0], zosiaUsage)
		return 2
	}
	fs := flag.NewFlagSet("tripcoil zosia connect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	replace := fs.Bool("replace", false, "connect again although a secret file exists")
	fs.Usage = func() { fmt.Fprint(stderr, zosiaUsage) }
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tripcoil zosia connect: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if d.euid() != 0 {
		fmt.Fprintln(stderr, "tripcoil zosia connect must run as root (try: sudo tripcoil zosia connect)")
		return 2
	}
	cfg, err := config.Load(d.configPath)
	if err != nil {
		fmt.Fprintf(stderr, "tripcoil zosia connect: %v\n", err)
		return 1
	}
	file := cfg.Zosia.SecretFile
	if file == "" {
		fmt.Fprintf(stderr, "zosia.secretFile is empty in %s, so sending to Zosia is off.\n", cfg.Path)
		return 1
	}
	_, replacing, _ := d.zosiaSecret(file)
	if replacing && !*replace {
		fmt.Fprintf(stderr, "Zosia is already connected (%s). Use --replace to connect again.\n", file)
		return 1
	}
	url := cfg.Zosia.URL
	if url == "" {
		url = zosia.DefaultURL
	}
	ctx, stop := d.interrupts()
	defer stop()
	name, err := connectZosia(ctx, d, url, file, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "Zosia: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "✓ Connected to Zosia as %q. The next run sends its report.\n", name)
	if replacing {
		fmt.Fprintf(stdout, "The secret this replaces stays valid until you revoke it at %s/app/secrets.\n", url)
	}
	return 0
}

// connectZosia has the person approve this machine in the browser and stores the secret Zosia
// hands over in file. The secret is never printed. Setup uses it too.
func connectZosia(ctx context.Context, d deps, url, file string, stdout io.Writer) (name string, err error) {
	r, err := d.startConnect(ctx, url, d.hostInfo())
	if err != nil {
		return "", err
	}
	fmt.Fprintf(stdout, "Open this page in a browser where you are logged in to Zosia:\n\n    %s\n\nor open %s and enter the code %s.\n",
		r.VerificationURIComplete, r.VerificationURI, r.UserCode)
	fmt.Fprintf(stdout, "Waiting for you to approve (%d minutes at most; Ctrl-C cancels) …\n", r.ExpiresIn/60)
	secret, name, err := d.waitConnect(ctx, url, r)
	var ze *zosia.Error
	switch {
	case errors.As(err, &ze) && ze.Code == "DENIED":
		return "", errors.New("the request was denied.")
	case errors.As(err, &ze) && ze.Code == "EXPIRED":
		return "", errors.New("nobody approved in time; run the command again.")
	case errors.As(err, &ze) && ze.Code == "CANCELLED":
		return "", errors.New("cancelled; nothing changed.")
	case err != nil:
		return "", err
	}
	if err := setup.WriteSecret(file, secret); err != nil {
		return "", err
	}
	if _, err := d.pingZosia(ctx, url, secret); err != nil {
		return "", fmt.Errorf("the secret is stored in %s, but checking it failed: %v", file, err)
	}
	return name, nil
}

func hostInfo() zosia.HostInfo {
	h := zosia.HostInfo{Version: buildinfo.Version}
	h.Hostname, _ = os.Hostname()
	if rel, err := osrel.Read("/"); err == nil {
		h.OS = rel.ID
		if rel.VersionID != "" {
			h.OS += " " + rel.VersionID
		}
	}
	return h
}
