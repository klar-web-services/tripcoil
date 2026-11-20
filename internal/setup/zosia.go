package setup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/zosia"
)

// zosia asks for the Zosia secret unless the secret file exists, sending is off, or nobody can answer.
func (h Host) zosia(o Options, c config.Config) (bool, error) {
	file := c.Zosia.SecretFile
	if file == "" {
		return false, nil
	}
	if h.exists(file) {
		fmt.Fprintf(h.Out, "· Zosia: connected (%s).\n", file)
		return false, nil
	}
	if o.Yes || !h.Terminal() {
		return false, nil
	}
	url := c.Zosia.URL
	if url == "" {
		url = zosia.DefaultURL
	}
	for range 2 {
		fmt.Fprintf(h.Out, "Zosia secret from %s/app/secrets (input hidden, empty to skip): ", url)
		line, err := h.readHidden()
		fmt.Fprintln(h.Out)
		secret := strings.TrimSpace(strings.NewReplacer("\x1b[200~", "", "\x1b[201~", "").Replace(line))
		if err != nil || secret == "" {
			break
		}
		name, err := h.PingZosia(url, secret)
		if err != nil {
			fmt.Fprintf(h.Out, "! Zosia: %v\n", err)
			continue
		}
		if err := WriteSecret(h.path(file), secret); err != nil {
			return false, err
		}
		fmt.Fprintf(h.Out, "✓ Connected to Zosia as %q.\n", name)
		return true, nil
	}
	fmt.Fprintf(h.Out, "· Zosia: skipped; connect later with %stripcoil setup.\n", h.Sudo)
	return false, nil
}

// WriteSecret writes the Zosia secret file in one step, readable by its owner only.
func WriteSecret(path, secret string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".zosia.secret-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(secret + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
