package setup

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/klar-web-services/tripcoil/internal/run"
)

// RestartUpdated restarts the running service after its binary was replaced. A run in progress is
// interrupted only when the user agrees.
func (h Host) RestartUpdated(stateDir string) error {
	svc, err := h.Service()
	if err != nil || !svc.Running {
		return nil
	}
	cmd, hint := []string{"systemctl", "restart", "tripcoil.service"}, "systemctl restart tripcoil"
	if svc.Manager == OpenRC {
		cmd, hint = []string{"rc-service", "tripcoil", "restart"}, "rc-service tripcoil restart"
	}
	busy, err := run.Busy(h.path(stateDir))
	if err != nil {
		return err
	}
	if busy {
		a, err := h.ask("A run is in progress. Interrupt it and restart the service now? yes or no", "no", "yes", "y", "no", "n")
		if err != nil {
			fmt.Fprintln(h.Out)
		}
		if err != nil || a == "no" || a == "n" {
			fmt.Fprintf(h.Out, "Restart the service to use the new version: %s%s\n", h.Sudo, hint)
			return nil
		}
	}
	if out, err := h.Run(cmd[0], cmd[1:]...); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(cmd, " "), err, bytes.TrimSpace(out))
	}
	fmt.Fprintln(h.Out, "Restarted the tripcoil service.")
	return nil
}
