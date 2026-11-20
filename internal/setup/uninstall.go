package setup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/klar-web-services/tripcoil/internal/agent"
	"github.com/klar-web-services/tripcoil/internal/config"
	"github.com/klar-web-services/tripcoil/internal/run"
	"github.com/klar-web-services/tripcoil/internal/sandbox"
	"github.com/klar-web-services/tripcoil/internal/zosia"
)

type UninstallOptions struct {
	Yes      bool
	StateDir string
}

const logPath = "/var/log/tripcoil.log"

func (h Host) Uninstall(o UninstallOptions) error {
	underHome := strings.HasPrefix(h.Exe, "/home/") || h.Exe == "/home"
	if !o.Yes {
		what := []string{"the service", filepath.Dir(config.DefaultPath) + " (config and token)", o.StateDir + " (runs and cache)", "the user " + agent.UserName}
		if len(h.markedNodeSource()) > 0 {
			what = append(what, "NodeSource's repository")
		}
		if !underHome {
			what = append(what, h.Exe)
		}
		last := len(what) - 1
		a, err := h.ask(fmt.Sprintf("Remove Tripcoil from this host: %s and %s? yes or no", strings.Join(what[:last], ", "), what[last]), "no", "yes", "no")
		if err != nil {
			return errors.New("no answer; run tripcoil uninstall with --yes to remove without asking")
		}
		if a == "no" {
			fmt.Fprintln(h.Out, "Nothing removed.")
			return nil
		}
	}
	failed := false
	step := func(removed bool, err error, done, absent string) {
		switch {
		case err != nil:
			failed = true
			fmt.Fprintf(h.Out, "! %v\n", err)
		case removed:
			fmt.Fprintf(h.Out, "✓ %s\n", done)
		default:
			fmt.Fprintf(h.Out, "· %s\n", absent)
		}
	}
	if m, err := h.Manager(); err != nil {
		step(false, nil, "", "Neither systemd nor OpenRC runs this host, so there is no service to remove.")
	} else {
		removed, err := h.removeService(m)
		step(removed, err, "Stopped and removed the tripcoil service.", "The tripcoil service was not installed.")
	}
	if _, err := h.LookPath("nft"); err != nil {
		step(false, nil, "", "nft is not installed, so there is no nftables table to delete.")
	} else {
		removed, err := h.deleteTable()
		step(removed, err, "Deleted the nftables table inet tripcoil.", "The nftables table inet tripcoil was not there.")
	}
	removed, err := h.removeNodeSource()
	if len(removed) > 0 {
		step(true, nil, "Removed NodeSource's repository: "+strings.Join(removed, ", ")+".", "")
	}
	if err != nil || len(removed) == 0 {
		step(false, err, "", "Setup added no NodeSource repository.")
	}
	secret := h.exists(config.DefaultZosiaSecretFile)
	for _, dir := range []string{filepath.Dir(config.DefaultPath), o.StateDir} {
		removed, err := h.removeDir(dir)
		done := "Removed " + dir + "."
		if secret && dir == filepath.Dir(config.DefaultPath) {
			done = fmt.Sprintf("Removed %s, with the Zosia secret %s; revoke it at %s/app/secrets.", dir, config.DefaultZosiaSecretFile, zosia.DefaultURL)
		}
		step(removed, err, done, dir+" was not there.")
	}
	removedUser, err := h.removeAgentUser()
	step(removedUser, err, "Removed the user and group "+agent.UserName+".", "The user "+agent.UserName+" was not there.")
	switch {
	case underHome:
		fmt.Fprintf(h.Out, "· %s is under /home; it stays.\n", h.Exe)
	case failed:
		fmt.Fprintf(h.Out, "! Kept %s so tripcoil uninstall can run again once the above is fixed.\n", h.Exe)
	default:
		removedExe, err := h.remove(h.Exe)
		step(removedExe, err, "Removed "+h.Exe+".", h.Exe+" was not there.")
	}
	fmt.Fprintf(h.Out, "Node.js, npm, Claude Code and bubblewrap stay installed; remove Claude Code with: %snpm uninstall -g %s\n", h.Sudo, claudePackage)
	if failed {
		return errors.New("some steps failed; fix what they name, then run tripcoil uninstall again")
	}
	return nil
}

func (h Host) removeService(m Manager) (bool, error) {
	if m == Systemd {
		if out, err := h.Run("systemctl", "disable", "--now", "tripcoil.service"); err != nil &&
			!bytes.Contains(out, []byte("not loaded")) && !bytes.Contains(out, []byte("does not exist")) {
			return false, fmt.Errorf("systemctl disable --now tripcoil.service: %v: %s", err, bytes.TrimSpace(out))
		}
		h.Run("systemctl", "stop", sandbox.UnitPrefix+"*")
		h.Run("systemctl", "stop", "tripcoil-run-*")
		removed, err := h.remove(UnitPath)
		if err != nil || !removed {
			return false, err
		}
		if out, err := h.Run("systemctl", "daemon-reload"); err != nil {
			return true, fmt.Errorf("systemctl daemon-reload: %v: %s", err, bytes.TrimSpace(out))
		}
		return true, nil
	}
	var steps [][]string
	if _, err := h.Run("rc-service", "tripcoil", "status"); err == nil {
		steps = append(steps, []string{"rc-service", "tripcoil", "stop"})
	}
	if out, _ := h.Run("rc-update", "show", "default"); hasService(out) {
		steps = append(steps, []string{"rc-update", "del", "tripcoil", "default"})
	}
	for _, s := range steps {
		if out, err := h.Run(s[0], s[1:]...); err != nil {
			return false, fmt.Errorf("%s: %v: %s", strings.Join(s, " "), err, bytes.TrimSpace(out))
		}
	}
	removed := len(steps) > 0
	for _, p := range []string{InitScriptPath, ConfDPath, logPath} {
		did, err := h.remove(p)
		if err != nil {
			return removed, err
		}
		removed = removed || did
	}
	return removed, nil
}

func (h Host) deleteTable() (bool, error) {
	if _, err := h.Run("nft", "list", "table", "inet", "tripcoil"); err != nil {
		return false, nil
	}
	out, err := h.Run("nft", "delete", "table", "inet", "tripcoil")
	if err == nil {
		return true, nil
	}
	return false, fmt.Errorf("nft delete table inet tripcoil: %v: %s", err, bytes.TrimSpace(out))
}

func (h Host) markedNodeSource() []string {
	var marked []string
	for _, p := range NodeSourceFiles {
		if data, err := os.ReadFile(h.path(p)); err == nil && bytes.HasPrefix(data, []byte(AddedMarker+"\n")) {
			marked = append(marked, p)
		}
	}
	return marked
}

func (h Host) removeNodeSource() ([]string, error) {
	var removed []string
	for _, p := range h.markedNodeSource() {
		// The key goes before its mark, so a failed removal leaves the mark for the next run.
		if p == NodeSourceKeyMarkPath && h.exists(NodeSourceKeyPath) {
			if err := os.Remove(h.path(NodeSourceKeyPath)); err != nil {
				return removed, err
			}
			removed = append(removed, NodeSourceKeyPath)
		}
		if err := os.Remove(h.path(p)); err != nil {
			return removed, err
		}
		removed = append(removed, p)
	}
	for _, p := range NodeSourceFiles {
		if h.hostOwned(p) {
			fmt.Fprintf(h.Out, "· %s is the host's own; it stays.\n", p)
		}
	}
	return removed, nil
}

func (h Host) removeDir(dir string) (bool, error) {
	if !h.exists(dir) {
		return false, nil
	}
	err := os.RemoveAll(h.path(dir))
	if errors.Is(err, syscall.EBUSY) {
		return false, fmt.Errorf("%s is busy, likely a review's agent home that is still mounted (%v); reboot, then run tripcoil uninstall again", dir, err)
	}
	return err == nil, err
}

func (h Host) removeAgentUser() (bool, error) {
	delUser, delGroup := "userdel", "groupdel"
	if _, err := h.LookPath("userdel"); err != nil { // BusyBox, as on Alpine
		delUser, delGroup = "deluser", "delgroup"
	}
	removed := false
	if h.UserExists(agent.UserName) {
		if out, err := h.Run(delUser, agent.UserName); err != nil {
			return false, fmt.Errorf("%s %s: %v: %s", delUser, agent.UserName, err, bytes.TrimSpace(out))
		}
		removed = true
	}
	if h.GroupExists(run.AgentGroup) {
		out, err := h.Run(delGroup, run.AgentGroup)
		switch {
		case err == nil:
			removed = true
		case !bytes.Contains(out, []byte("does not exist")):
			return removed, fmt.Errorf("%s %s: %v: %s", delGroup, run.AgentGroup, err, bytes.TrimSpace(out))
		}
	}
	return removed, nil
}

func (h Host) remove(p string) (bool, error) {
	err := os.Remove(h.path(p))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
