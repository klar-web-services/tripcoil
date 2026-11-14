// Package problem is the shape of the errors, warnings, notices and coverage gaps a run records
// (spec section 12).
package problem

import "fmt"

// Kind says how a problem affects a run.
type Kind string

const (
	Error   Kind = "error"   // something Tripcoil tried failed; makes its stage partial or failed
	Warning Kind = "warning" // worth knowing; changes no status
	Notice  Kind = "notice"  // an expected situation, such as no Docker on the host
	Gap     Kind = "gap"     // a coverage gap: not audited by design or not identifiable
)

// Codes used in this plan. Later plans add theirs here.
const (
	ConfigInvalid       = "CONFIG_INVALID"
	RunFolderUnwritable = "RUN_FOLDER_UNWRITABLE"
	Interrupted         = "INTERRUPTED"
	InventoryFailed     = "INVENTORY_FAILED" // /proc itself could not be listed
	DockerAbsent        = "DOCKER_ABSENT"
	DockerUnavailable   = "DOCKER_UNAVAILABLE"
	PackageToolFailed   = "PACKAGE_TOOL_FAILED"
	AppDirNotFound      = "APPDIR_NOT_FOUND"
	ImageOnly           = "IMAGE_ONLY"
)

// Problem is one recorded error, warning, notice or coverage gap.
type Problem struct {
	Code    string `json:"code"`
	Kind    Kind   `json:"kind"`
	Stage   string `json:"stage,omitempty"`
	Message string `json:"message"`
}

// New builds a Problem with a formatted message.
func New(kind Kind, code, stage, format string, args ...any) Problem {
	return Problem{Code: code, Kind: kind, Stage: stage, Message: fmt.Sprintf(format, args...)}
}

// Split sorts problems into errors, warnings and notices, always as non-nil slices. Gaps are
// left out: they are recorded on the items and origins they concern.
func Split(ps []Problem) (errs, warns, notices []Problem) {
	errs, warns, notices = []Problem{}, []Problem{}, []Problem{}
	for _, p := range ps {
		switch p.Kind {
		case Error:
			errs = append(errs, p)
		case Warning:
			warns = append(warns, p)
		case Notice:
			notices = append(notices, p)
		}
	}
	return errs, warns, notices
}

// HasErrors reports whether any problem is an error.
func HasErrors(ps []Problem) bool {
	for _, p := range ps {
		if p.Kind == Error {
			return true
		}
	}
	return false
}
