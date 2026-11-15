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

// Codes of the Audit (spec sections 6 and 12).
const (
	GrypeUnavailable       = "GRYPE_UNAVAILABLE"         // Grype or its database cannot be obtained
	DBStale                = "DB_STALE"                  // the database is older than audit.maxDatabaseAgeHours
	OriginScanFailed       = "ORIGIN_SCAN_FAILED"        // one origin could not be scanned
	KernelDataStale        = "KERNEL_DATA_STALE"         // the kernel CNA data is too old, so the kernel is not audited
	OriginUnresolved       = "ORIGIN_UNRESOLVED"         // gap: the Inventory could not resolve an origin
	OriginUnidentified     = "ORIGIN_UNIDENTIFIED"       // gap: Grype found no packages in an origin, or no vulnerability data applies to them
	DBUpdateFailed         = "DB_UPDATE_FAILED"          // warning: the database could not be updated, but is fresh enough
	KernelDataUpdateFailed = "KERNEL_DATA_UPDATE_FAILED" // warning: the kernel CNA data could not be checked for news, but is fresh enough
	UpgradeCheckFailed     = "UPGRADE_CHECK_FAILED"      // warning: Grype could not check the upgrade lines, so none are given
)

// Codes of the Facts stage and the AI Review (spec sections 7, 8 and 12).
const (
	FactMissing          = "FACT_MISSING"           // gap: a fact could not be collected
	AgentMissing         = "AGENT_MISSING"          // the agent CLI is not installed safely
	AgentAuth            = "AGENT_AUTH"             // the agent CLI has no working credentials
	AgentSandbox         = "AGENT_SANDBOX"          // the sandbox could not be set up or did not hold
	AgentTimeout         = "AGENT_TIMEOUT"          // the review ran past review.timeout
	AgentFailed          = "AGENT_FAILED"           // the agent CLI failed
	AgentRefused         = "AGENT_REFUSED"          // the model refused the task
	AgentOutputInvalid   = "AGENT_OUTPUT_INVALID"   // the review does not parse or does not match the schema
	ReviewUnsupported    = "REVIEW_UNSUPPORTED"     // notice: systemd older than 247, so no review
	ReviewEntriesDropped = "REVIEW_ENTRIES_DROPPED" // warning: review entries for unknown findings or items were dropped
	AgentNetworkRestored = "AGENT_NETWORK_RESTORED" // warning: the agent's network table was recreated during the review
	AgentUnitLeft        = "AGENT_UNIT_LEFT"        // warning: a unit of the review could not be stopped, so its network table stays
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
