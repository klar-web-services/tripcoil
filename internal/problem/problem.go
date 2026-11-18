package problem

import "fmt"

type Kind string

const (
	Error   Kind = "error"
	Warning Kind = "warning"
	Notice  Kind = "notice"
	Gap     Kind = "gap"
)

const (
	ConfigInvalid       = "CONFIG_INVALID"
	RunFolderUnwritable = "RUN_FOLDER_UNWRITABLE"
	Interrupted         = "INTERRUPTED"
	InventoryFailed     = "INVENTORY_FAILED"
	DockerAbsent        = "DOCKER_ABSENT"
	DockerUnavailable   = "DOCKER_UNAVAILABLE"
	PackageToolFailed   = "PACKAGE_TOOL_FAILED"
	AppDirNotFound      = "APPDIR_NOT_FOUND"
	ImageOnly           = "IMAGE_ONLY"
)

const (
	GrypeUnavailable       = "GRYPE_UNAVAILABLE"
	DBStale                = "DB_STALE"
	OriginScanFailed       = "ORIGIN_SCAN_FAILED"
	KernelDataStale        = "KERNEL_DATA_STALE"
	OriginUnresolved       = "ORIGIN_UNRESOLVED"
	OriginUnidentified     = "ORIGIN_UNIDENTIFIED"
	DBUpdateFailed         = "DB_UPDATE_FAILED"
	KernelDataUpdateFailed = "KERNEL_DATA_UPDATE_FAILED"
	UpgradeCheckFailed     = "UPGRADE_CHECK_FAILED"
)

const (
	FactMissing          = "FACT_MISSING"
	AgentMissing         = "AGENT_MISSING"
	AgentAuth            = "AGENT_AUTH"
	AgentSandbox         = "AGENT_SANDBOX"
	AgentTimeout         = "AGENT_TIMEOUT"
	AgentFailed          = "AGENT_FAILED"
	AgentRefused         = "AGENT_REFUSED"
	AgentOutputInvalid   = "AGENT_OUTPUT_INVALID"
	ReviewUnsupported    = "REVIEW_UNSUPPORTED"
	ReviewEntriesDropped = "REVIEW_ENTRIES_DROPPED"
	AgentNetworkRestored = "AGENT_NETWORK_RESTORED"
	AgentUnitLeft        = "AGENT_UNIT_LEFT"
)

type Problem struct {
	Code    string `json:"code"`
	Kind    Kind   `json:"kind"`
	Stage   string `json:"stage,omitempty"`
	Message string `json:"message"`
}

func New(kind Kind, code, stage, format string, args ...any) Problem {
	return Problem{Code: code, Kind: kind, Stage: stage, Message: fmt.Sprintf(format, args...)}
}

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

func HasErrors(ps []Problem) bool {
	for _, p := range ps {
		if p.Kind == Error {
			return true
		}
	}
	return false
}
