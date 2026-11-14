// Package inventory finds what is running on the host and where it comes from (spec section 5).
package inventory

import (
	"time"

	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

// Inventory is inventory.json.
type Inventory struct {
	SchemaVersion string            `json:"schemaVersion"`
	Host          Host              `json:"host"`
	Items         []Item            `json:"items"`
	Origins       []Origin          `json:"origins"`
	Errors        []problem.Problem `json:"errors"`
	Warnings      []problem.Problem `json:"warnings"`
	Notices       []problem.Problem `json:"notices"`
}

// Status is the Inventory stage's status for run.json: "partial" when an error was recorded.
func (inv *Inventory) Status() string {
	if len(inv.Errors) > 0 {
		return "partial"
	}
	return "ok"
}

// Host describes the machine.
type Host struct {
	Hostname string `json:"hostname"`
	Distro   Distro `json:"distro"`
	Arch     string `json:"arch"`
	Init     string `json:"init"` // systemd, openrc or unknown
}

// Distro is the distribution from os-release, with the family Tripcoil treats it as.
type Distro struct {
	ID        string   `json:"id"`
	VersionID string   `json:"versionId,omitempty"`
	IDLike    []string `json:"idLike"` // never nil
	Family    string   `json:"family"`
}

// Item kinds.
const (
	KindKernel    = "kernel"
	KindProcess   = "process"
	KindContainer = "container"
)

// Item is one thing that runs.
type Item struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`

	// Kernel.
	Release         string   `json:"release,omitempty"`
	RunningVersion  string   `json:"runningVersion,omitempty"`
	UpstreamVersion string   `json:"upstreamVersion,omitempty"`
	RebootPending   *bool    `json:"rebootPending,omitempty"` // set on the kernel item only
	RebootReasons   []string `json:"rebootReasons,omitempty"`
	Modules         []string `json:"modules,omitempty"`

	// Host process.
	Exe           string    `json:"exe,omitempty"`
	AppDir        string    `json:"appDir,omitempty"`
	Units         []string  `json:"units,omitempty"`
	Processes     []Process `json:"processes,omitempty"`
	RestartNeeded []string  `json:"restartNeeded,omitempty"`

	// Docker container.
	ContainerID string   `json:"containerId,omitempty"`
	Image       string   `json:"image,omitempty"`
	ImageID     string   `json:"imageId,omitempty"`
	Compose     *Compose `json:"compose,omitempty"`
	Ports       []Port   `json:"ports,omitempty"`
	User        string   `json:"user,omitempty"`
	Privileged  bool     `json:"privileged,omitempty"`
	NetworkMode string   `json:"networkMode,omitempty"`
	Mounts      []Mount  `json:"mounts,omitempty"`
	PIDs        []int    `json:"pids,omitempty"`

	// Notes are coverage-gap codes about the item, such as APPDIR_NOT_FOUND or IMAGE_ONLY.
	Notes   []string `json:"notes,omitempty"`
	Origins []string `json:"origins"`
}

// Process is one process of a host process item.
type Process struct {
	PID     int       `json:"pid"`
	User    string    `json:"user,omitempty"`
	Cmdline []string  `json:"cmdline"` // secrets redacted
	Started time.Time `json:"started,omitzero"`
}

// Compose names the Docker Compose project and service a container belongs to.
type Compose struct {
	Project string `json:"project,omitempty"`
	Service string `json:"service,omitempty"`
	// WorkingDir is the directory `docker compose` ran in.
	WorkingDir string `json:"workingDir,omitempty"`
}

// Port is a published container port.
type Port struct {
	IP            string `json:"ip,omitempty"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
}

// Mount is a container mount.
type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	ReadWrite   bool   `json:"readWrite"`
}

// Origin kinds.
const (
	OriginPackage        = "package"
	OriginBinary         = "binary"
	OriginAppDir         = "appdir"
	OriginImage          = "image"
	OriginKernelUpstream = "kernel-upstream"
	OriginUnresolved     = "unresolved"
)

// Origin is where running software comes from; the Audit scans origins.
type Origin struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`

	// Package.
	Name             string `json:"name,omitempty"`
	Version          string `json:"version,omitempty"`
	Epoch            string `json:"epoch,omitempty"`
	Arch             string `json:"arch,omitempty"`
	Type             string `json:"type,omitempty"`
	RunningOlderCopy bool   `json:"runningOlderCopy,omitempty"`

	// Binary: SHA256, every path it was seen at, and the cached copy of a running file that was
	// replaced on disk. Unresolved: the path concerned.
	SHA256 string   `json:"sha256,omitempty"`
	Paths  []string `json:"paths,omitempty"`
	Copy   string   `json:"copy,omitempty"`

	// App directory (or jar).
	Path string `json:"path,omitempty"`
	Jar  bool   `json:"jar,omitempty"`

	// Image.
	ImageID string `json:"imageId,omitempty"`
	Ref     string `json:"ref,omitempty"`

	// Kernel matched by upstream version.
	UpstreamVersion string `json:"upstreamVersion,omitempty"`

	// Unresolved.
	Reason string `json:"reason,omitempty"`
}

func packageOrigin(d Distro, p pkgtool.Package) Origin {
	return Origin{ID: PackageOriginID(d, p), Kind: OriginPackage, Name: p.Name, Version: p.Version, Epoch: p.Epoch, Arch: p.Arch, Type: p.Type}
}
