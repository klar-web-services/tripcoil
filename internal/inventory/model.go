package inventory

import (
	"time"

	"github.com/klar-web-services/tripcoil/internal/pkgtool"
	"github.com/klar-web-services/tripcoil/internal/problem"
)

type Inventory struct {
	SchemaVersion string            `json:"schemaVersion"`
	Host          Host              `json:"host"`
	Items         []Item            `json:"items"`
	Origins       []Origin          `json:"origins"`
	Errors        []problem.Problem `json:"errors"`
	Warnings      []problem.Problem `json:"warnings"`
	Notices       []problem.Problem `json:"notices"`
}

func (inv *Inventory) Status() string {
	if len(inv.Errors) > 0 {
		return "partial"
	}
	return "ok"
}

type Host struct {
	Hostname string `json:"hostname"`
	Distro   Distro `json:"distro"`
	Arch     string `json:"arch"`
	Init     string `json:"init"`
}

type Distro struct {
	ID        string   `json:"id"`
	VersionID string   `json:"versionId,omitempty"`
	IDLike    []string `json:"idLike"`
	Family    string   `json:"family"`
}

const (
	KindKernel    = "kernel"
	KindProcess   = "process"
	KindContainer = "container"
)

type Item struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`

	Release         string   `json:"release,omitempty"`
	RunningVersion  string   `json:"runningVersion,omitempty"`
	UpstreamVersion string   `json:"upstreamVersion,omitempty"`
	RebootPending   *bool    `json:"rebootPending,omitempty"`
	RebootReasons   []string `json:"rebootReasons,omitempty"`
	Modules         []string `json:"modules,omitempty"`

	Exe           string    `json:"exe,omitempty"`
	AppDir        string    `json:"appDir,omitempty"`
	Units         []string  `json:"units,omitempty"`
	Processes     []Process `json:"processes,omitempty"`
	RestartNeeded []string  `json:"restartNeeded,omitempty"`

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

	Notes   []string `json:"notes,omitempty"`
	Origins []string `json:"origins"`
}

type Process struct {
	PID     int       `json:"pid"`
	User    string    `json:"user,omitempty"`
	Cmdline []string  `json:"cmdline"`
	Started time.Time `json:"started,omitzero"`
}

type Compose struct {
	Project     string   `json:"project,omitempty"`
	Service     string   `json:"service,omitempty"`
	WorkingDir  string   `json:"workingDir,omitempty"`
	ConfigFiles []string `json:"configFiles,omitempty"`
}

type Port struct {
	IP            string `json:"ip,omitempty"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
}

type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	ReadWrite   bool   `json:"readWrite"`
}

const (
	OriginPackage        = "package"
	OriginBinary         = "binary"
	OriginAppDir         = "appdir"
	OriginImage          = "image"
	OriginKernelUpstream = "kernel-upstream"
	OriginUnresolved     = "unresolved"
)

type Origin struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`

	Name             string `json:"name,omitempty"`
	Version          string `json:"version,omitempty"`
	Epoch            string `json:"epoch,omitempty"`
	Arch             string `json:"arch,omitempty"`
	Type             string `json:"type,omitempty"`
	RunningOlderCopy bool   `json:"runningOlderCopy,omitempty"`

	SHA256 string   `json:"sha256,omitempty"`
	Paths  []string `json:"paths,omitempty"`
	Copy   string   `json:"copy,omitempty"`

	Path string `json:"path,omitempty"`
	Jar  bool   `json:"jar,omitempty"`

	ImageID string `json:"imageId,omitempty"`
	Ref     string `json:"ref,omitempty"`

	UpstreamVersion string `json:"upstreamVersion,omitempty"`

	Reason string `json:"reason,omitempty"`
}

func packageOrigin(d Distro, p pkgtool.Package) Origin {
	return Origin{ID: PackageOriginID(d, p), Kind: OriginPackage, Name: p.Name, Version: p.Version, Epoch: p.Epoch, Arch: p.Arch, Type: p.Type}
}
