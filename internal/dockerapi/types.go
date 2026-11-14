package dockerapi

// Summary is one entry of GET /containers/json (running containers only).
type Summary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	Labels  map[string]string `json:"Labels"`
	State   string            `json:"State"`
	Ports   []Port            `json:"Ports"`
}

// Port is a container port; PublicPort is 0 when it is not published.
type Port struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

// Detail is GET /containers/{id}/json, the fields Tripcoil reads (the facts snapshot of Plan 3
// reads the HostConfig security fields).
type Detail struct {
	ID         string     `json:"Id"`
	Name       string     `json:"Name"`
	Image      string     `json:"Image"`
	State      State      `json:"State"`
	Config     Config     `json:"Config"`
	HostConfig HostConfig `json:"HostConfig"`
	Mounts     []Mount    `json:"Mounts"`
}

type State struct {
	Running bool `json:"Running"`
	Pid     int  `json:"Pid"`
}

type Config struct {
	User   string            `json:"User"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
}

type HostConfig struct {
	Privileged     bool     `json:"Privileged"`
	NetworkMode    string   `json:"NetworkMode"`
	CapAdd         []string `json:"CapAdd"`
	PidMode        string   `json:"PidMode"`
	ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
}

type Mount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}
