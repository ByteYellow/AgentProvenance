package node

// The helper inherits stdout/stderr for workload output. FD 3 carries one
// versioned result so output, even arbitrary JSON, cannot forge an exit code.
type dockerRequest struct {
	Operation string                `json:"operation"`
	Create    *CreateSessionRequest `json:"create,omitempty"`
	Container string                `json:"container,omitempty"`
	Command   []string              `json:"command,omitempty"`
	Weight    int64                 `json:"weight,omitempty"`
}

type dockerReply struct {
	Version   int        `json:"version"`
	Container string     `json:"container,omitempty"`
	Exec      ExecResult `json:"exec"`
	Error     string     `json:"error,omitempty"`
}
