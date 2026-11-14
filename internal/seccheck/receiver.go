package seccheck

import (
	"context"
	"time"
)

// Record describes transport evidence independently from syscall outcome. An
// orderly EOF is still a disconnected stream, not proof of complete capture.
type Record struct {
	Kind            string       `json:"kind"`
	Reason          string       `json:"reason,omitempty"`
	Registration    Registration `json:"registration"`
	ConnectionID    string       `json:"connection_id"`
	Sequence        uint64       `json:"sequence"`
	ReceivedAt      time.Time    `json:"received_at"`
	PeerPID         int32        `json:"peer_pid"`
	ProtocolVersion uint32       `json:"protocol_version,omitempty"`
	Identity        Identity     `json:"identity"`
	DroppedDelta    *uint64      `json:"dropped_delta,omitempty"`
	// A decrease may be a wrap or reset. Report the boundary without inventing
	// a precise loss count. Each new connection has an independent counter.
	DropCounterDecreased bool          `json:"drop_counter_decreased,omitempty"`
	Packet               *Packet       `json:"-"`
	Capabilities         *Capabilities `json:"capabilities,omitempty"`
}

// Sink synchronously accepts one observation. Production consumers must durably
// accept it before returning nil. An error stops the receiver rather than losing
// an unreported record. Calls are serialized within each Receiver.
type Sink func(context.Context, Record) error

type Receiver struct {
	SocketPath       string
	Registration     Registration
	Sink             Sink
	HandshakeTimeout time.Duration
	// Ready runs after the private endpoint is listening, before accepting peers.
	Ready func() error
}
