package runtimeadapter

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const maxCommandObservations = 16384
const maxCommandObservationBytes = 32 << 20

// SentryProcess is qualified by its CommandEvidence receiver lifecycle. The
// exact nanosecond birth is serialized as a string for JavaScript consumers.
type SentryProcess struct {
	PID     int32 `json:"pid"`
	StartNS int64 `json:"start_ns,string"`
}

type CommandEvidence struct {
	SchemaVersion  string                  `json:"schema_version"`
	DerivationRule string                  `json:"derivation_rule"`
	Receiver       seccheck.Target         `json:"receiver"`
	ConnectionID   string                  `json:"connection_id"`
	FirstSequence  uint64                  `json:"first_sequence"`
	LastSequence   uint64                  `json:"last_sequence"`
	RangeSHA256    string                  `json:"range_sha256"`
	Root           SentryProcess           `json:"root"`
	Processes      []SentryProcess         `json:"processes"`
	Events         []telemetry.EventRecord `json:"events"`
	RootExecRef    string                  `json:"root_exec_ref,omitempty"`
	RootExitRef    string                  `json:"root_exit_ref,omitempty"`
	RootWaitStatus *int32                  `json:"root_wait_status,omitempty"`
	BoundaryEvents []telemetry.EventRecord `json:"boundary_events,omitempty"`
	Watermark      *CommandWatermark       `json:"watermark,omitempty"`
}

type commandObservation struct {
	event    telemetry.EventRecord
	evidence telemetry.SecCheckEvidence
	point    telemetry.SecCheckPoint
	details  telemetry.SecCheckDetails
	group    SentryProcess
}

// DeriveSecCheckCommand computes ancestry from exact creating-group births and
// sentry/clone child births. PPIDs, host IDs and event timestamps are never used
// to infer ownership. The result is a bounded observation prefix, NOT a drain
// assertion: the runtime's task-set observation and durable barrier must follow.
func DeriveSecCheckCommand(receiver seccheck.Target, connection string, root SentryProcess,
	argv []string, events []telemetry.EventRecord) (CommandEvidence, error) {
	r := CommandEvidence{SchemaVersion: "agentprovenance.sentry_command_evidence/v1", DerivationRule: "sentry-clone-birth/v1",
		Receiver: receiver, ConnectionID: connection, Root: root, Events: []telemetry.EventRecord{}, Processes: []SentryProcess{}}
	if root.PID <= 0 || root.StartNS <= 0 || len(argv) == 0 || connection == "" || len(events) == 0 || len(events) > maxCommandObservations {
		return r, fmt.Errorf("command evidence needs a controlled root and bounded observations")
	}
	if err := receiver.Registration.Validate(); err != nil {
		return r, err
	}
	observations := make([]commandObservation, 0, len(events))
	clones := map[SentryProcess][]int{}
	rangeHash := sha256.New()
	bytes := 0
	seen := map[string]bool{}
	for i, event := range events {
		if event.ID == "" || seen[event.ID] {
			return r, fmt.Errorf("command interval has missing or repeated event references")
		}
		seen[event.ID] = true
		bytes += len(event.Payload)
		if bytes > maxCommandObservationBytes {
			return r, fmt.Errorf("command observations exceed byte budget")
		}
		e, err := telemetry.ReadSecCheckEvidence(event)
		if err != nil {
			return r, err
		}
		if event.RunID != receiver.RunID || e.Registration != receiver.Registration || e.ConnectionID != connection || e.RuntimeRelease != seccheck.RuntimeRelease {
			return r, fmt.Errorf("command observation crossed receiver lifecycle")
		}
		if i == 0 {
			r.FirstSequence = e.Sequence
		} else if e.Sequence <= r.LastSequence || e.Sequence-r.LastSequence != 1 {
			return r, fmt.Errorf("command observation sequence is not contiguous")
		}
		r.LastSequence = e.Sequence
		if e.Kind != "event" || e.Context == nil || len(e.IdentityGaps) != 0 || e.DroppedDelta == nil || *e.DroppedDelta != 0 || e.DropCounterDecreased {
			return r, fmt.Errorf("command interval contains transport loss or identity gaps")
		}
		p, err := telemetry.ReadSecCheckPoint(event)
		if err != nil {
			return r, err
		}
		d, err := telemetry.ReadSecCheckDetails(event)
		if err != nil {
			return r, err
		}
		group := SentryProcess{PID: e.Context.GroupID, StartNS: e.Context.GroupStartNS}
		if group.PID <= 0 || group.StartNS <= 0 {
			return r, fmt.Errorf("command observation lacks group birth")
		}
		observations = append(observations, commandObservation{event, e, p, d, group})
		if wire.MessageType(p.MessageType) == wire.MessageType_MESSAGE_SENTRY_CLONE {
			clones[group] = append(clones[group], i)
		}
		// JSON plus a newline gives an unambiguous ordered stream commitment.
		raw, _ := json.Marshal(event)
		rangeHash.Write(raw)
		rangeHash.Write([]byte{'\n'})
	}
	r.RangeSHA256 = fmt.Sprintf("%x", rangeHash.Sum(nil))
	owned := map[SentryProcess]bool{root: true}
	queue := []SentryProcess{root}
	for n := 0; n < len(queue); n++ {
		parent := queue[n]
		for _, index := range clones[parent] {
			d := observations[index].details
			if d.CreatedThreadID <= 0 || d.CreatedGroupID <= 0 || d.CreatedThreadStartNS <= 0 {
				return r, fmt.Errorf("owned clone lacks exact child identity")
			}
			if d.CloneFlags&0x10000 != 0 { // Linux CLONE_THREAD: same group, different thread birth.
				if d.CreatedGroupID != parent.PID {
					return r, fmt.Errorf("owned thread clone changed group")
				}
				continue
			}
			if d.CreatedThreadID != d.CreatedGroupID {
				return r, fmt.Errorf("new owned group has no leader birth")
			}
			child := SentryProcess{PID: d.CreatedGroupID, StartNS: d.CreatedThreadStartNS}
			if child == parent {
				return r, fmt.Errorf("owned clone reused its parent identity")
			}
			if !owned[child] {
				if len(owned) >= 4096 {
					return r, fmt.Errorf("command process budget exceeded")
				}
				owned[child] = true
				queue = append(queue, child)
			}
		}
	}
	r.Processes = queue
	slices.SortFunc(r.Processes, func(a, b SentryProcess) int {
		if a.PID < b.PID {
			return -1
		}
		if a.PID > b.PID {
			return 1
		}
		if a.StartNS < b.StartNS {
			return -1
		}
		if a.StartNS > b.StartNS {
			return 1
		}
		return 0
	})
	for _, observation := range observations {
		if !owned[observation.group] {
			continue
		}
		r.Events = append(r.Events, observation.event)
		if observation.group != root {
			continue
		}
		switch wire.MessageType(observation.point.MessageType) {
		case wire.MessageType_MESSAGE_SENTRY_EXEC:
			if r.RootExecRef == "" && slices.Equal(observation.details.Argv, argv) {
				r.RootExecRef = observation.event.ID
			}
		case wire.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT:
			if observation.details.WaitStatus == nil || r.RootExitRef != "" {
				return r, fmt.Errorf("conflicting or missing root group exit status")
			}
			r.RootExitRef, r.RootWaitStatus = observation.event.ID, observation.details.WaitStatus
		}
	}
	return r, nil
}
