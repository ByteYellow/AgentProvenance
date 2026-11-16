package browserlink

import (
	"context"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

// RuntimeCustody is a caller-authorized mapping, not a captured Browser claim.
// The trusted caller must verify the Browser receipt and operator placement
// independently (for example with agentcontext.OwnedBrowserCapture), and bind
// the exact host/process lifetime to that placement. SourceRefs identify the
// retained Browser observations supporting that check. JSON from a transcript
// or Bundle must never be used to authorize this input.
//
// Multiple roles may belong to a context, and a process may serve many contexts.
// Neither fact attributes a process's individual effects to a Browser action.
type RuntimeCustody struct {
	RunID             string
	Scope             Scope
	Role              string
	HostID            string
	PID               int64
	ProcessInstanceID string
	SourceRefs        []string
}

func (*RuntimeCustody) UnmarshalJSON([]byte) error {
	return fmt.Errorf("runtime custody requires an independently authorized local mapping")
}

func (p *projector) runtime(ctx context.Context, in Input) error {
	type eventIdentity struct {
		event   telemetry.EventRecord
		process telemetry.RuntimeProcessNode
	}
	byProcess := map[string][]eventIdentity{}
	seenEvents := map[string]bool{}
	total := 0
	for _, event := range in.Events {
		if err := ctx.Err(); err != nil {
			return err
		}
		total += len(event.Payload)
		if total > MaxInputBytes {
			return fmt.Errorf("browser runtime input exceeds limit")
		}
		if event.ID == "" || event.RunID != in.RunID {
			continue
		}
		if seenEvents[event.ID] {
			return fmt.Errorf("duplicate browser runtime event identity")
		}
		seenEvents[event.ID] = true
		if event.Source != "agentprov_ebpf" {
			continue
		}
		var body map[string]any
		if err := decodeRecord([]byte(event.Payload), &body); err != nil {
			continue
		}
		layers := []map[string]any{body}
		for {
			nested, ok := body["payload"].(map[string]any)
			if !ok {
				nested, ok = body["raw"].(map[string]any)
			}
			if !ok {
				break
			}
			layers = append(layers, nested)
			body = nested
		}
		if _, valid := correlation.CaptureOrigin(layers, event.PID); !valid {
			continue
		}
		id := telemetry.ProcessGraphIdentity(event)
		if id.Version != telemetry.RuntimeProcessGraphVersion || id.Process.Basis != "kernel_process_instance" || id.Process.HostID == "" {
			continue
		}
		key := identity(id.Process.HostID, id.Process.InstanceID)
		byProcess[key] = append(byProcess[key], eventIdentity{event, id.Process})
	}
	scopes := map[string]*observation{}
	for _, o := range p.observations {
		if old := scopes[o.scopeID]; old == nil || o.ref < old.ref {
			scopes[o.scopeID] = o
		}
	}
	claims := map[string]string{}
	conflicts := map[string]bool{}
	for _, c := range in.Custody {
		key := identity(c.RunID, c.Scope, c.Role)
		process := identity(c.HostID, c.ProcessInstanceID, c.PID)
		if old, ok := claims[key]; ok && old != process {
			conflicts[key] = true
		}
		claims[key] = process
	}
	provided := map[string]bool{}
	attempts := 0
	for _, c := range in.Custody {
		if err := ctx.Err(); err != nil {
			return err
		}
		scopeID := "browser_scope/" + digest(c.RunID, c.Scope)
		o := scopes[scopeID]
		if o == nil || c.RunID != in.RunID {
			continue
		}
		provided[scopeID] = true
		issue := func(status, reason string) {
			p.Issues = append(p.Issues, Issue{NodeID: scopeID, Rule: RuntimeRule, Status: status, Reason: reason, SourceRefs: unique(c.SourceRefs)})
		}
		if conflicts[identity(c.RunID, c.Scope, c.Role)] {
			issue("ambiguous", "conflicting_runtime_custody")
			continue
		}
		if !c.Scope.complete() || c.HostID == "" || !validID(c.HostID) || c.Role == "" || !validID(c.Role) || correlation.CanonicalProcessInstance(c.ProcessInstanceID, c.PID) != c.ProcessInstanceID || c.ProcessInstanceID == "" {
			issue("unresolved", "incomplete_runtime_custody")
			continue
		}
		if len(c.SourceRefs) > 32 {
			return fmt.Errorf("browser runtime custody reference limit exceeded")
		}
		retained := len(c.SourceRefs) > 0
		for _, ref := range c.SourceRefs {
			witness := p.byRef[ref]
			if witness == nil || witness.scope != c.Scope {
				retained = false
			}
		}
		if !retained {
			issue("unresolved", "missing_runtime_custody_support")
			continue
		}
		events := byProcess[identity(c.HostID, c.ProcessInstanceID)]
		if len(events) == 0 {
			issue("unresolved", "missing_native_process_lifetime")
			continue
		}
		for _, matched := range events {
			if err := ctx.Err(); err != nil {
				return err
			}
			attempts++
			if attempts > MaxRecords*12 {
				return fmt.Errorf("browser runtime relation limit exceeded")
			}
			e, process := matched.event, matched.process
			refs := unique(append(append([]string{}, c.SourceRefs...), "runtime_event/"+e.ID))
			p.addRelation(Relation{From: scopeID, To: process.ID, Kind: "browser_scope_process", Rule: RuntimeRule, Basis: "runtime_identity", Status: "supported", Scope: c.Scope, SourceRefs: refs, EvidenceGrade: "verified_custody_and_kernel_identity", SourceEventID: e.ID})
			// This is process activity, deliberately not a request/socket or
			// download/file attribution. Existing runtime_event_file edges and
			// native connection/stream metadata retain the actual OS endpoints.
			p.addRelation(Relation{From: process.ID, To: "runtime_event/" + e.ID, Kind: "browser_process_activity", Rule: RuntimeRule, Basis: "runtime_identity", Status: "supported", Scope: c.Scope, SourceRefs: refs, EvidenceGrade: "kernel_observed", SourceEventID: e.ID})
		}
	}
	for scopeID, o := range scopes {
		if !provided[scopeID] {
			p.Issues = append(p.Issues, Issue{NodeID: scopeID, Rule: RuntimeRule, Status: "unresolved", Reason: "runtime_custody_not_supplied", SourceRefs: []string{o.ref}})
		}
	}
	return nil
}
