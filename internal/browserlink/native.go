package browserlink

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
)

type projector struct {
	Projection
	observations []*observation
	byRef        map[string]*observation
	groups       map[string][]*observation
	conflicts    map[string]bool
	nodes        map[string]bool
	edges        map[string]bool
}

// Project recomputes relations from the retained evidence. Removing an explicit
// support record therefore removes its relations without a stale edge cache.
func Project(ctx context.Context, in Input) (Projection, error) {
	if in.RunID == "" {
		return Projection{}, fmt.Errorf("browser run is required")
	}
	if len(in.Records) > MaxRecords || len(in.Events) > MaxRecords || len(in.Custody) > MaxRecords {
		return Projection{}, fmt.Errorf("browser projection record limit exceeded")
	}
	p := projector{byRef: map[string]*observation{}, groups: map[string][]*observation{}, conflicts: map[string]bool{}, nodes: map[string]bool{}, edges: map[string]bool{}}
	seen := map[string][32]byte{}
	owners := map[string]string{}
	claim := func(key, owner string) {
		if old, ok := owners[key]; ok && old != owner {
			p.conflicts[key] = true
		}
		owners[key] = owner
	}
	total := 0
	for _, r := range in.Records {
		if err := ctx.Err(); err != nil {
			return Projection{}, err
		}
		total += len(r.Payload)
		if total > MaxInputBytes {
			return Projection{}, fmt.Errorf("browser projection byte limit exceeded")
		}
		hash := sha256.Sum256(r.Payload)
		if prior, ok := seen[r.Ref]; ok {
			if prior != hash {
				return Projection{}, fmt.Errorf("conflicting browser record reference")
			}
			continue
		}
		seen[r.Ref] = hash
		var e entry
		if err := decodeRecord(r.Payload, &e); err != nil {
			return Projection{}, fmt.Errorf("browser record %s: %w", r.Ref, err)
		}
		if e.Browser == nil || e.Source.Harness != "browser" || e.ExecutionScope != "current_execution" {
			continue
		}
		if e.RunID != in.RunID || r.Ref == "" {
			return Projection{}, fmt.Errorf("browser record run or reference mismatch")
		}
		if e.Source.Browser == nil || !e.Source.Browser.complete() || e.Browser.EventID == "" {
			p.Issues = append(p.Issues, Issue{NodeID: r.Ref, Rule: NativeRule, Status: "unresolved", Reason: "incomplete_browser_identity", SourceRefs: []string{r.Ref}})
			continue
		}
		o := &observation{ref: r.Ref, scope: *e.Source.Browser, entry: e, native: *e.Browser}
		for _, id := range []string{o.EventID, o.TargetID, o.TargetType, o.CDPSessionID, o.FrameID, o.LoaderID, o.RequestID, o.InitiatorRequestID, o.OperationID, o.Operation, o.DownloadID} {
			if !validID(id) {
				return Projection{}, fmt.Errorf("invalid or oversized browser native identifier")
			}
		}
		o.scopeID = "browser_scope/" + digest(in.RunID, o.scope)
		p.observations = append(p.observations, o)
		p.byRef[o.ref] = o
		p.addNode(Node{ID: o.scopeID, Kind: "browser_scope", Label: "Browser context " + o.scope.ContextID, Data: map[string]any{"scope": o.scope, "run_id": in.RunID, "association_level": "context_membership"}})
		p.addNode(Node{ID: o.ref, Kind: "browser_observation", Label: o.Kind, Data: map[string]any{"scope": o.scope, "source_id": e.Source.ID, "session_id": e.Source.SessionID, "browser": o.native}})
		p.link(o.scopeID, o.ref, "browser_scope_member", "explicit_reference", o, o.ref)
		if o.CDPSessionID != "" {
			claim(identity(o.scopeID, o.CDPSessionID), identity(o.TargetID, o.TargetType))
		}
		if o.OperationID != "" && o.Operation != "" && o.TargetID != "" {
			key := o.operationIdentity()
			claim("operation_target"+key, identity(o.TargetID, o.Operation))
			// Admission receipts can precede the CDP session binding.
			if o.CDPSessionID != "" {
				claim("operation_session"+key, o.CDPSessionID)
			}
			p.index("operation_owner", key, o)
		}
		p.index("event", identity(o.scopeID, o.EventID), o)
		if o.TargetID == "" || o.CDPSessionID == "" {
			continue
		}
		switch o.Kind {
		case "request":
			if o.RequestID != "" && o.RedirectIndex >= 0 {
				p.index("request", o.requestKey(), o)
				p.index("initiator", o.requestBase(), o)
			}
		case "request_finished", "request_failed":
			if o.RequestID != "" && o.RedirectIndex >= 0 {
				p.index("request_terminal", o.requestBase(), o)
			}
		case "action_start":
			if o.OperationID != "" && o.Operation != "" {
				p.index("operation", o.operationKey(), o)
			}
		case "frame":
			if o.FrameID != "" && o.LoaderID != "" {
				p.index("document", o.documentKey(), o)
			}
		case "download":
			if o.DownloadID != "" {
				p.index("download", o.downloadKey(), o)
			}
		}
	}
	for _, o := range p.observations {
		if err := ctx.Err(); err != nil {
			return Projection{}, err
		}
		if !p.usable(o) {
			continue
		}
		switch o.Kind {
		case "action_start":
			p.issue(o, "unresolved", "action_effect_requires_explicit_native_reference")
		case "action_end", "action_result", "screenshot":
			p.operation(o)
		case "response", "request_finished", "request_failed":
			p.match(o, "request", o.requestKey(), "browser_request_lifecycle", "explicit_reference", compatibleDocument)
		case "request":
			p.request(o)
		case "download_finished":
			p.match(o, "download", o.downloadKey(), "browser_download_lifecycle", "explicit_reference", compatibleDocument)
		case "download":
			if o.RequestID != "" && o.RedirectIndex >= 0 {
				p.match(o, "request", o.requestKey(), "browser_request_download", "explicit_reference", compatibleDocument)
			}
			p.document(o, "browser_document_download")
		}
	}
	if err := p.runtime(ctx, in); err != nil {
		return Projection{}, err
	}
	// An explicit anchor supersedes only the missing-anchor diagnostic for that
	// operation, never another unresolved or conflicting reference.
	anchored := map[string]bool{}
	for _, r := range p.Relations {
		if r.Kind == "browser_action_request" || r.Kind == "browser_action_document" || r.Kind == "browser_action_download" {
			anchored[r.From] = true
		}
	}
	p.Issues = slices.DeleteFunc(p.Issues, func(i Issue) bool {
		return i.Reason == "action_effect_requires_explicit_native_reference" && anchored[i.NodeID]
	})
	sort.Slice(p.Nodes, func(i, j int) bool { return p.Nodes[i].ID < p.Nodes[j].ID })
	sort.Slice(p.Relations, func(i, j int) bool { return p.Relations[i].ID < p.Relations[j].ID })
	sort.Slice(p.Issues, func(i, j int) bool { return identity(p.Issues[i]) < identity(p.Issues[j]) })
	return p.Projection, ctx.Err()
}

func (p *projector) index(kind, key string, o *observation) {
	p.groups[kind+key] = append(p.groups[kind+key], o)
}
func (o *observation) lane() string              { return identity(o.scopeID, o.CDPSessionID, o.TargetID) }
func (o *observation) requestBase() string       { return identity(o.lane(), o.RequestID) }
func (o *observation) requestKey() string        { return identity(o.requestBase(), o.RedirectIndex) }
func (o *observation) operationKey() string      { return identity(o.lane(), o.OperationID) }
func (o *observation) operationIdentity() string { return identity(o.scopeID, o.OperationID) }
func (o *observation) documentKey() string       { return identity(o.lane(), o.FrameID, o.LoaderID) }
func (o *observation) downloadKey() string       { return identity(o.lane(), o.DownloadID) }

func (p *projector) usable(o *observation) bool {
	key := o.operationIdentity()
	if o.OperationID != "" && (p.conflicts["operation_target"+key] || p.conflicts["operation_session"+key]) {
		var refs []string
		for _, owner := range p.groups["operation_owner"+key] {
			refs = append(refs, owner.ref)
			if len(refs) == 16 {
				break
			}
		}
		p.issue(o, "ambiguous", "conflicting_operation_owner", refs...)
		return false
	}
	if o.TargetID == "" || o.CDPSessionID == "" {
		p.issue(o, "unresolved", "missing_native_target_or_session")
		return false
	}
	if p.conflicts[identity(o.scopeID, o.CDPSessionID)] || len(p.groups["event"+identity(o.scopeID, o.EventID)]) != 1 {
		p.issue(o, "ambiguous", "conflicting_native_owner_or_event")
		return false
	}
	return true
}

func (p *projector) candidate(o *observation, kind, key string) *observation {
	candidates := p.groups[kind+key]
	if len(candidates) != 1 {
		status, reason := "unresolved", "missing_"+kind+"_reference"
		if len(candidates) > 1 {
			status, reason = "ambiguous", "multiple_"+kind+"_claims"
		}
		refs := []string{o.ref}
		for _, c := range candidates {
			refs = append(refs, c.ref)
			if len(refs) == 17 {
				break
			}
		}
		p.issue(o, status, reason, refs...)
		return nil
	}
	c := candidates[0]
	if !p.usable(c) {
		p.issue(o, "ambiguous", "conflicting_reference_owner", c.ref)
		return nil
	}
	return c
}

func (p *projector) match(o *observation, group, key, kind, basis string, compatible func(*observation, *observation) bool) *observation {
	c := p.candidate(o, group, key)
	if c == nil {
		return nil
	}
	if !compatible(c, o) {
		p.issue(o, "contradicted", "native_reference_identity_mismatch", c.ref)
		return nil
	}
	p.link(c.ref, o.ref, kind, basis, o, c.ref, o.ref)
	return c
}

func compatibleDocument(a, b *observation) bool {
	return (a.FrameID == "" || b.FrameID == "" || a.FrameID == b.FrameID) && (a.LoaderID == "" || b.LoaderID == "" || a.LoaderID == b.LoaderID)
}

func (p *projector) operation(o *observation) {
	if o.OperationID == "" || o.Operation == "" {
		p.issue(o, "unresolved", "missing_operation_reference")
		return
	}
	start := p.match(o, "operation", o.operationKey(), "browser_action_result", "explicit_reference", func(a, b *observation) bool { return a.Operation == b.Operation })
	if start == nil || o.Kind != "action_end" {
		return
	}
	if o.RequestID != "" && o.RedirectIndex >= 0 {
		request := p.candidate(o, "request", o.requestKey())
		if request != nil {
			if compatibleDocument(request, o) {
				p.link(start.ref, request.ref, "browser_action_request", "explicit_reference", o, start.ref, o.ref, request.ref)
			} else {
				p.issue(o, "contradicted", "action_request_identity_mismatch", request.ref)
			}
		}
	}
	if o.FrameID != "" && o.LoaderID != "" {
		frame := p.candidate(o, "document", o.documentKey())
		if frame != nil {
			p.link(start.ref, frame.ref, "browser_action_document", "explicit_reference", o, start.ref, o.ref, frame.ref)
		}
	}
	if o.DownloadID != "" {
		download := p.candidate(o, "download", o.downloadKey())
		if download != nil && compatibleDocument(download, o) {
			p.link(start.ref, download.ref, "browser_action_download", "explicit_reference", o, start.ref, o.ref, download.ref)
		}
	}
}

func (p *projector) request(o *observation) {
	if o.RequestID == "" || o.RedirectIndex < 0 {
		p.issue(o, "unresolved", "missing_request_identity")
		return
	}
	if len(p.groups["request"+o.requestKey()]) != 1 {
		p.issue(o, "ambiguous", "multiple_request_claims")
		return
	}
	if o.RedirectIndex > 0 {
		prior := *o
		prior.RedirectIndex--
		p.match(o, "request", prior.requestKey(), "browser_request_redirect", "explicit_reference", compatibleDocument)
	}
	if o.InitiatorRequestID != "" {
		if o.InitiatorRequestID == o.RequestID {
			p.issue(o, "contradicted", "self_initiator_reference")
		} else {
			p.initiator(o)
		}
	}
	p.document(o, "browser_document_request")
}

func (p *projector) initiator(o *observation) {
	parent := p.candidate(o, "initiator", identity(o.lane(), o.InitiatorRequestID))
	if parent == nil {
		return
	}
	if parent.RedirectIndex != 0 {
		p.issue(o, "ambiguous", "initiator_redirect_hop_unrecorded", parent.ref)
		return
	}
	// A request-ID-only initiator does not name a redirect hop. A retained
	// hop-zero terminal proves a completed non-redirect chain; uniqueness in a
	// selected subset alone does not. Removing this proof removes the edge.
	terminal := p.candidate(o, "request_terminal", parent.requestBase())
	if terminal == nil {
		return
	}
	if terminal.RedirectIndex != 0 {
		p.issue(o, "ambiguous", "initiator_redirect_hop_unrecorded", parent.ref, terminal.ref)
		return
	}
	if !compatibleDocument(parent, terminal) {
		p.issue(o, "contradicted", "initiator_terminal_identity_mismatch", parent.ref, terminal.ref)
		return
	}
	p.link(parent.ref, o.ref, "browser_request_initiator", "initiator_evidence", o, parent.ref, terminal.ref, o.ref)
}

func (p *projector) document(o *observation, kind string) {
	if o.FrameID == "" || o.LoaderID == "" {
		p.issue(o, "unresolved", "missing_document_loader_reference")
		return
	}
	p.match(o, "document", o.documentKey(), kind, "explicit_reference", compatibleDocument)
}

func (p *projector) addNode(n Node) {
	if !p.nodes[n.ID] {
		p.nodes[n.ID] = true
		p.Nodes = append(p.Nodes, n)
	}
}
func (p *projector) link(from, to, kind, basis string, o *observation, refs ...string) {
	r := Relation{From: from, To: to, Kind: kind, Rule: NativeRule, Basis: basis, Status: "supported", Scope: o.scope, SourceRefs: unique(refs), EvidenceGrade: "application_observed"}
	p.addRelation(r)
}
func (p *projector) addRelation(r Relation) {
	r.ID = "browser-link/" + digest(r)
	if !p.edges[r.ID] {
		p.edges[r.ID] = true
		p.Relations = append(p.Relations, r)
	}
}
func (p *projector) issue(o *observation, status, reason string, refs ...string) {
	p.Issues = append(p.Issues, Issue{NodeID: o.ref, Rule: NativeRule, Status: status, Reason: reason, SourceRefs: unique(append(refs, o.ref))})
}
func unique(values []string) []string {
	values = slices.Clone(values)
	sort.Strings(values)
	return slices.Compact(values)
}
func identity(parts ...any) string { raw, _ := json.Marshal(parts); return string(raw) }
func digest(parts ...any) string   { return fmt.Sprintf("%x", sha256.Sum256([]byte(identity(parts...)))) }
