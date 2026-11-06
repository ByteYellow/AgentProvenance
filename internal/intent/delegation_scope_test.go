package intent

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestDiffUnboundPeerMessagesRetainCandidates(t *testing.T) {
	contracts := []IntentContract{
		{ID: "contract/msg-a", Kind: ContractPeerMessage, ScopeAgent: "bob", Operation: "install", Target: "install A", Source: "message-a", Profile: profileFor(profiles(), "install"), Confidence: .5},
		{ID: "contract/msg-b", Kind: ContractPeerMessage, ScopeAgent: "bob", Operation: "install", Target: "install B", Source: "message-b", Profile: profileFor(profiles(), "install"), Confidence: .5},
	}
	effects := []RuntimeEffect{{Kind: EffectSecretRead, AgentID: "bob", ToolCallID: "install-b", EventID: "secret", Confidence: 1}}
	before := append([]RuntimeEffect(nil), effects...)
	for _, cs := range [][]IntentContract{contracts, {contracts[1], contracts[0]}} {
		diffs := Diff(cs, effects)
		if len(diffs) != 1 || diffs[0].Status != "intent_association_gap" {
			t.Fatalf("one unresolved association expected, got %+v", diffs)
		}
		d := diffs[0]
		if d.Finding != "" || d.Confidence != 0 || !reflect.DeepEqual(d.EventIDs, []string{"secret"}) || d.ToolCallID != "install-b" {
			t.Fatalf("candidate gained a violation claim or lost event scope: %+v", d)
		}
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var view struct {
			Association struct {
				Status     string `json:"status"`
				Candidates []struct {
					ContractID string `json:"contract_id"`
					Source     string `json:"source"`
				} `json:"candidates"`
			} `json:"association"`
		}
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatal(err)
		}
		if view.Association.Status != "ambiguous" || len(view.Association.Candidates) != 2 || view.Association.Candidates[0].ContractID != "contract/msg-a" || view.Association.Candidates[0].Source != "message-a" || view.Association.Candidates[1].ContractID != "contract/msg-b" {
			t.Fatalf("candidate identities/references missing: %s", raw)
		}
	}
	if !reflect.DeepEqual(before, effects) {
		t.Fatal("association analysis changed runtime evidence")
	}
}

func TestPeerCandidatesUseCaptureOrderNotInputOrder(t *testing.T) {
	const at = "2026-11-06T00:00:02Z"
	cs := []IntentContract{}
	for i, stamp := range []string{"2026-11-06T00:00:01Z", at, "2026-11-06T00:00:03Z", ""} {
		cs = append(cs, IntentContract{ID: fmt.Sprint("contract/", i), Kind: ContractPeerMessage, ScopeAgent: "bob", ObservedAt: stamp, Profile: profileFor(profiles(), "install")})
	}
	es := []RuntimeEffect{{Kind: EffectSecretRead, AgentID: "bob", EventID: "secret", ObservedAt: at, Confidence: 1}}
	for i := 0; i < 2; i++ {
		ds := Diff(cs, es)
		if len(ds) != 1 || len(ds[0].Association.Candidates) != 3 {
			t.Fatalf("capture ordering: %+v", ds)
		}
		var ids []string
		for _, c := range ds[0].Association.Candidates {
			ids = append(ids, c.ContractID)
		}
		if !reflect.DeepEqual(ids, []string{"contract/0", "contract/1", "contract/3"}) {
			t.Fatalf("late/same-time/unknown candidates: %v", ids)
		}
		slices.Reverse(cs)
	}
}

func TestExplicitPoliciesPreserveMultipleApplicableConstraints(t *testing.T) {
	c := IntentContract{Kind: ContractPeerMessage, ScopeAgent: "bob", ScopeKind: "agent_policy", ScopeStart: "2026-11-06T00:00:00Z", ScopeEnd: "2026-11-06T00:01:00Z", EvidenceRefs: []string{"policy-source"}, Profile: profileFor(profiles(), "install"), Confidence: .5}
	a, b := c, c
	a.ID, b.ID = "contract/policy-a", "contract/policy-b"
	e := RuntimeEffect{Kind: EffectSecretRead, AgentID: "bob", ToolCallID: "work", EventID: "secret", ObservedAt: "2026-11-06T00:00:20Z", Confidence: 1}
	ds := Diff([]IntentContract{a, b}, []RuntimeEffect{e})
	if len(ds) != 2 {
		t.Fatalf("multiple valid policies lost: %+v", ds)
	}
	for _, d := range ds {
		if d.Status != StatusMismatch || d.Association.Status != "policy_scope" || !reflect.DeepEqual(d.EventIDs, []string{"secret"}) {
			t.Fatalf("policy scope: %+v", d)
		}
	}
	for _, change := range []func(*IntentContract, *RuntimeEffect){
		func(c *IntentContract, e *RuntimeEffect) { c.EvidenceRefs = nil },
		func(c *IntentContract, e *RuntimeEffect) { c.ScopeStart = "" },
		func(c *IntentContract, e *RuntimeEffect) { e.ObservedAt = "" },
		func(c *IntentContract, e *RuntimeEffect) { e.ObservedAt = c.ScopeEnd },
		func(c *IntentContract, e *RuntimeEffect) { e.AgentID = "alice" },
		func(c *IntentContract, e *RuntimeEffect) { c.ScopeKind = "" },
	} {
		x, y := a, e
		change(&x, &y)
		for _, d := range Diff([]IntentContract{x}, []RuntimeEffect{y}) {
			if d.Status == StatusMismatch {
				t.Fatalf("unsupported policy applied: %+v", d)
			}
		}
	}
}

func TestExplicitPeerBindingRespectsCaptureOrder(t *testing.T) {
	c := IntentContract{ID: "contract/bound", Kind: ContractPeerMessage, ScopeAgent: "bob", ToolCallID: "work", ObservedAt: "2026-11-06T00:00:02Z", Profile: profileFor(profiles(), "install"), Confidence: .5}
	e := RuntimeEffect{Kind: EffectSecretRead, AgentID: "bob", ToolCallID: "work", EventID: "secret", ObservedAt: "2026-11-06T00:00:01Z", Confidence: 1}
	ds := Diff([]IntentContract{c}, []RuntimeEffect{e})
	if len(ds) != 1 || ds[0].Status != StatusCoverageGap {
		t.Fatalf("later instruction applied retroactively: %+v", ds)
	}
	e.ObservedAt = "2026-11-06T00:00:03Z"
	ds = Diff([]IntentContract{c}, []RuntimeEffect{e})
	if len(ds) != 1 || ds[0].Status != StatusMismatch || ds[0].Association.Status != "bound" {
		t.Fatalf("valid explicit binding lost: %+v", ds)
	}
}

func TestExecutedAssociationConfidenceKeepsRuntimeGrade(t *testing.T) {
	c := IntentContract{ID: "contract/tool", Kind: ContractToolCall, ToolCallID: "work", Profile: Profile{Declared: []EffectKind{EffectProcessExec}}, Confidence: .5}
	e := RuntimeEffect{Kind: EffectProcessExec, ToolCallID: "work", EventID: "exec", Confidence: .25}
	ds := Diff([]IntentContract{c}, []RuntimeEffect{e})
	if len(ds) != 1 || ds[0].Status != StatusExecuted || ds[0].Confidence != .25 {
		t.Fatalf("positive relation overstated its runtime support: %+v", ds)
	}
}

func putPeerContractFixture(t *testing.T, db *sql.DB, source, at string, scope map[string]any) string {
	t.Helper()
	payload := map[string]any{"body": "install the same dependency"}
	if scope != nil {
		payload["intent_scope"] = scope
	}
	obj, err := (provenance.ObjectStore{DB: db, Paths: store.Paths{Root: t.TempDir()}}).PutExternalObject(provenance.ExternalObjectInput{RunID: "run", Type: "artifact", SourceID: "agent_message/" + source, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,created_at) VALUES (?,'run',?,'agent/a','agent_message',?)`, source, obj.Hash, at); err != nil {
		t.Fatal(err)
	}
	return obj.Hash
}

func TestMessageContractsKeepIdentitiesCandidatesAndBindings(t *testing.T) {
	db := attributionStore(t, false)
	refs := []string{
		putPeerContractFixture(t, db, "one", "2026-09-28T00:00:00Z", nil),
		putPeerContractFixture(t, db, "two", "2026-09-28T00:00:00Z", nil),
	}
	cs, err := ExtractContracts(db, "run", DefaultProfiles())
	if err != nil {
		t.Fatal(err)
	}
	var original []string
	for _, c := range cs {
		if c.Kind == ContractPeerMessage {
			original = append(original, c.ID)
			if !slices.Contains(refs, c.Source) || !reflect.DeepEqual(c.EvidenceRefs, []string{c.Source}) {
				t.Fatalf("lost source reference: %+v", c)
			}
		}
	}
	if len(original) != 2 || original[0] == original[1] {
		t.Fatalf("identical bodies merged: %v", original)
	}
	for i := 0; i < 2; i++ {
		r, err := Materialize(db, "run")
		if err != nil {
			t.Fatal(err)
		}
		if r.AssociationGaps != 1 || r.Mismatches != 1 || r.MismatchEvents != 1 {
			t.Fatalf("candidate and event counts: %+v", r)
		}
		var raw string
		if err := db.QueryRow(`SELECT association FROM intent_diffs WHERE run_id='run' AND status=?`, StatusAssociationGap).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var a IntentAssociation
		if err := json.Unmarshal([]byte(raw), &a); err != nil {
			t.Fatal(err)
		}
		if a.Status != "ambiguous" || len(a.Candidates) != 2 || !slices.Contains(a.EvidenceRefs, "runtime_event/secret") {
			t.Fatalf("stored association: %+v", a)
		}
		graph, err := provenance.BuildGraphLens(db, provenance.GraphLensOptions{RunID: "run", Lens: "intent", Detail: "raw"})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, n := range graph.Nodes {
			if n.Subtype == StatusAssociationGap {
				found = n.Data["association"].(map[string]any)["status"] == "ambiguous"
			}
		}
		if !found {
			t.Fatal("graph omitted candidate state")
		}
		var payload string
		if err := db.QueryRow(`SELECT payload FROM signals WHERE run_id='run' AND signal_type=?`, StatusAssociationGap).Scan(&payload); err != nil || payload != raw {
			t.Fatalf("signal association diverged: %s %s %v", payload, raw, err)
		}
	}
	bound := putPeerContractFixture(t, db, "bound", "2026-09-28T00:00:00Z", map[string]any{"kind": "tool_call", "agent_id": "a", "tool_call_id": "a"})
	invalid := putPeerContractFixture(t, db, "invalid", "2026-09-28T00:00:00Z", map[string]any{"kind": "tool_call", "agent_id": "other", "tool_call_id": "a"})
	cs, err = ExtractContracts(db, "run", DefaultProfiles())
	if err != nil {
		t.Fatal(err)
	}
	var oldIDs []string
	for _, c := range cs {
		if c.Source == bound && c.ToolCallID != "a" {
			t.Fatalf("recipient binding lost: %+v", c)
		}
		if c.Source == invalid && c.ToolCallID != "" {
			t.Fatalf("cross-agent binding accepted: %+v", c)
		}
		if slices.Contains(refs, c.Source) {
			oldIDs = append(oldIDs, c.ID)
		}
	}
	if !reflect.DeepEqual(oldIDs, original) {
		t.Fatalf("late import renumbered old messages: %v -> %v", original, oldIDs)
	}
}

func TestDiffSingleUnboundPeerIsStillCandidate(t *testing.T) {
	c := IntentContract{ID: "contract/msg", Kind: ContractPeerMessage, ScopeAgent: "bob", Operation: "install", Profile: profileFor(profiles(), "install"), Confidence: .5}
	e := RuntimeEffect{Kind: EffectSecretRead, AgentID: "bob", ToolCallID: "install", EventID: "secret", Confidence: 1}
	diffs := Diff([]IntentContract{c}, []RuntimeEffect{e})
	if len(diffs) != 1 || diffs[0].Status != "intent_association_gap" {
		t.Fatalf("one candidate was promoted to a fact: %+v", diffs)
	}
}

func TestDiffRefusalDoesNotCoverOtherTool(t *testing.T) {
	c := IntentContract{ID: "contract/refusal", Kind: ContractRefusal, ScopeAgent: "bob", ToolCallID: "refusal", Negative: true, Confidence: .5}
	e := RuntimeEffect{Kind: EffectSecretRead, AgentID: "bob", ToolCallID: "independent", EventID: "secret", Confidence: 1}
	diffs := Diff([]IntentContract{c}, []RuntimeEffect{e})
	if len(diffs) != 1 || diffs[0].Status != StatusCoverageGap || !reflect.DeepEqual(diffs[0].EventIDs, []string{"secret"}) {
		t.Fatalf("refusal widened to all agent activity: %+v", diffs)
	}
}

func TestDiffExplicitPeerBindingDoesNotUseOtherCalls(t *testing.T) {
	cs := []IntentContract{
		{ID: "contract/a", Kind: ContractPeerMessage, ScopeAgent: "bob", ToolCallID: "install-a", Operation: "install", Profile: profileFor(profiles(), "install"), Confidence: .5},
		{ID: "contract/b", Kind: ContractPeerMessage, ScopeAgent: "bob", ToolCallID: "install-b", Operation: "install", Profile: profileFor(profiles(), "install"), Confidence: .5},
	}
	es := []RuntimeEffect{{Kind: EffectSecretRead, AgentID: "bob", ToolCallID: "install-b", EventID: "secret", Confidence: 1}}
	diffs := Diff(cs, es)
	if len(diffs) != 1 || diffs[0].Finding != FindingPeerMessageMismatch || diffs[0].ToolCallID != "install-b" {
		t.Fatalf("explicit peer scope ignored: %+v", diffs)
	}
}
