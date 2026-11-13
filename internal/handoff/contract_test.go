package handoff

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func fixtureRequest() Request {
	return Request{SchemaVersion: SchemaVersion,
		Source:     Source{ProducerID: "mac", Namespace: "trusted-router", RunID: "source-run", Harness: "codex", SessionID: "session", ToolCallID: "tool-1"},
		Target:     Target{ProducerID: "lab", InstanceID: "vm-1", Generation: "boot-generation-1"},
		DispatchID: "dispatch-1", OperationID: "operation-1", ValidUntil: time.Date(2026, 11, 14, 12, 0, 0, 123, time.UTC),
		Command: Command{Argv: []string{"python3", "report.py"}}}
}

func fixturePrincipal(r Request) Principal {
	return Principal{ID: "trusted-router", ProducerID: r.Source.ProducerID, Namespace: r.Source.Namespace, AllowedTargets: []Target{r.Target}}
}

func TestCanonicalRequestDefaultsAndBoundaries(t *testing.T) {
	r := fixtureRequest()
	canonical, raw, hash, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Command.CapturePreset != "detailed" || canonical.Command.SampleIntervalMS != 25 || canonical.Command.PostRootGraceMS != 250 {
		t.Fatalf("wrong defaults: %+v", canonical.Command)
	}
	if !strings.Contains(string(raw), `"argv":["python3","report.py"]`) {
		t.Fatalf("argv boundaries lost: %s", raw)
	}
	_, _, again, err := canonical.Canonical()
	if err != nil || again != hash {
		t.Fatalf("canonicalization is not idempotent: %s %s %v", hash, again, err)
	}
	r.ValidUntil = r.ValidUntil.In(time.FixedZone("offset", 8*3600))
	_, _, offsetHash, err := r.Canonical()
	if err != nil || offsetHash != hash {
		t.Fatalf("equivalent time changed digest: %s %v", offsetHash, err)
	}
	r.Command.Argv[1] = "another.py"
	if canonical.Command.Argv[1] != "report.py" {
		t.Fatal("canonical request shares caller-owned argv")
	}
	_, _, changed, _ := r.Canonical()
	if hash == changed {
		t.Fatal("changed command reused digest")
	}
	a, b := fixtureRequest(), fixtureRequest()
	a.Command.Argv = []string{"python3", "a b"}
	b.Command.Argv = []string{"python3", "a", "b"}
	_, _, ha, _ := a.Canonical()
	_, _, hb, _ := b.Canonical()
	if ha == hb {
		t.Fatal("argv was flattened before hashing")
	}
	if digest("a:b", "c") == digest("a", "b:c") {
		t.Fatal("identity separators collided")
	}
}

func TestInvalidRequests(t *testing.T) {
	tests := map[string]func(*Request){
		"version":        func(r *Request) { r.SchemaVersion = "unknown" },
		"missing source": func(r *Request) { r.Source.SessionID = "" },
		"missing target": func(r *Request) { r.Target.Generation = "" },
		"control ID":     func(r *Request) { r.OperationID = "bad\n" },
		"large ID":       func(r *Request) { r.DispatchID = strings.Repeat("x", 513) },
		"missing expiry": func(r *Request) { r.ValidUntil = time.Time{} },
		"empty command":  func(r *Request) { r.Command.Argv = nil },
		"null byte":      func(r *Request) { r.Command.Argv = []string{"python3", "a\x00b"} },
		"invalid utf8":   func(r *Request) { r.Command.Workdir = string([]byte{0xff}) },
		"oversized":      func(r *Request) { r.Command.Argv = []string{"python3", strings.Repeat("x", 1<<20)} },
		"sampling":       func(r *Request) { r.Command.SampleIntervalMS = -1 },
		"grace":          func(r *Request) { r.Command.PostRootGraceMS = 30001 },
		"capture":        func(r *Request) { r.Command.CapturePreset = "minimal" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := fixtureRequest()
			mutate(&r)
			if _, _, _, err := r.Canonical(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected invalid request, got %v", err)
			}
		})
	}
}

func TestPrincipalOwnsNamespaceAndTarget(t *testing.T) {
	r := fixtureRequest()
	p := fixturePrincipal(r)
	if err := p.Authorize(r.Source, r.Target); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Source, *Target, *Principal){
		func(s *Source, _ *Target, _ *Principal) { s.ProducerID = "someone-else" },
		func(s *Source, _ *Target, _ *Principal) { s.Namespace = "another-router" },
		func(_ *Source, target *Target, _ *Principal) { target.Generation = "clone" },
		func(_ *Source, _ *Target, p *Principal) { p.AllowedTargets = nil },
		func(_ *Source, _ *Target, p *Principal) { p.ID = "" },
	} {
		source, target, principal := r.Source, r.Target, fixturePrincipal(r)
		mutate(&source, &target, &principal)
		if !errors.Is(principal.Authorize(source, target), ErrForbidden) {
			t.Fatalf("identity override accepted: %+v %+v", source, target)
		}
	}
}

func TestStateDimensionsDoNotImplyEachOther(t *testing.T) {
	state := InitialState()
	state.Execution = Succeeded
	if state.Capture != NotReady || state.Delivery != Pending {
		t.Fatalf("execution success changed capture/delivery: %+v", state)
	}
	for _, pair := range [][2]ExecutionState{{Accepted, Starting}, {Starting, Unknown}, {Unknown, Running}, {Running, Failed}} {
		if !pair[0].CanTransition(pair[1]) {
			t.Fatalf("valid transition rejected: %v", pair)
		}
	}
	for _, pair := range [][2]ExecutionState{{Unknown, Accepted}, {Running, Accepted}, {Succeeded, Running}, {Accepted, Succeeded}} {
		if pair[0].CanTransition(pair[1]) {
			t.Fatalf("invalid transition accepted: %v", pair)
		}
	}
	if NotReady.CanTransition(Sealed) || Sealed.CanTransition(Collecting) || Pending.CanTransition(Acknowledged) || Acknowledged.CanTransition(Transferring) {
		t.Fatal("capture/delivery skipped required evidence stage")
	}
	if !Collecting.CanTransition(Draining) || !Draining.CanTransition(Incomplete) || !Transferring.CanTransition(Pending) {
		t.Fatal("capture drain or transport retry rejected")
	}
}
