// Package demo contains the signed, offline examples shipped with the CLI.
package demo

import "embed"

// Files preserves the original bundles, attestations and public keys unchanged.
// Evaluator source and capture scripts ship in the release archive, not the CLI.
//
//go:embed */*.json.gz */*.dsse.json */*.pub */README.md */README.zh-CN.md */*.png jev-judge/validation-*.json
var Files embed.FS

type Entry struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Directory    string `json:"directory"`
	Run          string `json:"run,omitempty"`
	Bundle       string `json:"-"`
	Lens         string `json:"lens,omitempty"`
	Key          string `json:"-"`
	Requirements string `json:"requirements"`
}

// Catalog includes every demo directory, with both historical Grok captures
// separate because they have different runs and signing keys.
func Catalog() []Entry {
	return []Entry{
		{"snake-supply-chain", "One agent: supply chain", "Follow a poisoned install from tool call to file, network and artifact evidence.", "snake-supply-chain", "run-snake-supervised", "run-snake-supervised", "agent-intent", "attestation.pub", "Offline signed replay; no account or VM required."},
		{"multiagent-provenance", "An agent team", "Follow delegation, peer influence, a refusal and a later install attempt.", "multiagent-provenance", "run-double-attempt", "run-double-attempt", "orchestration", "attestation.pub", "Offline signed replay; shared-process attribution includes inference."},
		{"k8s-cross-pod-a2a", "Across Kubernetes Pods", "Inspect live cross-Pod network and runtime evidence alongside replayed application hooks.", "k8s-cross-pod-a2a", "a2a-demo", "run-a2a-demo", "substrate", "attestation.pub", "Offline signed replay; Kubernetes is only needed to recapture."},
		{"k8s-substrate", "Kubernetes placement", "Inspect workload placement and container identity in a captured execution.", "k8s-substrate", "claude-demo", "run-claude-demo", "substrate", "attestation.pub", "Offline signed replay; Kubernetes is only needed to recapture."},
		{"grok-codebase-exfil", "Grok: historical investigation", "Inspect a dated outbound-data investigation and its documented evidence limits.", "grok-codebase-exfil", "run-grok-exfil", "run-grok-exfil", "network-egress", "attestation.pub", "Offline signed replay; not a claim about current vendor behavior."},
		{"grok-3routes", "Grok: three outbound routes", "Distinguish model requests, vendor telemetry and third-party analytics in a dated capture.", "grok-codebase-exfil", "run-grok-3routes", "run-grok-3routes", "network-egress", "run-grok-3routes.attestation.pub", "Offline signed replay; not a claim about current vendor behavior."},
		{"llm-judge", "LLM as security analyst", "An external evaluator consumes evidence and returns referenced signals; its own requests can be audited.", "llm-judge", "", "", "", "", "Optional Python 3 example in demo/llm-judge in the archive. Keyless fixture available; live judging requires a model endpoint and credentials."},
		{"jev-judge", "Jev reference integration", "Compare typed decisions and manually review them in the separate evaluator workbench.", "jev-judge", "", "", "", "", "Optional Python 3.9+ example in demo/jev-judge in the archive. Live evaluation requires a key and explicit raw-evidence consent; completed studies reopen offline."},
	}
}
