package capturemanifest

const ObservationRuleVersion = "agentprov.capture_observation/v1"

// Observation describes the layer that produced evidence, separately from the
// receiver placement. Scope references are qualified by Record.Identity.
type Observation struct {
	RuleVersion  string   `json:"rule_version"`
	Layer        string   `json:"layer"`
	LayerBasis   string   `json:"layer_basis"`
	ScopeKind    string   `json:"scope_kind"`
	ScopeRef     string   `json:"scope_ref,omitempty"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// A configured state sampler does not identify the role of a sampled process.
// Policy decisions carry their own task identity in access-control evidence.
type PolicySubject struct {
	Layer string `json:"layer"`
	Role  string `json:"role"`
	Basis string `json:"basis"`
}

func observation(layer, basis, scope, ref, evidence string) Observation {
	return Observation{RuleVersion: ObservationRuleVersion, Layer: layer, LayerBasis: basis,
		ScopeKind: scope, ScopeRef: ref, EvidenceRefs: []string{evidence}}
}

func kernelObservation(identity map[string]string, ref string) Observation {
	layer, basis := "unknown", "kernel_topology_not_recorded"
	switch identity["placement"] {
	case "host_kernel", "guest_kernel":
		layer, basis = identity["placement"], identity["placement_basis"]
		if basis == "" {
			basis = "recorded_producer_placement"
		}
	}
	return observation(layer, basis, "collector", identity["collector_id"], ref)
}

func (r *Record) projectObservation() {
	o := observation("unknown", "not_recorded", "unknown", "", r.EvidenceRef)
	switch r.Source {
	case "agentprov_sensor":
		// A top-level producer describes one boundary only. Each snapshot must
		// retain its own boot, collector, version and placement after recovery.
		for i := range r.Snapshots {
			s := &r.Snapshots[i]
			s.Observation = kernelObservation(s.Identity, r.EvidenceRef)
			for j := range s.Features {
				f := &s.Features[j]
				if f.Category == "access_control" {
					f.PolicySubject = &PolicySubject{Layer: s.Observation.Layer, Role: "unknown", Basis: "state_collection_configuration"}
				}
			}
			if i == 0 {
				o = s.Observation
			} else {
				if o.Layer != s.Observation.Layer {
					o.Layer, o.LayerBasis = "mixed", "recorded_boundaries"
				} else if o.LayerBasis != s.Observation.LayerBasis {
					o.LayerBasis = "recorded_boundaries"
				}
				if o.ScopeRef != s.Observation.ScopeRef {
					o.ScopeKind, o.ScopeRef = "multiple_collectors", ""
				}
			}
		}
	case "gvisor_seccheck":
		o = observation("sentry", "saved_seccheck_protocol", "sentry_connection", r.Identity["connection_id"], r.EvidenceRef)
	case "agent_context":
		o = observation("application", "saved_context_source", r.IdentityDomain, r.Identity["source_id"], r.EvidenceRef)
	case "record":
		o = observation("application", "recorder_method", "execution_attempt", r.Identity["attempt_id"], r.EvidenceRef)
	case "execution_capture":
		o = observation("unknown", "capture_not_recorded", "execution_attempt", r.Identity["attempt_id"], r.EvidenceRef)
	case "runtime_execution":
		o = observation("unknown", "capture_not_recorded", "execution_attempt", r.Identity["attempt_id"], r.EvidenceRef)
		for i, snapshot := range r.Snapshots {
			if i == 0 {
				o = snapshot.Observation
			} else if snapshot.Observation.ScopeRef != o.ScopeRef {
				o.ScopeKind, o.ScopeRef = "multiple_sentry_connections", ""
			}
		}
	case "context_retention", "launch_settings":
		o = observation("unknown", "configuration_only", "run_configuration", "", r.EvidenceRef)
	}
	for i := range r.Snapshots {
		if r.Snapshots[i].Observation.RuleVersion == "" {
			r.Snapshots[i].Observation = o
		}
	}
	r.Observation = o
}
