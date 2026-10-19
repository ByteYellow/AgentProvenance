package correlation

// AppProcessMethod identifies derived app-to-runtime links, not kernel-proven
// agent identity. Keep its version in the stored edge ID for portable readers.
const (
	AppProcessMethod     = "agentprov.command_time_process/v3"
	AppProcessConfidence = 0.8 // Attribution tier, not a calibrated probability.
	AppProcessEdgePrefix = "agent-correlation-v3-"
)
