package agentcontext

// ToolNodeID namespaces a native call identity by run and actor. Transcript and
// hook channels can describe the same invocation, while separate runs cannot
// overwrite each other's graph nodes when a harness reuses a call ID.
func ToolNodeID(e Entry) string {
	return "context-tool-" + digest([]string{e.RunID, e.Source.Harness, e.Source.SessionID, e.AgentID, e.ToolCallID})
}
