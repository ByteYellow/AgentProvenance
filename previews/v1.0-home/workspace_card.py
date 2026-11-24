"""Select the three public demo operations by identity, not by timestamp or file name."""
import json
from replay_card_source import catalog, context_body, shard


RUN = "run-w01-445a3a164ae14723b82f90634cff96f5"
CALLS = ("workspace-tool-45d80d290577", "workspace-tool-8eed32d09e28", "workspace-tool-c4c447186a48")


def summarize(entry, result):
    call = entry["tool_call_id"]
    if result.get("schema") != "agentprovenance.workspace_tool_result/v1" or result.get("tool_call_id") != call or result.get("run_id") != RUN:
        raise ValueError(f"Workspace result identity mismatch for {call}")
    row = {"call": call, "entry": entry["id"], "tool": entry["tool_name"]}
    if result["ok"] is False:
        # A rejected result may also carry a view of a *previous* successful operation.
        return dict(row, error=result["error"]["code"], next=result["error"].get("next_action"))
    receipt = result["view"]["last_receipt"]
    if not result.get("operation_ref") or receipt["ref"] != result["operation_ref"] or receipt["tool_call_id"] != call:
        raise ValueError(f"Workspace receipt does not belong to {call}")
    changes = receipt["changes"]
    if len(changes) != 1:
        raise ValueError(f"Expected one referenced file change for the featured operation {call}")
    change = changes[0]
    return dict(row, before=receipt["input_revision"], after=receipt["output_revision"],
                path=change["path"], kind=change["kind"], outcome=receipt["outcome"],
                digest=change["after"]["Hash"], size=change["after"]["SizeBytes"])


def workspace_card(root):
    ctx = shard(root, catalog(root)["runs"][RUN]["context"])
    latest = set(ctx["latest"])
    rows = []
    for call in CALLS:
        matches = [e for e in ctx["entries"] if e["run_id"] == RUN and e["kind"] == "tool_result" and e["id"] in latest and e.get("tool_call_id") == call]
        if len(matches) != 1 or matches[0]["content"]["state"] != "stored":
            raise ValueError(f"Expected one retained tool result for {call}")
        entry = matches[0]
        rows.append(summarize(entry, json.loads(context_body(root, ctx, entry))))
    return {"run": RUN, "rows": rows}
