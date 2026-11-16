"""Refresh display-only navigation in archived candidate replays.

The source archives stay unchanged. Saved nodes, evidence references and causal
edges are retained; the adjustments match the current graph reader's counts,
artifact grouping and standalone-record display.
"""
import base64
import copy
import gzip
import hashlib
import json


def refresh_graph_navigation(root, catalog, saved):
    def write(value):
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
        digest = hashlib.sha256(raw).hexdigest()
        ref = {"path": f"data/{digest}.json.gz", "sha256": digest, "bytes": len(raw)}
        encoded = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
        (root / ref["path"].replace(".json.gz", ".js")).write_text(
            f'window.AgentProvOffline.accept("{ref["path"]}","{encoded}");'
        )
        return ref

    for run_id, run in catalog["runs"].items():
        for holder in [run, *run.get("sessions", {}).values()]:
            index = saved(holder["lenses"])
            nodes, focus = saved(index["nodes"]), saved(index["focus_nodes"])
            canonical = [nodes[key] for key in index.get("present") or []]
            artifacts = sum(n["kind"] == "artifact" for n in canonical)
            for key, ref in list(index["views"].items()):
                lens, detail = key.split("/")
                if lens not in ("default", "file-artifact", "intent"):
                    continue
                view = saved(ref)
                manifest = view["manifest"]
                before_nodes = len(manifest["nodes"])
                before_edges = len(manifest["edges"])
                added_groups = 0
                if key == "default/summary":
                    for n in manifest["nodes"]:
                        if n["id"] == "overview/artifacts":
                            n["label"] = f"Artifacts: {artifacts}"
                            n["data"]["count"] = artifacts
                    for edge in manifest["edges"]:
                        if edge["to_id"] == "overview/artifacts":
                            edge["data"]["count"] = artifacts
                elif key == "file-artifact/summary" and artifacts:
                    group_id = "file_group/artifacts"
                    if not any(n["id"] == group_id for n in manifest["nodes"]):
                        data = {"category": "artifacts", "count": artifacts,
                                "drilldown_lens": lens, "drilldown_detail": "raw"}
                        root_id = f"run/{run_id}"
                        if not any(n["id"] == root_id for n in manifest["nodes"]):
                            manifest["nodes"].append(copy.deepcopy(nodes[root_id]))
                        manifest["nodes"].append({"id": group_id, "kind": "file_group",
                            "subtype": "artifacts", "label": f"artifacts: {artifacts}",
                            "trust_origin": "summary", "data": data})
                        manifest["edges"].append({"id": "summary-file-artifacts", "from_id": root_id,
                            "to_id": group_id, "edge_type": "run_file_group", "derived": False, "data": data})
                        focus[group_id] = {"id": group_id, "kind": "unknown", "label": group_id}
                        added_groups = 1
                elif lens == "intent" or (lens == "file-artifact" and detail != "summary"):
                    kinds = {"tool_call"} if lens == "intent" else {"artifact", "file"}
                    present = {n["id"] for n in manifest["nodes"]}
                    for n in sorted(canonical, key=lambda n: (n["kind"], n["id"])):
                        if n["kind"] not in kinds or n["id"] in present:
                            continue
                        if len(present) >= manifest["query"]["limit"]:
                            manifest["query"]["truncated"] = True
                            break
                        manifest["nodes"].append(copy.deepcopy(n))
                        present.add(n["id"])
                else:
                    continue
                manifest["nodes"].sort(key=lambda n: (n["kind"], n["id"]))
                query = manifest["query"]
                query["node_count"] = len(manifest["nodes"])
                query["edge_count"] = len(manifest["edges"]) + len(manifest.get("derived_edges", []))
                query["omitted_nodes"] = max(0, query.get("omitted_nodes", 0) + added_groups + before_nodes - query["node_count"])
                query["omitted_edges"] = max(0, query.get("omitted_edges", 0) + before_edges - len(manifest["edges"]))
                tagged = {(tag["kind"], tag["target_id"]) for tag in manifest.get("overlays", [])}
                for n in manifest["nodes"]:
                    if "trust" in query.get("overlays", []) and n.get("trust_origin") and ("trust_origin", n["id"]) not in tagged:
                        manifest.setdefault("overlays", []).append({"target_id": n["id"], "kind": "trust_origin", "label": n["trust_origin"]})
                    if "risk" in query.get("overlays", []) and n.get("risk") and ("risk", n["id"]) not in tagged:
                        manifest.setdefault("overlays", []).append({"target_id": n["id"], "kind": "risk", "label": n["risk"], "severity": n["risk"]})
                manifest["summary"] = [f'lens={lens} layout={query["layout_hint"]}',
                    f'detail={detail} raw_events={query["raw_event_count"]} nodes={query["node_count"]} '
                    f'edges={len(manifest["edges"])} derived_edges={query["derived_edge_count"]} '
                    f'omitted_nodes={query["omitted_nodes"]} omitted_edges={query["omitted_edges"]}']
                for n in manifest["nodes"]:
                    nodes[n["id"]] = n
                index["views"][key] = write(view)
            index["nodes"] = write(nodes)
            index["focus_nodes"] = write(focus)
            holder["lenses"] = write(index)
    encoded = base64.b64encode(json.dumps(catalog, separators=(",", ":")).encode()).decode()
    (root / "assets/catalog.js").write_text(f'window.AgentProvOfflineCatalog="{encoded}";')
