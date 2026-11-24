"""Build featured excerpts from the published recording each card opens."""
import errno
import json
from urllib.parse import urlsplit

from replay_card_source import catalog, context_body, saved_bytes, shard


PAIR = ("run-860466af8a9a", "run-3bfc6838a9c6")
BROWSER = "run-da25e015ca1f"
TEAM = "run-double-attempt"
# Curated bookmarks, not copies of the answers shown on the homepage.
BROWSER_EVENTS = {
    "navigation": ("action_end", "d3d9ed21-d67b-4af8-bb63-38a63394305d"),
    "read": ("action_end", "3c1cf5f4-68a5-4b69-b1ea-86ccbe103622"),
    "png": ("screenshot", "3f4d995a-3eeb-4b55-a0ae-2356047ed188"),
    "har": ("har", "6562916f-4070-428b-9449-b443af2aeaa9"),
}


def one(matches, name):
    matches = list(matches)
    if len(matches) != 1:
        raise ValueError(f"Expected one {name}; found {len(matches)}")
    return matches[0]


def recorded_file(root, run, events, artifacts, path):
    event = one((e for e in events if e["run_id"] == run and e["source"] == "record_file_diff"
                 and e.get("raw_event_id") == "record-file-" + path), path)
    meta = json.loads(event["payload"])["payload"]
    if (meta["op"], meta["content_state"], meta["path"]) != ("record_diff", "stored", path):
        raise ValueError(f"Expected a retained file snapshot: {path}")
    body = saved_bytes(root, artifacts["en/body/workspace_file/" + path],
                       {"ref": meta["artifact_ref"], "schema_version": "agentprovenance.artifact_page/v1",
                        "mode": "body", "content_state": "stored", "truncated": False})
    return {"path": path, "event": event["id"], "ref": meta["artifact_ref"]}, json.loads(body)


def investigation_card(root):
    runs = catalog(root)["runs"]
    out = {}
    for role, run in zip(("before", "after"), PAIR):
        events, artifacts = (shard(root, runs[run][key]) for key in ("events", "artifacts"))
        meta, diag = recorded_file(root, run, events, artifacts, "output/diagnostics.json")
        if not isinstance(diag, list):
            raise ValueError("Expected the saved diagnostic entries")
        denied = sum(row["result"] == -1 and row["errno"] in (errno.EACCES, errno.EPERM) for row in diag)
        out[role] = dict(meta, run=run, records=len(diag), denied=denied)
        if role == "after":
            meta, config = recorded_file(root, run, events, artifacts, "settings.json")
            switches = config["diagnostics"]
            if not isinstance(switches, dict) or not all(isinstance(v, bool) for v in switches.values()):
                raise ValueError("Expected boolean diagnostic settings")
            out["settings"] = dict(meta, disabled=sum(v is False for v in switches.values()))
    return out


def browser_card(root):
    ctx = shard(root, catalog(root)["runs"][BROWSER]["context"])
    latest = set(ctx["latest"])
    entries = [e for e in ctx["entries"] if e["id"] in latest and e["run_id"] == BROWSER
               and e["source"].get("harness") == "browser" and "browser" in e]
    cuts = {name: one((e for e in entries if (e["browser"].get("kind"), e["browser"].get("event_id")) == pair), name)
            for name, pair in BROWSER_EVENTS.items()}
    if len({e["source"]["id"] for e in cuts.values()}) != 1:
        raise ValueError("Featured browser records are from different capture sources")
    nav, read = cuts["navigation"], cuts["read"]
    if len({cuts[k]["browser"]["target_id"] for k in ("navigation", "read", "png")}) != 1:
        raise ValueError("Featured page records belong to different browser targets")
    if (nav["browser"]["operation"], read["browser"]["operation"]) != ("navigate", "read_text"):
        raise ValueError("Unexpected browser operation at the selected bookmark")
    out = {"run": BROWSER, "navigation": {"op": nav["browser"]["operation"], "entry": nav["id"],
                                         "path": urlsplit(nav["browser"]["url"]).path},
           "read": {"op": read["browser"]["operation"], "entry": read["id"],
                    "text": json.loads(context_body(root, ctx, read))["text"].splitlines()[0]}}
    image = None
    for key, media, schema in (("png", "image/png", "raster"), ("har", "application/har+json", "har")):
        e = cuts[key]
        att = one((a for a in e["attachments"] if a["media_type"] == media and a["state"] == "stored"), media)
        data = saved_bytes(root, ctx["attachments"][att["ref"]],
                           {"schema_version": f"agentprovenance.{schema}_attachment/v1",
                            "ref": att["ref"], "run_id": BROWSER, "media_type": media},
                           digest=att["sha256"], size=att["bytes"], binary=True)
        out[key] = {"entry": e["id"], "ref": att["ref"], "bytes": len(data), "sha256": att["sha256"]}
        if key == "png":
            image = data
    return out, image


def team_card(site):
    gallery = json.loads((site / "replay-catalog.json").read_text())
    idx = shard(site, gallery["run_indexes"][TEAM], http=True)
    if idx["run_id"] != TEAM:
        raise ValueError("Wrong gallery run for the featured team case")
    events = shard(site, idx["run"]["events"], http=True)
    ids = {e["id"] for e in events if e["run_id"] == TEAM}
    summary = one((s for s in gallery["summaries"] if s["run"] == TEAM), "team run summary")
    if len(ids) != len(events) or len(ids) != summary["events"]:
        raise ValueError("Team event index disagrees with the gallery summary")
    return {"run": TEAM, "events": len(ids)}
