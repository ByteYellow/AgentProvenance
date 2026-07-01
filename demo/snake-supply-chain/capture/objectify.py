#!/usr/bin/env python3
# Legacy helper. `agentprov record` now objectifies changed files automatically;
# keep this only for manually repairing older captures.
#
# Objectify the agent's output files into the run's provenance object store so the
# dashboard Side Panel can preview "what the agent actually produced".
#
# The content is wrapped in the canonical provenance-object envelope (so `verify`
# accepts it as valid JSON) with the file bytes under payload.content; the dashboard
# unwraps artifact-type objects for preview. source_id is the lens node id
# (workspace_file/<path>) so the existing preview resolver matches.
import os, hashlib, json, sqlite3

DD = os.path.expanduser(os.environ.get("AGENTPROV_DATA_DIR", "~/.agentprov-snake"))
DB = os.path.join(DD, "agentprov.db")
RUN = os.environ.get("AGENTPROV_RUN_ID", "run-snake-supervised")
WS = os.path.expanduser(os.environ.get("AGENTPROV_WORKDIR", "~/agentprov-snake-demo/workspace"))
targets = ["snake.py", "SETUP.md"]

con = sqlite3.connect(DB)
# Drop any prior artifact objects for these source ids (e.g. an earlier raw-content
# objectify) so re-running is idempotent and leaves no invalid objects behind.
for rel in targets:
    sid = "workspace_file/" + rel
    for (path,) in con.execute("SELECT path FROM provenance_objects WHERE run_id=? AND source_id=?", (RUN, sid)):
        try:
            os.remove(path)
        except OSError:
            pass
    con.execute("DELETE FROM provenance_objects WHERE run_id=? AND source_id=?", (RUN, sid))

for rel in targets:
    fp = os.path.join(WS, rel)
    if not os.path.exists(fp):
        print("skip (missing):", rel)
        continue
    text = open(fp, "r", errors="replace").read()
    envelope = {
        "schema": "agentprov.provenance.object.v1",
        "type": "artifact",
        "source_id": "workspace_file/" + rel,
        "run_id": RUN,
        "refs": {},
        "parents": [],
        "payload": {"path": rel, "size": len(text), "content": text},
    }
    raw = json.dumps(envelope, sort_keys=True).encode()
    h = hashlib.sha256(raw).hexdigest()
    hashid = "sha256:" + h
    objdir = os.path.join(DD, "provenance", "objects", "sha256", h[:2])
    os.makedirs(objdir, exist_ok=True)
    objpath = os.path.join(objdir, h + ".json")
    with open(objpath, "wb") as fh:
        fh.write(raw)
    con.execute(
        "INSERT OR REPLACE INTO provenance_objects "
        "(hash, object_type, source_id, run_id, rollout_id, parent_hashes, path, size_bytes, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (hashid, "artifact", "workspace_file/" + rel, RUN, "", "", objpath, len(raw), "2026-06-29T11:30:00Z"),
    )
    print("objectified workspace_file/%s -> %s (%d bytes content)" % (rel, hashid[:22], len(text)))
con.commit()
con.close()
