#!/usr/bin/env python3
# Objectify the agent's output files into the run's provenance object store so the
# dashboard Side Panel can preview "what the agent actually produced". source_id is
# set to the lens node id (workspace_file/<path>) so the existing resolver matches.
import os, hashlib, sqlite3, time

DD = os.path.expanduser("~/.agentprov-snake")
DB = os.path.join(DD, "agentprov.db")
RUN = "run-snake-agent"
WS = os.path.expanduser("~/agentprov-snake-demo/workspace")
ts = "2026-06-29T11:30:00Z"

targets = ["snake.py", "SETUP.md"]
con = sqlite3.connect(DB)
for rel in targets:
    fp = os.path.join(WS, rel)
    if not os.path.exists(fp):
        print("skip (missing):", rel); continue
    data = open(fp, "rb").read()
    h = hashlib.sha256(data).hexdigest()
    hashid = "sha256:" + h
    objdir = os.path.join(DD, "provenance", "objects", "sha256", h[:2])
    os.makedirs(objdir, exist_ok=True)
    objpath = os.path.join(objdir, h + ".json")
    with open(objpath, "wb") as fh:
        fh.write(data)
    con.execute(
        "INSERT OR REPLACE INTO provenance_objects "
        "(hash, object_type, source_id, run_id, rollout_id, parent_hashes, path, size_bytes, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (hashid, "artifact", "workspace_file/" + rel, RUN, "", "", objpath, len(data), ts),
    )
    print("objectified workspace_file/%s -> %s (%d bytes)" % (rel, hashid[:22], len(data)))
con.commit()
con.close()
