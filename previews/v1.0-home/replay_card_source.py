"""Read the same saved shards as the gallery and the offline reader, without running JS."""
import base64
import gzip
import hashlib
import json
import re


def catalog(root):
    prefix = "window.AgentProvOfflineCatalog="
    text = (root / "assets/catalog.js").read_text().strip()
    if not (text.startswith(prefix) and text.endswith(";")):
        raise ValueError("Invalid offline catalog")
    return json.loads(base64.b64decode(json.loads(text[len(prefix):-1]), validate=True))


def shard(root, ref, *, http=False):
    digest = ref["sha256"]
    if not re.fullmatch(r"[a-f0-9]{64}", digest) or ref["path"] != f"data/{digest}.json.gz":
        raise ValueError("Invalid replay shard reference")
    if http:
        zipped = (root / ref["path"]).read_bytes()
    else:
        prefix = "window.AgentProvOffline.accept("
        text = (root / "data" / (digest + ".js")).read_text().strip()
        if not (text.startswith(prefix) and text.endswith(");")):
            raise ValueError("Invalid replay shard wrapper")
        path, encoded = json.loads("[" + text[len(prefix):-2] + "]")
        if path != ref["path"]:
            raise ValueError("Mismatched replay shard path")
        zipped = base64.b64decode(encoded, validate=True)
    data = gzip.decompress(zipped)
    if len(data) != ref["bytes"] or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Replay shard failed integrity verification")
    return json.loads(data)


def saved_bytes(root, index, identity, *, digest=None, size=None, binary=False):
    """A page's wrapper digest is separate from the digest of the reconstructed body."""
    result = bytearray()
    pages = index["pages"]
    for i, ref in enumerate(pages):
        p = shard(root, ref)
        if i == 0:
            digest = p["sha256"] if digest is None else digest
            size = p["total_bytes"] if size is None else size
        if (any(p.get(k) != v for k, v in identity.items())
                or p["sha256"] != digest or p["total_bytes"] != size
                or p["offset"] != len(result) or p["has_more"] != (i + 1 < len(pages))):
            raise ValueError("Mismatched evidence page identity or range")
        if binary and p.get("encoding") != "base64":
            raise ValueError("Unexpected attachment encoding")
        result.extend(base64.b64decode(p["data"], validate=True) if binary else p["content"].encode())
        if len(result) != p["next_offset"]:
            raise ValueError("Incomplete evidence page")
    if not pages or len(result) != size or hashlib.sha256(result).hexdigest() != digest:
        raise ValueError("Saved body failed integrity verification")
    return bytes(result)


def context_body(root, ctx, entry):
    meta = entry["content"]
    if meta.get("state") != "stored":
        raise ValueError("Expected retained context body")
    return saved_bytes(root, ctx["content"][meta["ref"]],
                       {"schema_version": "agentprovenance.content_page/v1", "run_id": entry["run_id"], "ref": meta["ref"]},
                       digest=meta["sha256"], size=meta["bytes"])
