"""Check staged files and, optionally, all changes introduced since a commit."""

import argparse
import os
import subprocess
import sys


MAX_BYTES = 10 * 1024 * 1024
BOUNDARY = b"output/go.mod"
# Existing public evidence: only these exact Git blobs at these paths are exempt.
LEGACY = {
    b"docs/benchmarks/v1.0-candidate/replays/task-investigation.zip": b"b5d203ca8167bef49753bfa8173ea303337b735f",
    b"docs/benchmarks/v1.0-x86-completion/replays/browser/crash-recovery-reading.zip": b"cf1ed1ec9fe3d3d5589c84936da0d74c5a82df7b",
    b"docs/benchmarks/v1.0-x86-completion/replays/browser/sensor-on-reading.zip": b"77e1c8849322798c855dc7e752dea92ba391f5ea",
}
# Removed archives may occur in a PR's older history, never in its index or a new commit.
RETIRED_ADDITIONS = {
    (b"45d1c00ae896097c96121c7944c16d02d95ae24b", b"artifacts/acceptance/v0.10.1/AgentProvenance-v0.10.1-x86-acceptance-4828cce.zip", b"908aa6ab43e69a85ac9ec3d11334a0ac6e7b639a"),
    (b"541b33cabec7af3028a54b64ae421931ef690775", b"docs/benchmarks/v1.0-x86-completion/replays/browser/sensor-on-derived.zip", b"4490881ba1bf8002b97c0b4d086f12c02d0a5a5b"),
}


def git(*args, data=None):
    return subprocess.run(["git", *args], input=data, stdout=subprocess.PIPE, check=True).stdout


def index_entries():
    for record in git("ls-files", "--stage", "-z").split(b"\0"):
        if record:
            meta, path = record.split(b"\t", 1)
            mode, oid, stage = meta.split()
            if stage != b"0":
                raise ValueError(f"Unmerged index entry: {os.fsdecode(path)!r}")
            yield path, oid, mode


def history_entries(base):
    # Check intermediate commits too: deleting a file later leaves its blob in Git.
    if git("rev-parse", "--is-shallow-repository").strip() == b"true":
        raise ValueError("Range checks need full commit history; use a full checkout or check the index only.")
    base_oid = git("rev-parse", "--verify", "--end-of-options", base + "^{commit}").strip().decode()
    records = git("log", "--format=commit:%H", "--raw", "-z", "--no-abbrev", "--no-renames",
                  "--root", "-m", "--diff-filter=AMT", base_oid + "..HEAD", "--")
    fields = iter(records.split(b"\0"))
    commit = None
    for meta in fields:
        if meta.startswith(b"commit:"):
            commit = meta[len(b"commit:"):]
        elif meta:
            _, mode, _, oid, _ = meta.split()
            path = next(fields)
            if (commit, path, oid) not in RETIRED_ADDITIONS:
                yield path, oid, mode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", metavar="BASE", help="also inspect every commit in BASE..HEAD")
    args = parser.parse_args()
    os.chdir(os.fsdecode(git("rev-parse", "--show-toplevel").rstrip(b"\n")))
    staged = set(index_entries())
    errors = set()
    if not any(path == BOUNDARY and mode == b"100644" for path, _, mode in staged):
        errors.add("Keep output/go.mod in the index as a regular file to isolate generated Go packages.")
    entries = staged.union(history_entries(args.since)) if args.since else staged
    ids = {oid for _, oid, mode in entries if mode != b"160000"}
    sizes = {}
    if ids:
        rows = git("cat-file", "--batch-check=%(objectname) %(objectsize)",
                   data=b"\n".join(sorted(ids)) + b"\n")
        sizes = {oid: int(size) for oid, size in (line.split() for line in rows.splitlines())}
    for path, oid, mode in entries:
        label = repr(os.fsdecode(path))
        if path.startswith(b"output/") and path != BOUNDARY:
            errors.add(f"{label}: local output must not be tracked.")
        elif mode != b"160000" and sizes[oid] > MAX_BYTES and LEGACY.get(path) != oid:
            errors.add(f"{label}: {sizes[oid]} bytes exceeds 10 MiB. Use an artifact download and checksum.")
    for error in sorted(errors):
        print(error, file=sys.stderr)
    if not errors:
        print("Repository artifact check passed.")
    return int(bool(errors))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(f"Repository artifact check failed: {exc}")
