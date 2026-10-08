#!/usr/bin/env python3
"""Resolve archive identity and publication intent before building a release."""
import os
from pathlib import Path
import re


def resolve(event, ref):
    if event == "pull_request":
        return {"version": "v0.0.0-test", "publish": "false", "notes": ""}
    if event not in ("push", "workflow_dispatch"):
        raise ValueError("unsupported release event")
    prefixes = ("refs/tags/", "refs/heads/release/")
    prefix = next((value for value in prefixes if ref.startswith(value)), None)
    version = ref[len(prefix):] if prefix else ""
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("use a vX.Y.Z tag or release/vX.Y.Z branch")
    # Review branches exercise the same archives without creating a release.
    review = version.endswith("-review")
    notes_version = version.removesuffix("-review") if review else version
    return {"version": version, "publish": str(not review).lower(),
            "notes": f"docs/releases/{notes_version}.md"}


if __name__ == "__main__":
    plan = resolve(os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"])
    if plan["notes"] and not Path(plan["notes"]).is_file():
        raise SystemExit(f"Missing release notes: {plan['notes']}")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for key, value in plan.items():
            output.write(f"{key}={value}\n")
