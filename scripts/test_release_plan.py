import unittest

from release_plan import resolve


class ReleasePlanTest(unittest.TestCase):
    def test_review_builds_without_publishing(self):
        for event in ("push", "workflow_dispatch"):
            plan = resolve(event, "refs/heads/release/v0.9.0-review")
            self.assertEqual(plan, {"version": "v0.9.0-review", "publish": "false",
                                    "notes": "docs/releases/v0.9.0.md"})

    def test_release_and_prerelease_keep_their_own_notes(self):
        for prefix in ("refs/tags/", "refs/heads/release/"):
            for version in ("v0.9.0", "v0.9.0-rc.1"):
                plan = resolve("push", prefix + version)
                self.assertEqual(plan["version"], version)
                self.assertEqual(plan["publish"], "true")
                self.assertEqual(plan["notes"], f"docs/releases/{version}.md")

    def test_pull_requests_only_build(self):
        self.assertEqual(resolve("pull_request", "refs/pull/42/merge"),
                         {"version": "v0.0.0-test", "publish": "false", "notes": ""})

    def test_invalid_refs_cannot_publish(self):
        for ref in ("refs/heads/main", "refs/heads/v0.9.0", "refs/tags/vnext",
                    "refs/heads/release/v0.9.0/extra", "refs/tags/v0.9.0\n"):
            with self.assertRaises(ValueError):
                resolve("push", ref)


if __name__ == "__main__":
    unittest.main()
