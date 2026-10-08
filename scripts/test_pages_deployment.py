import unittest

from prepare_pages_deployment import select_run


class PagesDeploymentTest(unittest.TestCase):
    def setUp(self):
        self.run = {'id': 42, 'head_sha': 'published', 'status': 'completed', 'event': 'push',
                    'head_repository': {'full_name': 'owner/repo'}, 'path': '.github/workflows/release.yml'}
        self.jobs = [{'name': name, 'conclusion': 'success'} for name in ('validate', 'site', 'publish')]
        self.artifacts = [{'name': 'github-pages', 'expired': False}]

    def get(self, path):
        return {'jobs': self.jobs} if '/jobs?' in path else {'artifacts': self.artifacts}

    def select(self, run=None):
        return select_run([run or self.run], 'published', 'owner/repo', self.get)

    def test_recover_published_artifact_after_only_deployment_failed(self):
        self.run['conclusion'] = 'failure'
        self.jobs.append({'name': 'deploy-site', 'conclusion': 'failure'})
        self.assertEqual(self.select(), 42)

    def test_unpublished_or_unvalidated_build_is_ineligible(self):
        for job in self.jobs:
            job['conclusion'] = 'skipped'
            self.assertIsNone(self.select())
            job['conclusion'] = 'success'

    def test_other_commits_repositories_workflows_and_pull_requests_are_ineligible(self):
        for field, value in [('head_sha', 'unreleased'), ('event', 'pull_request'),
                             ('head_repository', {'full_name': 'fork/repo'}),
                             ('path', '.github/workflows/other.yml'), ('status', 'in_progress')]:
            self.assertIsNone(self.select(dict(self.run, **{field: value})))

    def test_expired_or_ambiguous_artifact_is_ineligible(self):
        self.artifacts[0]['expired'] = True
        self.assertIsNone(self.select())
        self.artifacts[0]['expired'] = False
        self.artifacts *= 2
        self.assertIsNone(self.select())


if __name__ == '__main__':
    unittest.main()
