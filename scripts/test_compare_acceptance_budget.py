import copy
import unittest

from compare_acceptance_budget import compare_environment


class EnvironmentComparisonTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {"system": "Linux", "architecture": "x86_64", "kernel": "6.8.0",
                         "cpu_count": 4, "memory_bytes": 4105359360}

    def test_one_page_is_explicit_and_preserves_both_observations(self):
        candidate = dict(self.baseline, memory_bytes=self.baseline["memory_bytes"] + 4096)
        originals = copy.deepcopy((candidate, self.baseline))
        with self.assertRaises(ValueError):
            compare_environment(candidate, self.baseline)
        equivalent, audit = compare_environment(candidate, self.baseline, True)
        self.assertEqual(equivalent, self.baseline)
        self.assertEqual(audit["difference_bytes"], 4096)
        self.assertFalse(audit["exact_match"])
        self.assertEqual((candidate, self.baseline), originals)

    def test_kib_and_negative_page_difference(self):
        before = {"system": "Linux", "cpu_count": 4, "memory_kib": 4009144}
        after = {"system": "Linux", "cpu_count": 4, "memory_kib": 4009140}
        _, audit = compare_environment(after, before, True)
        self.assertEqual(audit["difference_bytes"], -4096)

    def test_changed_machine_and_larger_difference_remain_rejected(self):
        for changes in ({"memory_bytes": self.baseline["memory_bytes"] + 8192},
                        {"cpu_count": 8}, {"kernel": "6.9.0"}, {"memory_bytes": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                compare_environment(dict(self.baseline, **changes), self.baseline, True)


if __name__ == "__main__":
    unittest.main()
