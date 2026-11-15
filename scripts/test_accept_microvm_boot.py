import copy
import unittest

from accept_microvm_boot import retirement_allowed


class MicrovmRetirementTest(unittest.TestCase):
    def setUp(self):
        self.target = dict(producer_id='producer', instance_id='instance', generation='first')
        self.expected = {'attempt-a': 'run-a', 'attempt-b': 'run-b'}
        self.deliveries = [dict(attempt_id=attempt, run_id=run, status='prepared',
                               delivery=dict(manifest=dict(receiver_id='receiver', identity=dict(
                                   attempt_id=attempt, local_run_id=run, target=self.target))))
                           for attempt, run in self.expected.items()]
        self.complete = dict(attempts=2, complete=True, delivery_complete=True,
                             receipts_pending=0, receipts_verified=2, target=self.target, receiver_id='receiver')

    def allowed(self, summary, **overrides):
        args = dict(target=self.target, expected=self.expected, deliveries=self.deliveries, receiver='receiver')
        args.update(overrides)
        return retirement_allowed(summary, **args)

    def test_only_complete_verified_receipts_allow_retirement(self):
        complete = self.complete
        self.assertTrue(self.allowed(complete))
        for field, values in {
            'attempts': [None, 0, -1, True, '2'],
            'complete': [False, None, 1],
            'delivery_complete': [False, None, 1],
            'receipts_pending': [1, None, False, '0'],
            'receipts_verified': [0, 1, 3, None, True, '2'],
            'target': [None, {}, dict(self.target, generation='other')],
            'receiver_id': [None, '', 'other'],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertFalse(self.allowed(dict(complete, **{field: value})))
        for field in complete:
            with self.subTest(missing=field):
                self.assertFalse(self.allowed({k: v for k, v in complete.items() if k != field}))

    def test_empty_missing_duplicate_or_substituted_inventory_is_rejected(self):
        for rows in ([], self.deliveries[:1], self.deliveries + self.deliveries[:1],
                     [self.deliveries[0], self.deliveries[0]], [None, self.deliveries[1]]):
            with self.subTest(rows=rows):
                self.assertFalse(self.allowed(self.complete, deliveries=rows))
        self.assertFalse(self.allowed(self.complete, expected={}))
        self.assertFalse(self.allowed(self.complete, expected={'other-a': 'run-a', 'other-b': 'run-b'}))
        for field, value in [('attempt_id', 'other'), ('local_run_id', 'other'),
                             ('target', dict(self.target, generation='other'))]:
            rows = copy.deepcopy(self.deliveries)
            rows[0]['delivery']['manifest']['identity'][field] = value
            with self.subTest(field=field):
                self.assertFalse(self.allowed(self.complete, deliveries=rows))
        for field, value in [('attempt_id', 'other'), ('run_id', 'other'), ('status', 'failed')]:
            rows = copy.deepcopy(self.deliveries)
            rows[0][field] = value
            self.assertFalse(self.allowed(self.complete, deliveries=rows))
        rows = copy.deepcopy(self.deliveries)
        rows[0]['delivery']['manifest']['receiver_id'] = 'other'
        self.assertFalse(self.allowed(self.complete, deliveries=rows))


if __name__ == '__main__':
    unittest.main()
