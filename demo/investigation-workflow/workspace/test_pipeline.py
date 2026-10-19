import unittest

from pipeline import summarize


class ReportTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(summarize([]), {"total": "0.00", "daily": {}})

    def test_single(self):
        self.assertEqual(summarize([{"date": "2026-10-01", "amount": "19.95"}])["total"], "19.95")

    def test_decimal_precision(self):
        rows = [{"date": "2026-10-01", "amount": amount} for amount in ("0.10", "0.20")]
        self.assertEqual(summarize(rows)["total"], "0.30")

    def test_same_day(self):
        rows = [{"date": "2026-10-01", "amount": amount} for amount in ("19.95", "10.05")]
        self.assertEqual(summarize(rows)["daily"], {"2026-10-01": "30.00"})

    def test_multiple_days(self):
        rows = [{"date": "2026-10-01", "amount": "30"}, {"date": "2026-10-02", "amount": "7.25"}]
        self.assertEqual(summarize(rows)["total"], "37.25")

    def test_sorted_days(self):
        rows = [{"date": day, "amount": "1"} for day in ("2026-10-03", "2026-10-01")]
        self.assertEqual(list(summarize(rows)["daily"]), ["2026-10-01", "2026-10-03"])

    def test_refund(self):
        rows = [{"date": "2026-10-01", "amount": amount} for amount in ("20", "-5")]
        self.assertEqual(summarize(rows)["total"], "15.00")


if __name__ == "__main__":
    unittest.main()
