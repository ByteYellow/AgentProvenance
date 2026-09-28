import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from report import total_revenue


class ReportTests(unittest.TestCase):
    def test_sample(self):
        self.assertEqual(total_revenue(Path(__file__).with_name("orders.csv")), Decimal("42.00"))

    def test_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.csv"
            path.write_text("date,order_id,amount,status\n", encoding="utf-8")
            self.assertEqual(total_revenue(path), Decimal("0"))


if __name__ == "__main__":
    unittest.main()
