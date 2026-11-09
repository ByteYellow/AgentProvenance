import unittest

from accept_sensor_live import timestamp_ns


class TimestampTests(unittest.TestCase):
    def test_nanosecond_ordering(self):
        first = timestamp_ns("2026-11-09T04:10:17.271168901Z")
        second = timestamp_ns("2026-11-09T04:10:17.271168902Z")
        self.assertEqual(second - first, 1)

    def test_offsets_and_fractional_precision(self):
        self.assertEqual(timestamp_ns("1970-01-01T00:00:00Z"), 0)
        self.assertEqual(timestamp_ns("1970-01-01T08:00:00.1+08:00"), 100_000_000)
        self.assertEqual(timestamp_ns("1969-12-31T23:59:59.999999999Z"), -1)
        self.assertEqual(timestamp_ns("1970-01-01T00:00:00.001Z"), 1_000_000)
        self.assertEqual(timestamp_ns("1969-12-31T19:00:00-05:00"), 0)

    def test_rejects_missing_zone_and_excess_precision(self):
        for value in ("2026-11-09T04:10:17", "2026-11-09T04:10:17.1234567891Z", "bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                timestamp_ns(value)


if __name__ == "__main__":
    unittest.main()
