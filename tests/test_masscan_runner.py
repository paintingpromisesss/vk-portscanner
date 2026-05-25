import unittest

from src.scanner.masscan_runner import MasscanRunner


class MasscanRunnerTestCase(unittest.TestCase):
    def test_normalize_csv_removes_spaces_around_items(self):
        runner = MasscanRunner()

        normalized = runner._normalize_csv("1.1.1.1/32, 45.33.32.156/32, 64.13.139.230/32")

        self.assertEqual(normalized, "1.1.1.1/32,45.33.32.156/32,64.13.139.230/32")
