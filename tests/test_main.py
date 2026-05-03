import unittest

from main import parse_args


class MainArgsTestCase(unittest.TestCase):
    def test_parse_test_notifications_flag(self):
        args = parse_args(["--test-notifications", "--config", "custom.yaml"])
        self.assertTrue(args.test_notifications)
        self.assertEqual(args.config, "custom.yaml")
