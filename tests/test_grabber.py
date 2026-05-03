import unittest

from src.grabber.grabber import BannerGrabber


class BannerGrabberTestCase(unittest.TestCase):
    def setUp(self):
        self.grabber = BannerGrabber()

    def test_parse_http_banner_extracts_server(self):
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n"
            b"Location: /login\r\n\r\n"
        )

        banner = self.grabber._parse_http_banner(payload)

        self.assertIn("HTTP/1.1 200 OK", banner)
        self.assertIn("Server: nginx/1.24.0", banner)
        self.assertIn("Location: /login", banner)

    def test_guess_service_handles_redis_banner(self):
        service = self.grabber._guess_service(6379, "+PONG")
        self.assertEqual(service, "redis")
