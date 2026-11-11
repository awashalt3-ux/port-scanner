from __future__ import annotations

import unittest

from scan_modules.base import ModuleResult
from scan_modules.dns_scan import parse_dns_server
from scan_modules.http import parse_http_response, split_http_response
from scan_modules.robots_txt import parse_robots


class RobotsParserTests(unittest.TestCase):
    def test_groups_sitemaps_and_comments(self) -> None:
        text = """
        # comment
        User-agent: *
        User-agent: ExampleBot
        Disallow: /private
        Allow: /public
        Crawl-delay: 2
        Sitemap: https://example.com/sitemap.xml
        """
        parsed = parse_robots(text)
        self.assertEqual(len(parsed["groups"]), 1)
        self.assertEqual(parsed["groups"][0]["agents"], ["*", "ExampleBot"])
        self.assertEqual(
            parsed["groups"][0]["rules"],
            [
                {"field": "disallow", "value": "/private"},
                {"field": "allow", "value": "/public"},
                {"field": "crawl-delay", "value": "2"},
            ],
        )
        self.assertEqual(parsed["sitemaps"], ["https://example.com/sitemap.xml"])

    def test_separate_groups_for_multiple_user_agents(self) -> None:
        text = """
        User-agent: A
        Disallow: /a

        User-agent: B
        Disallow: /b
        """
        parsed = parse_robots(text)
        self.assertEqual(len(parsed["groups"]), 2)
        self.assertEqual(parsed["groups"][0]["agents"], ["A"])
        self.assertEqual(parsed["groups"][1]["agents"], ["B"])


class HttpParserTests(unittest.TestCase):
    def test_split_crlf(self) -> None:
        head, body = split_http_response(b"HTTP/1.1 200 OK\r\n\r\nbody")
        self.assertEqual(head, b"HTTP/1.1 200 OK\r\n\r\n")
        self.assertEqual(body, b"body")

    def test_split_lf(self) -> None:
        head, body = split_http_response(b"HTTP/1.1 200 OK\n\nbody")
        self.assertEqual(head, b"HTTP/1.1 200 OK\n\n")
        self.assertEqual(body, b"body")

    def test_parse_folded_header(self) -> None:
        raw = b"HTTP/1.1 200 OK\r\nX-Test: one\r\n two\r\n\r\n"
        response = parse_http_response(raw)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response.header("x-test"), "one two")


class DnsServerTests(unittest.TestCase):
    def test_ipv4(self) -> None:
        self.assertEqual(parse_dns_server("1.1.1.1"), ("1.1.1.1", 53))

    def test_ipv4_with_port(self) -> None:
        self.assertEqual(parse_dns_server("1.1.1.1:5353"), ("1.1.1.1", 5353))

    def test_ipv6(self) -> None:
        self.assertEqual(parse_dns_server("2001:4860:4860::8888"), ("2001:4860:4860::8888", 53))

    def test_bracketed_ipv6_with_port(self) -> None:
        self.assertEqual(
            parse_dns_server("[2001:4860:4860::8888]:5353"),
            ("2001:4860:4860::8888", 5353),
        )

    def test_hostname_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_dns_server("dns.google")


class ModuleResultTests(unittest.TestCase):
    def test_to_dict(self) -> None:
        result = ModuleResult(name="dns", ok=True, summary="A", data={"x": 1})
        self.assertEqual(
            result.to_dict(),
            {
                "module": "dns",
                "ok": True,
                "summary": "A",
                "data": {"x": 1},
                "error": None,
            },
        )


if __name__ == "__main__":
    unittest.main()
