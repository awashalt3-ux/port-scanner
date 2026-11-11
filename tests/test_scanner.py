from __future__ import annotations

import unittest

import scanner


class ParseTargetTests(unittest.TestCase):
    def test_bare_host_defaults_to_http(self) -> None:
        self.assertEqual(
            scanner.parse_target("example.com"),
            ("example.com", 80, "http"),
        )

    def test_https_url_uses_https_default(self) -> None:
        self.assertEqual(
            scanner.parse_target("https://example.com/path"),
            ("example.com", 443, "https"),
        )

    def test_ipv6_url(self) -> None:
        self.assertEqual(
            scanner.parse_target("http://[::1]:8080/"),
            ("::1", 8080, "http"),
        )

    def test_explicit_port(self) -> None:
        self.assertEqual(
            scanner.parse_target("example.com:8443"),
            ("example.com", 8443, "http"),
        )


class ParsePortsTests(unittest.TestCase):
    def test_ranges_and_duplicates(self) -> None:
        self.assertEqual(
            scanner.parse_ports("80,443,8080-8082,80"),
            [80, 443, 8080, 8081, 8082],
        )

    def test_reversed_range_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            scanner.parse_ports("443-80")

    def test_out_of_range_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            scanner.parse_ports("65536")


class ModuleNameTests(unittest.TestCase):
    def test_names_are_normalised_and_deduplicated(self) -> None:
        self.assertEqual(
            scanner.parse_module_names("dns, robots,DNS"),
            ["dns", "robots"],
        )

    def test_unknown_module_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            scanner.parse_module_names("dns,nope")


class HttpResponseTests(unittest.TestCase):
    def test_parses_status_and_headers(self) -> None:
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Test: one\r\n\r\nbody"
        status, headers = scanner.parse_http_response(raw)
        self.assertEqual(status, "HTTP/1.1 200 OK")
        self.assertEqual(
            headers,
            [("Content-Type", "text/plain"), ("X-Test", "one")],
        )

    def test_rejects_non_http_response(self) -> None:
        self.assertEqual(scanner.parse_http_response(b"not http\r\n\r\n"), ("", []))


class PayloadTests(unittest.TestCase):
    def test_modules_are_included_when_present(self) -> None:
        modules = [
            scanner.ModuleResult(
                name="dns",
                ok=True,
                summary="A, AAAA",
                data={"records": {"A": ["127.0.0.1"]}},
            )
        ]
        payload = scanner.build_payload("example.com", [80], {}, modules)
        self.assertEqual(payload["open_port_count"], 1)
        self.assertEqual(payload["modules"][0]["module"], "dns")
        self.assertEqual(payload["modules"][0]["data"]["records"]["A"], ["127.0.0.1"])

    def test_modules_key_is_omitted_when_empty(self) -> None:
        payload = scanner.build_payload("example.com", [], {})
        self.assertNotIn("modules", payload)


if __name__ == "__main__":
    unittest.main()
