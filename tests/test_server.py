import base64
import io
import unittest
import zipfile
from unittest.mock import patch

import server


class ScanTextTests(unittest.TestCase):
    def test_finds_common_synthetic_signals_and_masks_them(self):
        result = server.scan_text(
            "Email: alex@example.test; UPI: sample-user@demo; "
            "Address: 42 Sample Road; api_key=demo_secret_value_12345"
        )
        types = {finding["type"] for finding in result["findings"]}
        self.assertIn("Email", types)
        self.assertIn("UPI ID", types)
        self.assertIn("Address / location", types)
        self.assertIn("Credential / secret", types)
        self.assertGreater(result["score"], 0)
        self.assertTrue(all("alex@example.test" not in f["masked"] for f in result["findings"]))

    def test_empty_scan_is_low_risk(self):
        result = server.scan_text("A friendly synthetic message with no personal details.")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "Low")
        self.assertEqual(result["findings"], [])

    def test_ocr_accepts_decimal_confidence_and_groups_words_by_line(self):
        tsv = "level\tpage\tblock\tparagraph\tline\tword\tleft\ttop\twidth\theight\tconf\ttext\n"
        tsv += "5\t1\t1\t1\t1\t1\t10\t20\t40\t12\t96.740738\talice@example.test\n"
        tsv += "5\t1\t1\t1\t2\t1\t10\t50\t30\t12\t88.5\tsecond\n"
        lines = server.parse_ocr_tsv(tsv)
        self.assertEqual(len(lines), 2)
        self.assertEqual(next(iter(lines.values()))[0][0], "alice@example.test")

    def test_overlap_is_not_double_counted(self):
        result = server.scan_text("4111111111111111")
        self.assertLessEqual(len(result["findings"]), 1)

    def test_specific_card_and_identity_patterns_beat_broad_phone_match(self):
        result = server.scan_text("Card: 4111 1111 1111 1111; ID: 1234 5678 9012")
        types = [finding["type"] for finding in result["findings"]]
        self.assertIn("Payment card", types)
        self.assertIn("Government ID pattern", types)
        self.assertNotIn("Phone number", types)


class AssistantTests(unittest.TestCase):
    def setUp(self):
        self.findings = server.scan_text("Email: alex@example.test; api_key=demo_secret_value_12345")["findings"]

    def test_sharing_question_warns_and_names_scan_findings(self):
        answer = server.assistant_reply("Can I share this?", self.findings)
        self.assertIn("review this before sharing", answer)
        self.assertIn("Credential / secret", answer)
        self.assertIn("cannot certify", answer)

    def test_explanation_question_includes_reason(self):
        answer = server.assistant_reply("What does this mean?", self.findings)
        self.assertIn("could grant access", answer)

    def test_first_action_prioritizes_secret_and_gives_advice(self):
        answer = server.assistant_reply("What should I fix first?", self.findings)
        self.assertIn("Start with Credential / secret", answer)
        self.assertIn("revoke or rotate", answer)

    def test_no_scan_gives_next_step(self):
        answer = server.assistant_reply("Can I share this?", [])
        self.assertIn("Run a text, document, or image scan first", answer)
        self.assertIn("not proof", answer)


class WebsiteValidationTests(unittest.TestCase):
    def test_missing_scheme_is_normalized(self):
        parsed = server.urllib.parse.urlsplit(server.normalize_url(" example.com "))
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "example.com")

    def test_host_is_normalized_and_root_path_is_added(self):
        self.assertEqual(server.normalize_url("HAPPY.COM"), "https://happy.com/")

    def test_spaces_are_rejected_instead_of_becoming_a_domain(self):
        with self.assertRaisesRegex(ValueError, "Remove spaces"):
            server.normalize_url("happy site.com")

    def test_bare_word_is_not_a_complete_public_domain(self):
        with self.assertRaisesRegex(ValueError, "full public domain"):
            server.normalize_url("happy")

    def test_invalid_port_is_explained(self):
        with self.assertRaisesRegex(ValueError, "invalid host or port"):
            server.normalize_url("https://example.com:bad")

    def test_betting_keyword_is_blocked_before_dns_or_network(self):
        with patch.object(server, "safe_resolve", side_effect=AssertionError("must not resolve blocked host")):
            result = server.check_url("https://casino.example.com")
        self.assertTrue(result["blocked"])
        self.assertEqual(result["summary"], "Blocked by local betting-site filter")
        self.assertIsNone(result["reachable"])

    def test_number_prefixed_xbet_domain_is_blocked(self):
        with patch.object(server, "safe_resolve", side_effect=AssertionError("must not resolve blocked host")):
            result = server.check_url("https://indian.1xbet.com/en/line/cricket")
        self.assertTrue(result["blocked"])
        self.assertIn("did not contact", result["note"].lower())

    def test_unrelated_domain_with_bet_as_substring_is_not_keyword_blocked(self):
        with patch.object(server, "safe_resolve", side_effect=ValueError("stop before network")):
            with self.assertRaisesRegex(ValueError, "stop before network"):
                server.check_url("https://alphabet.example.com")

    def test_unsupported_protocol_is_not_rewritten(self):
        with self.assertRaises(ValueError):
            server.check_url("ftp://example.com")

    def test_local_destinations_are_rejected_before_request(self):
        for url in ("http://127.0.0.1", "http://localhost", "http://192.168.1.1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                server.check_url(url)

    def test_credentials_in_url_are_rejected(self):
        with self.assertRaises(ValueError):
            server.check_url("https://user:pass@example.com")

    def test_head_rejection_falls_back_to_get_and_tls_timeout_is_inconclusive(self):
        class Response:
            status = 206
            def geturl(self): return "https://example.com/"
            def read(self, size): return b"x"
            def __enter__(self): return self
            def __exit__(self, *_): pass

        class Opener:
            def __init__(self, redirect_handler): self.handlers = [redirect_handler]
            def open(self, request, timeout):
                if request.get_method() == "HEAD":
                    raise server.urllib.error.HTTPError(request.full_url, 405, "Method not allowed", {}, None)
                return Response()

        def build_opener(handler): return Opener(handler)
        with patch.object(server, "safe_resolve"), \
             patch.object(server.urllib.request, "build_opener", side_effect=build_opener), \
             patch.object(server.socket, "create_connection", side_effect=TimeoutError):
            result = server.check_url("https://example.com")
        self.assertTrue(result["reachable"])
        self.assertEqual(result["httpStatus"], 206)
        self.assertIsNone(result["tls"]["valid"])
        self.assertIn("inconclusive", result["tlsNote"])
        self.assertFalse(any("certificate" in flag["title"].lower() for flag in result["flags"]))


class DocumentExtractionTests(unittest.TestCase):
    def test_docx_xml_extraction(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("word/document.xml", '<w:document xmlns:w="urn:w"><w:t>alex@example.test</w:t></w:document>')
        self.assertEqual(server.extract_document("sample.docx", stream.getvalue()), "alex@example.test")

    def test_oversized_text_is_refused_by_limit(self):
        with self.assertRaisesRegex(ValueError, "1 MB"):
            server.extract_document("sample.txt", b"x" * 1_000_001)


if __name__ == "__main__":
    unittest.main()
