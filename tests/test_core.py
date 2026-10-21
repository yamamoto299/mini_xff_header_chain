# SPDX-License-Identifier: MIT
"""Unit tests for mini_xff_header_chain.core."""

import unittest

from mini_xff_header_chain import parse_x_forwarded_for, InvalidXForwardedForError


class TestParseSingleToken(unittest.TestCase):
    def test_single_ipv4(self):
        self.assertEqual(
            parse_x_forwarded_for("192.0.2.1"),
            ["192.0.2.1"],
        )

    def test_single_bare_ipv6(self):
        self.assertEqual(
            parse_x_forwarded_for("2001:db8::1"),
            ["2001:db8::1"],
        )

    def test_single_bracketed_ipv6(self):
        self.assertEqual(
            parse_x_forwarded_for("[2001:db8::1]"),
            ["[2001:db8::1]"],
        )


class TestParseMultipleTokens(unittest.TestCase):
    def test_two_ipv4(self):
        self.assertEqual(
            parse_x_forwarded_for("203.0.113.5, 198.51.100.2"),
            ["203.0.113.5", "198.51.100.2"],
        )

    def test_ipv4_then_bracketed_ipv6(self):
        self.assertEqual(
            parse_x_forwarded_for("203.0.113.5, [2001:db8::1]"),
            ["203.0.113.5", "[2001:db8::1]"],
        )

    def test_bracketed_ipv6_then_ipv4(self):
        self.assertEqual(
            parse_x_forwarded_for("[2001:db8::1], 203.0.113.5"),
            ["[2001:db8::1]", "203.0.113.5"],
        )

    def test_three_tokens_mixed(self):
        self.assertEqual(
            parse_x_forwarded_for("203.0.113.5, [2001:db8::1], 198.51.100.2"),
            ["203.0.113.5", "[2001:db8::1]", "198.51.100.2"],
        )

    def test_preserves_order(self):
        # First token is the client, last is the trusted proxy.
        ips = parse_x_forwarded_for("10.0.0.1, 10.0.0.2, 10.0.0.3")
        self.assertEqual(ips[0], "10.0.0.1")
        self.assertEqual(ips[-1], "10.0.0.3")


class TestWhitespaceHandling(unittest.TestCase):
    def test_leading_and_trailing_spaces(self):
        self.assertEqual(
            parse_x_forwarded_for("  192.0.2.1  ,  198.51.100.2  "),
            ["192.0.2.1", "198.51.100.2"],
        )

    def test_tab_whitespace(self):
        self.assertEqual(
            parse_x_forwarded_for("\t192.0.2.1\t,\t198.51.100.2\t"),
            ["192.0.2.1", "198.51.100.2"],
        )


class TestCanonicalization(unittest.TestCase):
    def test_ipv6_canonicalized_to_lowercase_and_full_form(self):
        result = parse_x_forwarded_for("[2001:DB8:0:0:0:0:0:1]")
        self.assertEqual(result, ["[2001:db8::1]"])

    def test_bare_ipv6_canonicalized(self):
        # Bare IPv6 is returned in Python's canonical compressed form.
        result = parse_x_forwarded_for("2001:DB8:0:0:0:0:0:1")
        self.assertEqual(result, ["2001:db8::1"])


class TestInvalidInput(unittest.TestCase):
    def test_empty_string_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("")

    def test_empty_token_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("192.0.2.1,,198.51.100.2")

    def test_bare_whitespace_token_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("192.0.2.1,   ,198.51.100.2")

    def test_nul_byte_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("192.0.2.1\x00")

    def test_non_string_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for(None)  # type: ignore[arg-type]

    def test_garbage_token_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("not-an-ip")

    def test_unbalanced_open_bracket_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("[2001:db8::1")

    def test_unbalanced_close_bracket_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("2001:db8::1]")

    def test_bracketed_with_port_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("[2001:db8::1]:8080")

    def test_bracketed_ipv4_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("[192.0.2.1]")

    def test_bare_zero_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("0")

    def test_empty_brackets_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("[]")


class TestEdgeCases(unittest.TestCase):
    def test_leading_zeros_in_ipv4_rejected(self):
        # ipaddress treats leading zeros as octal in some impls and rejects
        # them outright in modern Python. Either way, we surface it as invalid.
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("192.0.2.010")

    def test_ipv4_mapped_ipv6(self):
        result = parse_x_forwarded_for("::ffff:192.0.2.1")
        self.assertEqual(result, ["::ffff:192.0.2.1"])

    def test_loopback_ipv4(self):
        self.assertEqual(parse_x_forwarded_for("127.0.0.1"), ["127.0.0.1"])

    def test_loopback_ipv6(self):
        self.assertEqual(parse_x_forwarded_for("[::1]"), ["[::1]"])

    def test_unspecified_ipv4(self):
        self.assertEqual(parse_x_forwarded_for("0.0.0.0"), ["0.0.0.0"])

    def test_unspecified_ipv6(self):
        self.assertEqual(parse_x_forwarded_for("[::]"), ["[::]"])

    def test_trailing_comma_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("192.0.2.1,")

    def test_leading_comma_raises(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for(",192.0.2.1")

    def test_internal_whitespace_in_brackets_rejected(self):
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("[::1 ]")

    def test_ipv4_in_zone_rejected(self):
        # Not a valid standalone IP token in our parser.
        with self.assertRaises(InvalidXForwardedForError):
            parse_x_forwarded_for("fe80::1%eth0")


if __name__ == "__main__":
    unittest.main()
