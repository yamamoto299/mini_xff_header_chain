# SPDX-License-Identifier: MIT
"""Parse the X-Forwarded-For header into an ordered list of client IPs.

The header is comma-separated, leftmost client first (RFC 7239 §5.1 / 5.2).
Each token may be an IPv4, IPv6, or IPv6-literal literal wrapped in square
brackets. We strip surrounding ASCII whitespace per RFC 7230 §3.2.6 but reject
zero tokens, whitespace embedded inside IPv6-literals (e.g. "[::1 ]"), and
surrogate characters per RFC 3629.

Interpretation of ambiguous whitespace in a comma-separated list:
When a token looks like " 192.0.2.1" (leading space) we strip it.
When a token looks like "192.0.2.1 \t" (trailing space) we strip it.
Whitespace *embedded* in a bracketed IPv6 literal (e.g. "[::1 ]") is rejected
because the only valid bracketed form is "[addr]" with no interior whitespace.
"""

import ipaddress
from typing import List


class InvalidXForwardedForError(ValueError):
    """Raised when the X-Forwarded-For header is structurally malformed."""


def _is_valid_ipv6_literal(token: str) -> bool:
    """Return True for a bare IPv6 inside brackets, e.g. "[::1]".

    We only accept the exact form "[<addr>]" with no interior whitespace
    and no port suffix; that is the RFC 7239 form. Reject "[::1]:8080" and
    "[::1 ]" so callers cannot receive a value with trailing junk.
    """
    if len(token) < 4 or token[0] != "[" or token[-1] != "]":
        return False
    inner = token[1:-1]
    for ch in inner:
        # RFC 3629 forbids non-characters, so reject any surrogate
        # code-point. For real Python 3 strings on a UTF-8 source this
        # branch cannot trigger from a literal, but an explicit check keeps
        # us robust against future decoder changes.
        if ch == " " or ch == "\t" or ord(ch) == 0xFEFF:
            return False
    try:
        ipaddress.IPv6Address(inner)
    except (ipaddress.AddressValueError, ValueError):
        return False
    else:
        return True


def _is_valid_token(token: str) -> bool:
    """Return True if token is a valid standalone IP."""
    if token.startswith("[") or token.endswith("]"):
        return False
    if "%" in token:
        return False
    try:
        ipaddress.ip_address(token)
    except (ipaddress.AddressValueError, ValueError):
        return False
    else:
        return True


def parse_x_forwarded_for(header: str) -> List[str]:
    """Parse the X-Forwarded-For header into an ordered list of client IPs.

    Leftmost client first, rightmost proxy last. Whitespace around tokens
    is stripped per RFC 7230. Empty tokens (",,") and bare whitespace tokens
    are rejected with :class:`InvalidXForwardedForError`. IPv6 literals must
    be wrapped in square brackets as in RFC 7239 §5.1; embedded whitespace
    inside the brackets is rejected.

    Returns a list of canonicalized IP strings (uppercase IPv6). Raises
    :class:`InvalidXForwardedForError` if the header is structurally invalid
    or contains a zero-length token.
    """
    if not isinstance(header, str):
        raise InvalidXForwardedForError("X-Forwarded-For must be a string")
    if "\x00" in header:
        # A NUL in the header would split the wire form from the parsed form;
        # reject rather than silently truncating.
        raise InvalidXForwardedForError("NUL byte in X-Forwarded-For header")

    parts = header.split(",")
    result: List[str] = []
    for raw in parts:
        token = raw.strip()
        if token == "":
            raise InvalidXForwardedForError(
                "empty token in X-Forwarded-For header"
            )

        is_bracketed = token.startswith("[") and token.endswith("]")
        if is_bracketed:
            if not _is_valid_ipv6_literal(token):
                raise InvalidXForwardedForError(
                    f"invalid IPv6 literal: {token!r}"
                )
            addr = ipaddress.IPv6Address(token[1:-1])
            result.append("[" + str(addr) + "]")
            continue

        if token.startswith("[") or token.endswith("]"):
            raise InvalidXForwardedForError(f"malformed IP token: {token!r}")

        if "%" in token:
            raise InvalidXForwardedForError(f"invalid IP token: {token!r}")

        try:
            addr = ipaddress.ip_address(token)
        except (ipaddress.AddressValueError, ValueError):
            raise InvalidXForwardedForError(f"invalid IP token: {token!r}") from None

        result.append(str(addr))

    return result
