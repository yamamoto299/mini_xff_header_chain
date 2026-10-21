# SPDX-License-Identifier: MIT
"""mini_xff_header_chain public API."""

from .core import parse_x_forwarded_for, InvalidXForwardedForError

__all__ = [
    "parse_x_forwarded_for",
    "InvalidXForwardedForError",
]
