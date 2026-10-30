# mini_xff_header_chain

Parses the `X-Forwarded-For` HTTP header into an ordered list of client IP addresses, leftmost first.

```python
from mini_xff_header_chain import parse_x_forwarded_for, InvalidXForwardedForError

try:
    clients = parse_x_forwarded_for("203.0.113.5, [2001:db8::1], 198.51.100.2")
except InvalidXForwardedForError as exc:
    raise
# clients == ["203.0.113.5", "[2001:db8::1]", "198.51.100.2"]
```

## Why this exists

When your service sits behind one or more proxies, the `X-Forwarded-For` header is the canonical way to recover the originating client IP. The header is a comma-separated chain, with the original client at the left and each successive proxy appended to the right. A correct parser has to split that chain, validate each hop, and preserve order.

This library makes one deliberate trade-off: it validates every token strictly and refuses to return values it cannot prove are IPs. Loose parsers that silently drop bad tokens make downstream code behave inconsistently depending on who sent the header. Strict rejection surfaces bad input at the boundary.

## Exported names

- `parse_x_forwarded_for(header: str) -> list[str]` — the parser.
- `InvalidXForwardedForError` — raised on any structural or per-token failure.

## Edge cases you will hit

- **Empty tokens** (e.g. `"192.0.2.1,,198.51.100.2"` or a trailing comma) raise. There is no silent skipping.
- **IPv6 must be bracketed** as `[<addr>]` per RFC 7239 when it appears in the chain. Bare IPv6 is still accepted by this parser because a single-token header is unambiguous, but mixing bare IPv6 with other tokens in a comma list is ambiguous on the wire — callers who need strict RFC compliance should bracket.
- **Ports are rejected.** `[2001:db8::1]:8080` and `192.0.2.1:8080` are both invalid. If you need port stripping, do it before calling.
- **IPv6 is canonicalized.** `[2001:DB8:0:0:0:0:0:1]` comes back as `[2001:db8::1]`. If you need byte-for-byte preservation, this library is not the right tool.
- **Leading zeros in IPv4** (e.g. `192.0.2.010`) are rejected, matching modern `ipaddress` semantics.

## Running the tests

```sh
PYTHONPATH=src python -m unittest discover -s tests
```

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

## Limitations

Values are coerced to floats, so very large integers lose precision. If you need
exact integer aggregates over a window, this is the wrong tool.

