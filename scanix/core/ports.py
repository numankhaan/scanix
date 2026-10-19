"""Port selection shared by CLI and callers."""
import re


def parse_ports(selection: str) -> tuple[int, ...]:
    ports = set()
    for token in selection.split(','):
        token = token.strip()
        if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?', token):
            raise ValueError(f"malformed port selection: {token!r}")
        bounds = token.split('-')
        try:
            start, end = int(bounds[0]), int(bounds[-1])
        except ValueError:
            raise ValueError("invalid port number") from None
        if not 1 <= start <= end <= 65535:
            raise ValueError("ports must be within 1–65535; ranges must not be reversed")
        ports.update(range(start, end + 1))
    return tuple(sorted(ports))
