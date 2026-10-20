import json
from .common import inline_payload, atomic_text


def save_json(data, filename='scan_results.json'):
    """Write a structured report; failures propagate to the caller."""
    payload = inline_payload(data)
    with atomic_text(filename) as stream:
        json.dump(payload, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write('\n')
