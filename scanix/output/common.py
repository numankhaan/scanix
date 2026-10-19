"""Shared serialization and atomic replacement for reports."""
from contextlib import contextmanager
from dataclasses import fields
import json
import os
from pathlib import Path
import tempfile
from ..core.models import ScanResult

RESULT_FIELDS = [field.name for field in fields(ScanResult)]
METADATA_FIELDS = ['completion_status', 'incomplete', 'requested_ports', 'completed_ports',
                   'configuration', 'issues', 'schema_version', 'implementation', 'probe_database_version', 'scope', 'discovery']
CSV_FIELDS = ['record_type'] + METADATA_FIELDS + RESULT_FIELDS


def scalar(value):
    if value is None or isinstance(value, (dict, list, tuple, bool)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value


@contextmanager
def atomic_text(filename):
    path = Path(filename)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='',
                                         dir=path.parent, prefix=f'.{path.name}.',
                                         suffix='.tmp', delete=False) as stream:
            temporary = stream.name
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
