import csv
from .common import atomic_text, CSV_FIELDS, METADATA_FIELDS, scalar


def spreadsheet_safe(value):
    # CSV quoting alone does not prevent spreadsheet formula execution.
    if isinstance(value, str) and value.lstrip(' \t\r\n').startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def save_csv(data, filename='scan_results.csv'):
    """A metadata row followed by result rows; nested values are JSON cells."""
    payload = data.to_dict()
    with atomic_text(filename) as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerow({'record_type': 'scan', **{
            key: spreadsheet_safe(scalar(payload[key])) for key in METADATA_FIELDS}})
        for result in payload['results']:
            writer.writerow({'record_type': 'result', **{
                key: spreadsheet_safe(scalar(value)) for key, value in result.items()}})
