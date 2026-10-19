import html
import json
from .common import atomic_text, RESULT_FIELDS, scalar


def save_html(data, filename='scan_results.html', title='Scanix Results'):
    payload = data.to_dict()
    escape = lambda value: html.escape(str(value), quote=True)
    with atomic_text(filename) as stream:
        stream.write('<!doctype html><html><head><meta charset="utf-8"><title>'
                     + escape(title) + '</title></head><body><h1>' + escape(title) + '</h1>')
        metadata = {key: value for key, value in payload.items() if key != 'results'}
        stream.write('<pre>' + escape(json.dumps(metadata, indent=2, ensure_ascii=False)) + '</pre>')
        stream.write('<table border="1"><thead><tr>' + ''.join(
            '<th>' + escape(key) + '</th>' for key in RESULT_FIELDS) + '</tr></thead><tbody>')
        for result in payload['results']:
            stream.write('<tr>' + ''.join('<td>' + escape(scalar(result[key])) + '</td>'
                                          for key in RESULT_FIELDS) + '</tr>')
        stream.write('</tbody></table></body></html>\n')
