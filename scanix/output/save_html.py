from ..core.utils import safe_print
import html


def save_html(data, filename="scan_results.html", title="Scanix Results"):
    try:
        rows = ""
        if data:
            keys = sorted({k for d in data for k in d.keys()})
            # header
            header = "".join(f"<th>{html.escape(str(k))}</th>" for k in keys)
            for item in data:
                row = "".join(
                    f"<td>{html.escape(str(item.get(k, '')))}</td>" for k in keys
                )
                rows += f"<tr>{row}</tr>\n"
            table = f"<table border='1'><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table>"
        else:
            table = "<p>No results</p>"

        html_doc = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>{html.escape(title)}</title></head>
<body>
<h1>{html.escape(title)}</h1>
{table}
</body>
</html>"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_doc)
        safe_print(f"Saved HTML results to {filename}", success=True)
    except Exception as e:
        safe_print(f"Failed to save HTML: {e}", error=True)
