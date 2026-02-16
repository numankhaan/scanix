import csv
from ..core.utils import safe_print

def save_csv(data, filename="scan_results.csv"):
    try:
        if not data:
            safe_print("No data to save", warn=True)
            return
        keys = sorted({k for d in data for k in d.keys()})
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        safe_print(f"Saved CSV results to {filename}", success=True)
    except Exception as e:
        safe_print(f"Failed to save CSV: {e}", error=True)