import json
import pandas as pd
from typing import List, Dict, Any

def to_json(results: List[Dict[str, Any]], path: str = "scan_results.json") -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def to_csv(results: List[Dict[str, Any]], path: str = "scan_summary.csv") -> None:
    rows = []
    for page in results:
        rows.append({
            "url": page.get("url"),
            "status": page.get("status"),
            "ga4": page.get("detectors", {}).get("ga4") if page.get("detectors") else None,
            "fb": page.get("detectors", {}).get("fb") if page.get("detectors") else None,
            "adobe": page.get("detectors", {}).get("adobe") if page.get("detectors") else None,
            "datalayer_valid": page.get("datalayer_validation", {}).get("valid") if page.get("datalayer_validation") else None
        })
    df = pd.DataFrame(rows)
    df.to_csv(path, index=False)
