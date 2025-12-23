import re
from typing import List, Dict, Any

GA4_PATTERNS = [
    re.compile(r"google-analytics.com/g/collect"),
    re.compile(r"gtag\("),
    re.compile(r"collect\?measurement_id=")
]

FB_PATTERNS = [
    re.compile(r"connect.facebook.net"),
    re.compile(r"facebook.com/tr/"),
    re.compile(r"fbq\(")
]

ADOBE_PATTERNS = [
    re.compile(r"/b/ss/"),
    re.compile(r"adobeanalytics"),
    re.compile(r"s\.t\(")
]

def detect_from_requests(requests: List[Dict[str, Any]]) -> Dict[str, bool]:
    found = {"ga4": False, "fb": False, "adobe": False}
    for r in requests or []:
        url = r.get("url", "") if isinstance(r, dict) else str(r)
        for p in GA4_PATTERNS:
            if p.search(url):
                found["ga4"] = True
        for p in FB_PATTERNS:
            if p.search(url):
                found["fb"] = True
        for p in ADOBE_PATTERNS:
            if p.search(url):
                found["adobe"] = True
    return found

def detect_from_html(html: str) -> Dict[str, bool]:
    if not html:
        return {"ga4": False, "fb": False, "adobe": False}
    found = {
        "ga4": any(p.search(html) for p in GA4_PATTERNS),
        "fb": any(p.search(html) for p in FB_PATTERNS),
        "adobe": any(p.search(html) for p in ADOBE_PATTERNS)
    }
    return found
