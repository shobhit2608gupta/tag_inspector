import sys
import os
import json
import re
from io import StringIO
import base64
import asyncio
import textwrap

import pandas as pd
import streamlit as st

@st.cache_resource(show_spinner=False)
def ensure_playwright_browsers():
    """
    Best-effort:
    - On hosts like Streamlit Cloud / GitHub deploys, Playwright browsers may not be present.
    - This tries to install them once, without crashing the app if it fails.
    """
    try:
        # If playwright isn't installed, nothing to do
        import playwright  # noqa: F401

        # Install browsers (idempotent)
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        # Don't hard-fail; crawler will raise a clear error if browsers are missing.
        pass

# Call it once at startup
ensure_playwright_browsers()


# --- Playwright + Streamlit on Windows fix ---
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# --- Make src importable ---
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from op_lite.crawler import Crawler
from op_lite.detectors import detect_from_requests, detect_from_html
from op_lite.validator import validate_datalayer

# -----------------------------
# Regexes / constants
# -----------------------------
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
# tel: URI patterns, e.g. tel:+1800123456 or tel:%2B1800123456
TEL_SCHEME_RE = re.compile(r"tel:%2B?\d+|tel:\+?\d+", re.IGNORECASE)
# very simple credit-card-like pattern (13–16 digits, spaces/dashes allowed)
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

# -----------------------------
# Helpers: PII scanning
# -----------------------------
def scan_pii_in_text(text: str):
    """Return (email_count, tel_count, cc_count) in a single text blob."""
    if not text:
        return 0, 0, 0
    emails = EMAIL_RE.findall(text)
    tels = TEL_SCHEME_RE.findall(text)
    ccs = CREDIT_CARD_RE.findall(text)
    return len(emails), len(tels), len(ccs)


def scan_pii_for_page(p: dict):
    """Scan network requests + dataLayer only, for PII patterns."""
    email_count = 0
    tel_count = 0
    cc_count = 0

    # Network requests URLs
    for r in p.get("requests", []):
        url_r = r.get("url") or ""
        e, t, c = scan_pii_in_text(url_r)
        email_count += e
        tel_count += t
        cc_count += c

    # dataLayer payloads
    if p.get("dataLayer") is not None:
        dl_str = json.dumps(p["dataLayer"])
        e, t, c = scan_pii_in_text(dl_str)
        email_count += e
        tel_count += t
        cc_count += c

    return email_count, tel_count, cc_count


# -----------------------------
# Helpers: aggregation & issues
# -----------------------------
def aggregate_results(results):
    rows = []
    unique_tags = set()  # still used for GA4 / Adobe / FB detector view

    for p in results:
        det_req = detect_from_requests(p.get("requests", []))
        det_html = detect_from_html(p.get("html") or "")
        detectors = {
            "ga4": det_req.get("ga4") or det_html.get("ga4"),
            "fb": det_req.get("fb") or det_html.get("fb"),
            "adobe": det_req.get("adobe") or det_html.get("adobe"),
        }

        dl_val = validate_datalayer(p.get("dataLayer"))
        p["detectors"] = detectors
        p["datalayer_validation"] = dl_val

        status = p.get("status")
        load_time = p.get("load_time")
        html = p.get("html") or ""
        page_size_kb = round(len(html) / 1024.0, 1) if html else 0.0

        has_datalayer = p.get("dataLayer") is not None
        form_audit = p.get("form_audit") or {}
        video_audit = p.get("video_audit") or {}

        has_form = bool(form_audit.get("attempted") or form_audit.get("success"))
        form_success = bool(form_audit.get("success"))
        has_video = bool(video_audit and video_audit.get("video_found"))
        video_started = bool(video_audit and video_audit.get("play_started"))

        # PII scan (network + dataLayer only)
        pii_email_count, pii_tel_count, pii_cc_count = scan_pii_for_page(p)
        pii_exposure = any(
            count > 0 for count in (pii_email_count, pii_tel_count, pii_cc_count)
        )

        for name, present in detectors.items():
            if present:
                unique_tags.add(name)

        rows.append(
            {
                "url": p.get("url"),
                "status": status,
                "load_time": load_time,
                "page_size_kb": page_size_kb,
                "has_datalayer": has_datalayer,
                "datalayer_valid": dl_val.get("valid"),
                "datalayer_errors": "; ".join(
                    [str(e) for e in dl_val.get("errors") or []]
                ),
                "ga4": bool(detectors.get("ga4")),
                "adobe": bool(detectors.get("adobe")),
                "fb": bool(detectors.get("fb")),
                "has_form": has_form,
                "form_submit_success": form_success,
                "has_video": has_video,
                "video_play_started": video_started,
                "pii_exposure": pii_exposure,
                "pii_email_count": pii_email_count,
                "pii_tel_count": pii_tel_count,
                "pii_cc_count": pii_cc_count,
            }
        )

    df = pd.DataFrame(rows)
    return df, unique_tags


def derive_issues(results):
    """Existing rule-based issues + updated PII detection."""
    issues = []
    for p in results:
        url = p.get("url")
        status = p.get("status")
        detectors = p.get("detectors") or {}
        dl_val = p.get("datalayer_validation") or {}
        form_audit = p.get("form_audit") or {}
        video_audit = p.get("video_audit") or {}

        if status and status >= 400:
            issues.append(
                {
                    "type": "http_error",
                    "severity": "high",
                    "url": url,
                    "details": f"HTTP status {status}",
                }
            )

        if detectors.get("ga4") is False:
            issues.append(
                {
                    "type": "missing_ga4",
                    "severity": "high",
                    "url": url,
                    "details": "GA4 not detected on this page",
                }
            )

        if dl_val.get("valid") is False:
            errors = dl_val.get("errors") or []
            issues.append(
                {
                    "type": "invalid_datalayer",
                    "severity": "high",
                    "url": url,
                    "details": f"dataLayer validation failed: {errors[:3]}",
                }
            )

        if form_audit.get("attempted") and not form_audit.get("success"):
            issues.append(
                {
                    "type": "form_submit_failed",
                    "severity": "medium",
                    "url": url,
                    "details": f"Form auto-submit failed: {form_audit.get('error')}",
                }
            )

        if video_audit.get("video_found") and not video_audit.get("play_started"):
            issues.append(
                {
                    "type": "video_playback_issue",
                    "severity": "low",
                    "url": url,
                    "details": f"Video found but playback did not start (error={video_audit.get('error')})",
                }
            )

        # Updated PII – reuse same helper as summary
        pii_email_count, pii_tel_count, pii_cc_count = scan_pii_for_page(p)
        if any(count > 0 for count in (pii_email_count, pii_tel_count, pii_cc_count)):
            issues.append(
                {
                    "type": "pii_exposure",
                    "severity": "high",
                    "url": url,
                    "details": (
                        f"Possible PII found "
                        f"(emails={pii_email_count}, tel={pii_tel_count}, cards={pii_cc_count})"
                    ),
                }
            )

    return issues


def extract_datalayer_events(results):
    rows = []
    for p in results:
        url = p.get("url")
        dl = p.get("dataLayer")
        if isinstance(dl, list):
            for item in dl:
                if isinstance(item, dict):
                    event = item.get("event")
                    rows.append(
                        {
                            "url": url,
                            "event": event,
                            "json": json.dumps(item, indent=2),
                        }
                    )
    if not rows:
        return pd.DataFrame(columns=["url", "event", "json"])
    return pd.DataFrame(rows)


EVENT_NAME_OK_RE = re.compile(r"^[a-z0-9_]+$")  # lower_snake_case


def find_naming_issues(results):
    rows = []
    for p in results:
        url = p.get("url")
        dl = p.get("dataLayer")
        if isinstance(dl, list):
            for item in dl:
                if not isinstance(item, dict):
                    continue
                event = item.get("event")
                if not isinstance(event, str):
                    continue
                if not EVENT_NAME_OK_RE.match(event):
                    rows.append({"url": url, "event_name": event})

    if not rows:
        detail_df = pd.DataFrame(columns=["url", "event_name"])
        summary_df = pd.DataFrame(columns=["event_name", "error_count"])
        total_issues = 0
    else:
        detail_df = pd.DataFrame(rows)
        summary_df = (
            detail_df.groupby("event_name")
            .size()
            .reset_index(name="error_count")
            .sort_values("error_count", ascending=False)
        )
        total_issues = int(detail_df.shape[0])

    return detail_df, summary_df, total_issues


# --------- Data quality issues from dataLayer ---------
ERROR_STR_STRINGS = {"undefined", "not set", "(not set)"}


def build_data_quality_issues(results):
    """
    Build SME-style Data Quality Issues:
      - Type of error (undefined / not set / (not set) / false / empty)
      - # of occurrences
      - Parameter
      - Event
    """
    rows = []
    pages_scanned = len(results)
    pages_with_dl = 0

    for p in results:
        dl = p.get("dataLayer")
        if not isinstance(dl, list) or not dl:
            continue
        pages_with_dl += 1

        for item in dl:
            if not isinstance(item, dict):
                continue
            event_name = item.get("event") or ""
            for key, val in item.items():
                if key == "event":
                    continue
                error_type = None
                if val is None:
                    error_type = "undefined"
                elif isinstance(val, bool) and val is False:
                    error_type = "false"
                elif isinstance(val, str):
                    v = val.strip().lower()
                    if v in ERROR_STR_STRINGS:
                        error_type = v
                    elif v == "":
                        error_type = "empty"
                # you could extend with more rules here

                if error_type:
                    rows.append(
                        {
                            "error_type": error_type,
                            "parameter": key,
                            "event": event_name,
                        }
                    )

    if rows:
        df_raw = pd.DataFrame(rows)
        df_detail = (
            df_raw.groupby(["error_type", "parameter", "event"])
            .size()
            .reset_index(name="# of occurrences")
            .sort_values("# of occurrences", ascending=False)
        )
        total_issues = int(df_detail["# of occurrences"].sum())
    else:
        df_detail = pd.DataFrame(
            columns=["error_type", "parameter", "event", "# of occurrences"]
        )
        total_issues = 0

    summary = {
        "pages_scanned": pages_scanned,
        "datalayer_loaded": pages_with_dl,
        "total_issues": total_issues,
    }
    return summary, df_detail


# --------- PII detail summary ---------
def build_pii_detail(df_summary: pd.DataFrame):
    """
    Build overall + per-page PII stats based on columns
    pii_email_count, pii_tel_count, pii_cc_count.
    """
    if df_summary.empty:
        overall = {
            "emails": 0,
            "tels": 0,
            "cards": 0,
            "pages_with_pii": 0,
        }
        per_page = pd.DataFrame(
            columns=["url", "emails", "tels", "cards"]
        )
        return overall, per_page

    per_page = df_summary[
        (df_summary["pii_email_count"] > 0)
        | (df_summary["pii_tel_count"] > 0)
        | (df_summary["pii_cc_count"] > 0)
    ][["url", "pii_email_count", "pii_tel_count", "pii_cc_count"]].rename(
        columns={
            "pii_email_count": "emails",
            "pii_tel_count": "tels",
            "pii_cc_count": "cards",
        }
    )

    overall = {
        "emails": int(df_summary["pii_email_count"].sum()),
        "tels": int(df_summary["pii_tel_count"].sum()),
        "cards": int(df_summary["pii_cc_count"].sum()),
        "pages_with_pii": int(per_page.shape[0]),
    }
    return overall, per_page


# --------- Tag inventory using external catalog ---------
def load_tag_catalog():
    """
    Try to load tag catalog from:
      - ./tag_catalog.csv OR
      - ./tag_catalog.xlsx

    Expected columns: Tag Name, Vendor, Category, Endpoints
    """
    base_dir = os.path.dirname(__file__)
    csv_path = os.path.join(base_dir, "tag_catalog.csv")
    xlsx_path = os.path.join(base_dir, "tag_catalog.xlsx")

    if os.path.exists(csv_path):
        return pd.read_csv(csv_path)
    if os.path.exists(xlsx_path):
        return pd.read_excel(xlsx_path)
    return None


TAG_CATALOG_DF = load_tag_catalog()


def build_tag_inventory(results, tag_catalog_df=None, df_summary=None):
    """
    Build SME-style Tag Inventory.

    If a catalog is available:
      - Uses endpoint patterns to map requests to tags.
      - Extracts "Accounts" (IDs) from request URLs when possible (GA4 Measurement ID,
        Adobe Report Suite, Meta Pixel ID, etc.).
    Otherwise:
      - Falls back to the simple GA4/Adobe/FB summary based on df_summary.
    """
    from urllib.parse import urlparse, parse_qs, unquote

    pages_scanned = len(results)

    # ---------- Fallback (no catalog) ----------
    if tag_catalog_df is None or tag_catalog_df.empty:
        if df_summary is None or df_summary.empty:
            by_tag = pd.DataFrame(
                columns=["tag_name", "accounts", "account_ids", "pages_without", "pages_with"]
            )
            by_page = pd.DataFrame(
                columns=["url", "tag_requests", "unique_tags", "broken_tags", "accounts", "account_ids"]
            )
            summary = {
                "pages_scanned": pages_scanned,
                "unique_tags": 0,
                "broken_tag_requests": 0,
            }
            return by_tag, by_page, summary

        total_pages = df_summary.shape[0]
        tag_defs = [
            ("Google Analytics 4", "ga4"),
            ("Adobe Analytics", "adobe"),
            ("Facebook Pixel", "fb"),
        ]
        rows = []
        for tag_name, col in tag_defs:
            if col not in df_summary.columns:
                continue
            pages_with = int(df_summary[col].sum())
            pages_without = int(total_pages - pages_with)
            rows.append(
                {
                    "tag_name": tag_name,
                    "accounts": 0,       # unknown without catalog-based parsing
                    "account_ids": "",
                    "pages_without": pages_without,
                    "pages_with": pages_with,
                }
            )

        by_tag = pd.DataFrame(rows)

        by_page = df_summary[["url"]].copy()
        by_page["tag_requests"] = 0
        by_page["unique_tags"] = (
            df_summary[["ga4", "adobe", "fb"]].sum(axis=1).astype(int)
        )
        by_page["broken_tags"] = 0
        by_page["accounts"] = 0
        by_page["account_ids"] = ""

        summary = {
            "pages_scanned": pages_scanned,
            "unique_tags": int(by_tag.shape[0]),
            "broken_tag_requests": 0,
        }
        return by_tag, by_page, summary

    # ---------- Helpers ----------
    def _extract_ids_from_url(tag_name: str, req_url: str) -> set:
        """Best-effort extraction of account / pixel / property IDs from a request URL."""
        ids = set()
        if not req_url:
            return ids

        try:
            parsed = urlparse(req_url)
            qs = parse_qs(parsed.query)
            path = parsed.path or ""
            host = (parsed.netloc or "").lower()
        except Exception:
            qs, path, host = {}, "", ""

        # Common query params used by many platforms
        common_params = ["id", "pid", "ti", "tag_id", "pixel_id", "account_id", "aid", "mid", "measurement_id", "tid"]
        for k in common_params:
            if k in qs:
                for v in qs.get(k) or []:
                    v = unquote(str(v)).strip()
                    # keep only "ID-like" values
                    if v and (re.search(r"[A-Za-z0-9_-]{4,}", v) or re.fullmatch(r"\d{6,}", v)):
                        ids.add(v)

        # GA4: Measurement ID like G-XXXXXXX often appears as tid=G-... or in URL
        if "google-analytics.com" in host or "googletagmanager.com" in host or "ga4" in tag_name.lower():
            for hit in re.findall(r"\bG-[A-Z0-9]+\b", req_url):
                ids.add(hit)
            for v in qs.get("tid", []):
                v = unquote(str(v)).strip()
                if v.startswith("G-"):
                    ids.add(v)

        # Adobe Analytics: /b/ss/<rsid>/... (report suite ID)
        if "adobe analytics" in tag_name.lower() or tag_name.lower() == "adobe analytics":
            m = re.search(r"/b/ss/([^/]+)/", req_url)
            if m:
                ids.add(m.group(1))

        # Meta/Facebook Pixel: graph.facebook.com/tr/?id=<pixel_id> or ...?id=...
        if "facebook" in tag_name.lower() or "meta" in tag_name.lower():
            for v in qs.get("id", []):
                v = unquote(str(v)).strip()
                if re.fullmatch(r"\d{6,20}", v):
                    ids.add(v)
            if ("facebook" in host or "fb" in host) and not ids:
                for hit in re.findall(r"(?<!\d)(\d{8,20})(?!\d)", req_url):
                    ids.add(hit)

        # LinkedIn Insight: px.ads.linkedin.com/collect/?pid=XXXX
        if "linkedin" in tag_name.lower():
            for v in qs.get("pid", []):
                v = unquote(str(v)).strip()
                if re.fullmatch(r"\d{4,20}", v):
                    ids.add(v)

        # Microsoft Ads (Bing UET): bat.bing.com/... ?ti=<tag_id>
        if "bing" in tag_name.lower() or "uet" in tag_name.lower() or "microsoft ads" in tag_name.lower():
            for v in qs.get("ti", []):
                v = unquote(str(v)).strip()
                if re.fullmatch(r"\d{4,20}", v):
                    ids.add(v)

        # Hotjar: static.hotjar.com/c/hotjar-<id>.js
        if "hotjar" in tag_name.lower():
            m = re.search(r"hotjar-(\d+)", req_url)
            if m:
                ids.add(m.group(1))
            for v in qs.get("hjid", []):
                v = unquote(str(v)).strip()
                if re.fullmatch(r"\d{3,20}", v):
                    ids.add(v)

        # TikTok: ...?pixel_id=... or ...?id=...
        if "tiktok" in tag_name.lower():
            for k in ["pixel_id", "id"]:
                for v in qs.get(k, []):
                    v = unquote(str(v)).strip()
                    if re.fullmatch(r"\d{4,20}", v):
                        ids.add(v)

        # Pinterest: often ?tid=...
        if "pinterest" in tag_name.lower():
            for v in qs.get("tid", []):
                v = unquote(str(v)).strip()
                if re.fullmatch(r"\d{4,20}", v):
                    ids.add(v)

        # Google Ads: AW-XXXXXXXXX sometimes appears in requests / config
        if "google ads" in tag_name.lower() or "conversion" in tag_name.lower():
            for hit in re.findall(r"\bAW-\d+\b", req_url):
                ids.add(hit)

        return ids

    # ---------- Catalog-based implementation ----------
    endpoint_map = {}
    for _, row in tag_catalog_df.iterrows():
        tag_name = str(row.get("Tag Name") or "").strip()
        endpoints = str(row.get("Endpoints") or "").strip()
        if not tag_name or not endpoints:
            continue
        patterns = [e.strip() for e in endpoints.split(";") if e.strip()]
        if not patterns:
            continue
        endpoint_map.setdefault(tag_name, []).extend(patterns)

    pages_with_tag = {tag: 0 for tag in endpoint_map.keys()}
    tag_account_ids = {tag: set() for tag in endpoint_map.keys()}

    page_rows = []
    all_tags_seen = set()
    broken_tag_requests = 0

    for p in results:
        url = p.get("url") or ""
        reqs = p.get("requests") or []

        tag_requests = []
        unique_tags_page = set()
        broken_for_page = 0

        page_account_ids = set()

        for r in reqs:
            r_url = r.get("url") or ""
            r_status = r.get("status")

            matched_tag = None
            for tag_name, patterns in endpoint_map.items():
                if any(pattern in r_url for pattern in patterns):
                    matched_tag = tag_name
                    break

            if matched_tag is None:
                continue

            tag_requests.append(matched_tag)
            unique_tags_page.add(matched_tag)

            if isinstance(r_status, int) and r_status >= 400:
                broken_for_page += 1

            ids = _extract_ids_from_url(matched_tag, r_url)
            if ids:
                tag_account_ids[matched_tag].update(ids)
                page_account_ids.update(ids)

        for t in unique_tags_page:
            pages_with_tag[t] += 1

        all_tags_seen.update(unique_tags_page)
        broken_tag_requests += broken_for_page

        page_rows.append(
            {
                "url": url,
                "# tag requests": len(tag_requests),
                "# unique tags": len(unique_tags_page),
                "# broken tags": broken_for_page,
                "Accounts": len(page_account_ids),
                "Account IDs": ", ".join(sorted(page_account_ids)) if page_account_ids else "",
            }
        )

    by_page_df = (
        pd.DataFrame(page_rows)
        if page_rows
        else pd.DataFrame(
            columns=["url", "# tag requests", "# unique tags", "# broken tags", "Accounts", "Account IDs"]
        )
    )

    total_pages = pages_scanned
    tag_rows = []
    for tag_name in sorted(endpoint_map.keys()):
        pages_with = pages_with_tag.get(tag_name, 0)
        pages_without = max(total_pages - pages_with, 0)

        ids = tag_account_ids.get(tag_name, set()) or set()
        tag_rows.append(
            {
                "Tag name": tag_name,
                "Accounts": len(ids),
                "Account IDs": ", ".join(sorted(ids)) if ids else "",
                "Pages without tags": pages_without,
                "Pages with tags": pages_with,
            }
        )

    by_tag_df = (
        pd.DataFrame(tag_rows)
        if tag_rows
        else pd.DataFrame(
            columns=[
                "Tag name",
                "Accounts",
                "Account IDs",
                "Pages without tags",
                "Pages with tags",
            ]
        )
    )

    summary = {
        "pages_scanned": pages_scanned,
        "unique_tags": int(len(all_tags_seen)),
        "broken_tag_requests": int(broken_tag_requests),
    }
    return by_tag_df, by_page_df, summary


# -----------------------------
# Streamlit config
# -----------------------------
st.set_page_config(page_title="Tag Auditor", layout="wide")

# --- Styling ---
st.markdown(
    """
<style>
/* Hide Streamlit chrome */
header[data-testid="stHeader"] { display: none !important; }
[data-testid="stToolbar"] { display: none !important; }
footer {visibility: hidden;}

/* ===== ObservePoint-like dark palette ===== */
:root{
  --bg: #101214;
  --panel: #1C1F23;
  --panel-2: #171A1D;
  --border: rgba(255,255,255,.08);
  --text: #E7EAEE;
  --muted: rgba(231,234,238,.72);
  --muted2: rgba(231,234,238,.50);
  --accent: #C9A227; /* gold underline */
}

/* App background */
[data-testid="stAppViewContainer"]{
  background: var(--bg) !important;
  color: var(--text) !important;
}

/* Keep your original page width/spacing */
.block-container{
  padding-top: 2.2rem;
  padding-bottom: 2rem;
  max-width: 1200px;
}

/* Typography */
html, body, [class*="css"]{
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
}
h1,h2,h3,h4,h5,h6{ color: var(--text) !important; }
p, span, label, div { color: var(--muted) !important; }
.stMarkdown strong{ color: var(--text) !important; }

/* ===== Header sizing (THIS fixes huge EXL) ===== */
.ti-header{
  display:flex;
  flex-direction:column;
  align-items:flex-start;
  gap: .25rem;
  margin-bottom: 1.25rem;
}
.ti-header-logo{
  height: 72px !important;
  width: auto !important;
  max-width: 280px !important;
  object-fit: contain !important;
}
.ti-header-title{
  font-size: 2.2rem;
  font-weight: 800;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--text) !important;
}
.ti-header-sub{
  font-size: .85rem;
  color: var(--muted2) !important;
}

/* ===== Tabs (same layout, dark styling) ===== */
[data-testid="stTabs"] > div{
  gap: .5rem !important;
  align-items: center;
}
[data-testid="stTabs"] button{
  flex: 0 0 auto !important;
  padding: .35rem .85rem !important;
  margin: 0 !important;
  border-radius: 0 !important;
  background: transparent !important;
  border: none !important;
  box-shadow: none !important;
  border-bottom: 2px solid transparent !important;
}
[data-testid="stTabs"] button p{
  color: var(--muted2) !important;
  font-size: .9rem !important;
}
[data-testid="stTabs"] button[aria-selected="true"]{
  border-bottom: 2px solid var(--accent) !important;
}
[data-testid="stTabs"] button[aria-selected="true"] p{
  color: var(--text) !important;
  font-weight: 600 !important;
}

/* ===== RESTORE TILE GRID LAYOUT (THIS brings tiles back) ===== */
.ta-card-grid{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1.4rem;
  margin-top: 0.4rem;
  margin-bottom: 1.4rem;
}
.ta-card{
  background: var(--panel) !important;
  border: 1px solid var(--border) !important;
  border-radius: 16px;
  padding: 1.2rem 1.3rem;
  box-shadow: 0 10px 26px rgba(0,0,0,0.35);
  display:flex;
  flex-direction:column;
  justify-content:space-between;
}
.ta-card-top{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:.75rem;
}
.ta-card-icon-wrap{
  display:flex;
  align-items:center;
  gap:.6rem;
}
.ta-card-icon{
  height: 40px;
  width: 40px;
  border-radius: 999px;
  display:flex;
  align-items:center;
  justify-content:center;
  font-size: 1.2rem;
  font-weight: 700;
  color: #fff;
  border: 1px solid rgba(255,255,255,.10);
}
.ta-pill{
  font-size: .65rem;
  text-transform: uppercase;
  letter-spacing: .16em;
  color: var(--muted2) !important;
  font-weight: 600;
}
.ta-meta{
  font-size: .65rem;
  letter-spacing: .16em;
  text-transform: uppercase;
  color: var(--muted2) !important;
}
.ta-title{
  font-size: .95rem;
  font-weight: 700;
  color: var(--text) !important;
  margin-top: .7rem;
}
.ta-subtitle{
  font-size: .75rem;
  color: var(--muted2) !important;
  margin-top: .15rem;
}

/* Your icon palette (darker, closer to sample) */
.bg-sky   { background:#0B4A6F !important; }
.bg-rose  { background:#7A0F2C !important; }
.bg-amber { background:#6B4B00 !important; }
.bg-emerald { background:#0B4E3A !important; }
.bg-indigo { background:#2C2A7A !important; }
.bg-slate { background:#111827 !important; }

/* Inputs */
div[data-testid="stTextInput"] input{
  background: var(--panel-2) !important;
  border: 1px solid var(--border) !important;
  color: var(--text) !important;
  border-radius: 10px !important;
}
div[data-testid="stTextInput"] input::placeholder{
  color: rgba(231,234,238,.35) !important;
}

/* Number inputs */
div[data-testid="stNumberInput"] input{
  background: var(--panel-2) !important;
  border: 1px solid var(--border) !important;
  color: var(--text) !important;
  border-radius: 10px !important;
}
div[data-testid="stNumberInput"] label,
div[data-testid="stNumberInput"] label p{
  color: var(--muted2) !important;
}

/* Expander */
[data-testid="stExpander"] > details{
  background: var(--panel) !important;
  border: 1px solid var(--border) !important;
  border-radius: 12px !important;
}
[data-testid="stExpander"] summary,
[data-testid="stExpander"] summary *{
  color: var(--text) !important;
  opacity: 1 !important;
}

/* Buttons (dark) */
.stButton > button{
  background: #2A2E33 !important;
  color: var(--text) !important;
  border: 1px solid var(--border) !important;
  border-radius: 10px !important;
  font-weight: 600 !important;
}
.stButton > button:hover{ background: #343941 !important; }
.stButton > button:disabled{
  background: #202327 !important;
  color: rgba(231,234,238,.40) !important;
  opacity: 1 !important;
}

/* Dataframes */
[data-testid="stDataFrame"]{
  background: var(--panel) !important;
  border: 1px solid var(--border) !important;
  border-radius: 12px !important;
  overflow: hidden;
}
</style>
    """,
    unsafe_allow_html=True,
)


# --- Load EXL logo ---
logo_path = os.path.join(os.path.dirname(__file__), "exl_logo.png")
if os.path.exists(logo_path):
    with open(logo_path, "rb") as f:
        logo_b64 = base64.b64encode(f.read()).decode("utf-8")
    EXL_LOGO_SRC = f"data:image/png;base64,{logo_b64}"
else:
    EXL_LOGO_SRC = ""

# --- Header row ---
if EXL_LOGO_SRC:
    st.markdown(
        f"""
        <div class="ti-header">
          <img src="{EXL_LOGO_SRC}" alt="EXL" class="ti-header-logo" />
          <div>
            <div class="ti-header-title">TAG AUDITOR</div>
            <div class="ti-header-sub">Web analytics &amp; tracking audit</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        """
        <div class="ti-header">
          <div class="ti-header-title">TAG AUDITOR</div>
          <div class="ti-header-sub">Web analytics &amp; tracking audit</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# -----------------------------
# Card grid helpers
# -----------------------------
COLOR_CLASSES = ["bg-sky", "bg-rose", "bg-amber", "bg-emerald", "bg-indigo", "bg-slate"]


def color_cycle(idx: int) -> str:
    return COLOR_CLASSES[idx % len(COLOR_CLASSES)]


def card_grid_html(items):
    if not items:
        return '<div style="font-size:0.75rem;color:#9ca3af;">No data.</div>'

    parts = ['<div class="ta-card-grid">']
    for it in items:
        card_html = textwrap.dedent(
            f"""
        <article class="ta-card">
          <div class="ta-card-top">
            <div class="ta-card-icon-wrap">
              <div class="ta-card-icon {it.get('icon_color','bg-slate')}">
                {it.get('icon','')}
              </div>
              <div class="ta-pill">{it.get('pill','')}</div>
            </div>
            <div class="ta-meta">{it.get('meta','')}</div>
          </div>
          <div>
            <div class="ta-title">{it.get('title','')}</div>
            <div class="ta-subtitle">{it.get('subtitle','')}</div>
          </div>
        </article>
        """
        )
        parts.append(card_html.strip("\n"))
    parts.append("</div>")
    return "\n".join(parts)


def render_card_grid(items):
    st.markdown(card_grid_html(items), unsafe_allow_html=True)


# -----------------------------
# State
# -----------------------------
if "has_results" not in st.session_state:
    st.session_state["has_results"] = False


def clear_results():
    for key in [
        "results",
        "df_summary",
        "unique_tags",
        "issues",
        "dl_events_df",
        "naming_detail_df",
        "naming_summary_df",
        "naming_total_issues",
        "pii_overall",
        "pii_per_page",
        "tag_by_tag_df",
        "tag_by_page_df",
        "ti_summary",
        "dq_summary",
        "dq_detail_df",
    ]:
        st.session_state.pop(key, None)
    st.session_state["has_results"] = False
    st.rerun()


# -----------------------------
# SCREEN 1: Landing
# -----------------------------
if not st.session_state["has_results"]:
    st.subheader("Scan your site for tracking & analytics issues.")

    col_url, col_btn = st.columns([4, 1])
    with col_url:
        start_url = st.text_input(
            "Website URL",
            value="https://example.com",
        )
    with col_btn:
        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
        run_btn = st.button("Scan site", use_container_width=True)

    with st.expander("Advanced crawl settings", expanded=False):
        col1, col2, col3 = st.columns([1, 1, 3])
        with col1:
            max_pages = st.number_input(
                "Max pages", min_value=1, max_value=500, value=10
            )
        with col2:
            max_depth = st.number_input(
                "Max depth", min_value=0, max_value=5, value=1
            )
        with col3:
            st.caption(
                "Limit how deep and how wide Tag Auditor should crawl from the start URL."
            )

    if run_btn and start_url:
        status_text = st.empty()
        status_text.info("Starting crawler...")

        crawler = Crawler(
            start_url,
            max_pages=int(max_pages),
            max_depth=int(max_depth),
            headless=True,
            auto_submit_form=True,
            auto_play_video=True,
            wait_until="load",
            auto_accept_cookies=True,
        )

        with st.spinner(
            "Crawling (time depends on site, number of pages, and depth)..."
        ):
            try:
                results = crawler.crawl()
            except Exception as e:
                st.exception(e)
                results = []

        status_text.success(f"Crawl finished: {len(results)} pages visited")

        if results:
            df_summary, unique_tags = aggregate_results(results)
            issues = derive_issues(results)
            dl_events_df = extract_datalayer_events(results)
            (
                naming_detail_df,
                naming_summary_df,
                naming_total_issues,
            ) = find_naming_issues(results)
            pii_overall, pii_per_page = build_pii_detail(df_summary)
            tag_by_tag_df, tag_by_page_df, ti_summary = build_tag_inventory(
                results,
                tag_catalog_df=TAG_CATALOG_DF,
                df_summary=df_summary,
            )
            dq_summary, dq_detail_df = build_data_quality_issues(results)

            s = st.session_state
            s["results"] = results
            s["df_summary"] = df_summary
            s["unique_tags"] = unique_tags
            s["issues"] = issues
            s["dl_events_df"] = dl_events_df
            s["naming_detail_df"] = naming_detail_df
            s["naming_summary_df"] = naming_summary_df
            s["naming_total_issues"] = naming_total_issues
            s["pii_overall"] = pii_overall
            s["pii_per_page"] = pii_per_page
            s["tag_by_tag_df"] = tag_by_tag_df
            s["tag_by_page_df"] = tag_by_page_df
            s["ti_summary"] = ti_summary
            s["dq_summary"] = dq_summary
            s["dq_detail_df"] = dq_detail_df
            s["has_results"] = True

            st.rerun()

# -----------------------------
# SCREEN 2: Dashboard
# -----------------------------
if st.session_state["has_results"]:
    results = st.session_state["results"]
    df_summary = st.session_state["df_summary"]
    unique_tags = st.session_state["unique_tags"]
    issues = st.session_state["issues"]
    dl_events_df = st.session_state["dl_events_df"]
    naming_detail_df = st.session_state["naming_detail_df"]
    naming_summary_df = st.session_state["naming_summary_df"]
    naming_total_issues = st.session_state["naming_total_issues"]
    pii_overall = st.session_state["pii_overall"]
    pii_per_page = st.session_state["pii_per_page"]
    tag_by_tag_df = st.session_state["tag_by_tag_df"]
    tag_by_page_df = st.session_state["tag_by_page_df"]
    ti_summary = st.session_state.get("ti_summary", {})
    dq_summary = st.session_state.get("dq_summary", {})
    dq_detail_df = st.session_state.get("dq_detail_df", pd.DataFrame())

    top_col1, top_col2 = st.columns([3, 1])
    with top_col1:
        st.markdown("### Audit results")
    with top_col2:
        st.button("Start new scan", on_click=clear_results)

    tabs = st.tabs(
        [
            "📊 Summary",
            "📄 Pages",
            "🚫 Broken Pages",
            "🏷️ Tag Inventory",
            "🧱 DataLayer",
            "🔐 PII Exposure",
            "🔤 Naming",
            "⚠️ Issues",
            "✅ Consent",
        ]
    )

    # ---------- SUMMARY TAB ----------
    with tabs[0]:
        pages_scanned = len(df_summary)
        avg_load_time = (
            round(df_summary["load_time"].dropna().mean(), 2)
            if "load_time" in df_summary
            and not df_summary["load_time"].dropna().empty
            else 0
        )
        broken_pages = (
            int(df_summary["status"].fillna(0).ge(400).sum())
            if "status" in df_summary
            else 0
        )
        datalayer_loaded = (
            int(df_summary["has_datalayer"].sum())
            if "has_datalayer" in df_summary
            else 0
        )
        # Prefer tag inventory's unique tag count if available
        unique_tags_count = ti_summary.get("unique_tags", len(unique_tags))
        pii_exposure_pages = (
            int(df_summary["pii_exposure"].sum())
            if "pii_exposure" in df_summary
            else 0
        )
        data_quality_issues_count = dq_summary.get("total_issues", len(issues))
        incorrect_naming_count = naming_total_issues

        consent_flag = any(
            "consent" in json.dumps(p.get("cookies") or "").lower()
            or "consent" in json.dumps(p.get("dataLayer") or "").lower()
            for p in results
        )
        consent_text = "Yes" if consent_flag else "No"

        summary_cards = [
            {
                "icon": "📄",
                "icon_color": color_cycle(0),
                "pill": "Pages scanned",
                "title": f"{pages_scanned} pages",
                "subtitle": "Unique URLs visited in this crawl.",
                "meta": "Few seconds ago",
            },
            {
                "icon": "🚫",
                "icon_color": color_cycle(1),
                "pill": "Broken pages",
                "title": f"{broken_pages} pages",
                "subtitle": "HTTP 4xx / 5xx responses.",
                "meta": "Status health",
            },
            {
                "icon": "🏷️",
                "icon_color": color_cycle(2),
                "pill": "Unique tags",
                "title": f"{unique_tags_count} tag types",
                "subtitle": "Unique vendors matched from your catalog endpoints.",
                "meta": "Implementation",
            },
            {
                "icon": "⚡",
                "icon_color": color_cycle(3),
                "pill": "Performance",
                "title": f"{avg_load_time}s avg load",
                "subtitle": "Based on Playwright navigation timing.",
                "meta": "Speed",
            },
            {
                "icon": "🔐",
                "icon_color": color_cycle(4),
                "pill": "PII exposure",
                "title": f"{pii_exposure_pages} pages",
                "subtitle": "Pages with possible email / tel / card patterns.",
                "meta": "Risk",
            },
            {
                "icon": "🧪",
                "icon_color": color_cycle(5),
                "pill": "Data quality",
                "title": f"{data_quality_issues_count} issues",
                "subtitle": "Rule-based dataLayer issues across pages.",
                "meta": "Validation",
            },
            {
                "icon": "🧱",
                "icon_color": color_cycle(0),
                "pill": "DataLayer",
                "title": f"{datalayer_loaded} pages",
                "subtitle": "Pages where window.dataLayer is present.",
                "meta": "Tracking",
            },
            {
                "icon": "🔤",
                "icon_color": color_cycle(1),
                "pill": "Naming",
                "title": f"{incorrect_naming_count} issues",
                "subtitle": "Events not in lower_snake_case.",
                "meta": "Governance",
            },
            {
                "icon": "✅",
                "icon_color": color_cycle(2),
                "pill": "Consent tracking",
                "title": consent_text,
                "subtitle": "Presence of consent strings in cookies / dataLayer.",
                "meta": "Compliance",
            },
        ]
        render_card_grid(summary_cards)

    # ---------- PAGES TAB ----------
    with tabs[1]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("Pages Scanned — Detail")

        # Use Tag Inventory per-page vendor-call counts (from tag_catalog endpoints)
        tag_page_map = {}
        if isinstance(tag_by_page_df, pd.DataFrame) and not tag_by_page_df.empty and "url" in tag_by_page_df.columns:
            tag_page_map = tag_by_page_df.set_index("url").to_dict(orient="index")

        page_cards = []
        for idx, row in df_summary.iterrows():
            url = row.get("url", "")
            status = row.get("status")
            load_time = row.get("load_time")
            has_dl = row.get("has_datalayer")
            tags = []
            if row.get("ga4"):
                tags.append("GA4")
            if row.get("adobe"):
                tags.append("Adobe")
            if row.get("fb"):
                tags.append("FB Pixel")
            tags_str = " • ".join(tags) if tags else "No analytics tags"
            tp = tag_page_map.get(url, {}) or {}
            tag_requests_count = int(tp.get("tag_requests", tp.get("# tag requests", 0)) or 0)
            unique_vendor_tags = int(tp.get("unique_tags", tp.get("# unique tags", 0)) or 0)
            broken_vendor_calls = int(tp.get("broken_tags", tp.get("# broken tags", 0)) or 0)
            subtitle = (
                f"{'DataLayer present' if has_dl else 'No dataLayer'} • "
                f"{tag_requests_count} vendor tag requests • {unique_vendor_tags} unique vendors"
            )
            meta = (
                f"{status or '-'} • {round(load_time, 2) if pd.notna(load_time) else '-'}s • "
                f"{unique_vendor_tags} vendors • {broken_vendor_calls} broken"
            )
            page_cards.append(
                {
                    "icon": "Pg",
                    "icon_color": color_cycle(idx),
                    "pill": "Page",
                    "title": url,
                    "subtitle": subtitle,
                    "meta": meta,
                }
            )
        render_card_grid(page_cards)

        st.markdown("---")
        sel = st.selectbox("Per-page deep dive", df_summary["url"].tolist())
        page_obj = next((p for p in results if p.get("url") == sel), None)
        if page_obj:
            st.markdown("**Detectors**")
            st.write(page_obj.get("detectors", {}))
            st.markdown("**dataLayer validation**")
            st.write(page_obj.get("datalayer_validation", {}))
            st.markdown("**Form audit**")
            st.write(page_obj.get("form_audit", {}))
            st.markdown("**Video audit**")
            st.write(page_obj.get("video_audit", {}))
            st.markdown("**Cookies (sample)**")
            st.write((page_obj.get("cookies") or [])[:20])
            st.markdown("**Requests (sample)**")
            st.write((page_obj.get("requests") or [])[:40])
            st.markdown("**HTML (truncated)**")
            st.code((page_obj.get("html") or "")[:2000])

    # ---------- BROKEN PAGES ----------
    with tabs[2]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("Broken Pages — Detail")
        broken_df = df_summary[df_summary["status"].fillna(0) >= 400]
        if broken_df.empty:
            st.info("No broken pages (HTTP >= 400) detected.")
        else:
            st.dataframe(broken_df[["url", "status", "load_time", "page_size_kb"]])

    # ---------- TAG INVENTORY ----------
    with tabs[3]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("Tag Inventory — Detail")

        ti_pages = ti_summary.get("pages_scanned", len(df_summary))
        ti_unique = ti_summary.get("unique_tags", 0)
        ti_broken = ti_summary.get("broken_tag_requests", 0)

        m1, m2, m3 = st.columns(3)
        m1.metric("Pages scanned", ti_pages)
        m2.metric("Unique tags", ti_unique)
        m3.metric("Broken tag requests", ti_broken)

        st.markdown("### Pages with or without tags")
        st.dataframe(tag_by_tag_df, use_container_width=True)

        st.markdown("### Pages scanned — tag activity")
        st.dataframe(tag_by_page_df, use_container_width=True)

    # ---------- DATALAYER ----------
    with tabs[4]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("DataLayer Loaded — Detail")
        if dl_events_df.empty:
            st.info("No dataLayer events detected.")
        else:
            st.dataframe(dl_events_df)

    # ---------- PII ----------
    with tabs[5]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("PII Exposure — Detail")
        st.markdown(
            f"- **Total email matches:** {pii_overall['emails']}  \n"
            f"- **Total tel: matches:** {pii_overall['tels']}  \n"
            f"- **Total credit-card pattern matches:** {pii_overall['cards']}  \n"
            f"- **Pages with possible PII:** {pii_overall['pages_with_pii']}"
        )
        st.markdown("**Per-page PII summary**")
        st.dataframe(pii_per_page, use_container_width=True)

    # ---------- NAMING ----------
    with tabs[6]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("Incorrect Naming Conventions — Detail")
        st.metric("Total naming issues", naming_total_issues)
        st.markdown("**By event name**")
        st.dataframe(naming_summary_df, use_container_width=True)
        st.markdown("**Event occurrences**")
        st.dataframe(naming_detail_df, use_container_width=True)

    # ---------- ISSUES / DATA QUALITY ----------
    with tabs[7]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("Data Quality Issues — Detail")

        c1, c2, c3 = st.columns(3)
        c1.metric("Pages scanned", dq_summary.get("pages_scanned", len(df_summary)))
        c2.metric(
            "DataLayer loaded",
            dq_summary.get("datalayer_loaded", int(df_summary["has_datalayer"].sum())),
        )
        c3.metric("Total data quality issues", dq_summary.get("total_issues", 0))

        st.markdown("### Value quality issues (dataLayer parameters)")
        if dq_detail_df.empty:
            st.info("No dataLayer value issues detected based on current rules.")
        else:
            st.dataframe(dq_detail_df, use_container_width=True)

        st.markdown("---")
        st.markdown("### Technical rule-based issues")
        if not issues:
            st.success("No issues detected based on current rules.")
        else:
            st.dataframe(pd.DataFrame(issues), use_container_width=True)

    # ---------- CONSENT ----------
    with tabs[8]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("Advanced Consent Tracking — Detail")
        rows = []
        for p in results:
            url = p.get("url")
            cookies_str = json.dumps(p.get("cookies") or {})
            dl_str = json.dumps(p.get("dataLayer") or {})
            has_consent = (
                "consent" in cookies_str.lower() or "consent" in dl_str.lower()
            )
            if has_consent:
                rows.append(
                    {
                        "url": url,
                        "cookies_sample": cookies_str[:200],
                        "datalayer_sample": dl_str[:200],
                    }
                )
        consent_df = (
            pd.DataFrame(rows)
            if rows
            else pd.DataFrame(columns=["url", "cookies_sample", "datalayer_sample"])
        )
        if consent_df.empty:
            st.info("No explicit consent strings detected in cookies or dataLayer.")
        else:
            st.dataframe(consent_df, use_container_width=True)

    # Export section
    st.markdown("---")
    st.subheader("Export results")
    csv_buf = StringIO()
    df_summary.to_csv(csv_buf, index=False)
    csv_bytes = csv_buf.getvalue().encode()
    st.download_button(
        "Download summary CSV",
        data=csv_bytes,
        file_name="scan_results_summary.csv",
        mime="text/csv",
    )
    json_bytes = json.dumps(results, indent=2).encode()
    st.download_button(
        "Download raw JSON",
        data=json_bytes,
        file_name="scan_results_raw.json",
        mime="application/json",
    )
