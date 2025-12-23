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
PHONE_RE = re.compile(r"\b[0-9]{10}\b")
EVENT_NAME_OK_RE = re.compile(r"^[a-z0-9_]+$")  # lower_snake_case


# -----------------------------
# Helpers: aggregation & issues
# -----------------------------
def aggregate_results(results):
    rows = []
    unique_tags = set()

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

        # simple PII scan
        pii_email_count = 0
        pii_phone_count = 0
        for r in p.get("requests", []):
            url_r = r.get("url") or ""
            pii_email_count += len(EMAIL_RE.findall(url_r))
            pii_phone_count += len(PHONE_RE.findall(url_r))
        if p.get("dataLayer") is not None:
            dl_str = json.dumps(p["dataLayer"])
            pii_email_count += len(EMAIL_RE.findall(dl_str))
            pii_phone_count += len(PHONE_RE.findall(dl_str))
        pii_exposure = pii_email_count > 0 or pii_phone_count > 0

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
                "pii_phone_count": pii_phone_count,
            }
        )

    df = pd.DataFrame(rows)
    return df, unique_tags


def derive_issues(results):
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

        pii_email_count = 0
        pii_phone_count = 0
        for r in p.get("requests", []):
            url_r = r.get("url") or ""
            pii_email_count += len(EMAIL_RE.findall(url_r))
            pii_phone_count += len(PHONE_RE.findall(url_r))
        if p.get("dataLayer") is not None:
            dl_str = json.dumps(p["dataLayer"])
            pii_email_count += len(EMAIL_RE.findall(dl_str))
            pii_phone_count += len(PHONE_RE.findall(dl_str))

        if pii_email_count > 0 or pii_phone_count > 0:
            issues.append(
                {
                    "type": "pii_exposure",
                    "severity": "high",
                    "url": url,
                    "details": f"Possible PII found (emails={pii_email_count}, phones={pii_phone_count})",
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


def build_pii_detail(df_summary):
    if df_summary.empty:
        overall = {"emails": 0, "phones": 0, "pages_with_pii": 0}
        per_page = pd.DataFrame(columns=["url", "emails", "phones"])
        return overall, per_page

    per_page = df_summary[
        (df_summary["pii_email_count"] > 0) | (df_summary["pii_phone_count"] > 0)
    ][["url", "pii_email_count", "pii_phone_count"]].rename(
        columns={"pii_email_count": "emails", "pii_phone_count": "phones"}
    )

    overall = {
        "emails": int(df_summary["pii_email_count"].sum()),
        "phones": int(df_summary["pii_phone_count"].sum()),
        "pages_with_pii": int(per_page.shape[0]),
    }
    return overall, per_page


def build_tag_inventory(df_summary):
    if df_summary.empty:
        by_tag = pd.DataFrame(columns=["tag_name", "pages_with", "pages_without"])
        by_page = pd.DataFrame(columns=["url", "ga4", "adobe", "fb"])
        return by_tag, by_page

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
                "pages_with": pages_with,
                "pages_without": pages_without,
            }
        )
    by_tag = pd.DataFrame(rows)
    by_page = df_summary[["url", "ga4", "adobe", "fb"]].copy()
    return by_tag, by_page


# -----------------------------
# Streamlit config
# -----------------------------
st.set_page_config(page_title="Tag Auditor", layout="wide")

# --- Styling ---
st.markdown(
    """
    <style>
    header[data-testid="stHeader"] { display: none !important; }
    [data-testid="stToolbar"] { display: none !important; }
    footer {visibility: hidden;}

    [data-testid="stAppViewContainer"] {
        background: #f3f4f6;
    }

    .block-container {
        padding-top: 2.2rem;
        padding-bottom: 2rem;
        max-width: 1200px;
    }

    .ti-header {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 0.25rem;
        margin-bottom: 1.25rem;
    }
    .ti-header-logo {
        height: 72px;
        width: auto;
    }
    .ti-header-title {
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        color: #111827;
    }
    .ti-header-sub {
        font-size: 0.85rem;
        color: #6b7280;
        margin-left: 0.1rem;
    }

    .ti-section-card {
        background:#ffffff;
        border-radius: 14px;
        padding:0.85rem 1.1rem;
        border:1px solid #e5e7eb;
        box-shadow:0 6px 18px rgba(15,23,42,0.08);
        margin-top:0.5rem;
        color:#111827;
    }

    [data-testid="stExpander"] > details {
        background:#ffffff;
        border-radius: 12px;
        border:1px solid #e5e7eb;
        color:#111827;
    }
    [data-testid="stExpander"] summary {
        color:#111827;
        font-size:0.9rem;
    }

    /* Tabs tweak */
    [data-testid="stTabs"] button {
        border-radius: 999px !important;
        padding: 0.35rem 0.9rem !important;
        font-size: 0.85rem !important;
    }

    /* Card grid */
    .ta-card-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        gap: 1.4rem;
        margin-top: 0.4rem;
    }
    .ta-card {
        background: #ffffff;
        border-radius: 16px;
        padding: 1.2rem 1.3rem;
        border: 1px solid #e5e7eb;
        box-shadow: 0 10px 26px rgba(15,23,42,0.08);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .ta-card-top {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 0.75rem;
    }
    .ta-card-icon-wrap {
        display: flex;
        align-items: center;
        gap: 0.6rem;
    }
    .ta-card-icon {
        height: 40px;
        width: 40px;
        border-radius: 999px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.2rem;
        font-weight: 600;
        color: #fff;
    }
    .ta-pill {
        font-size: 0.65rem;
        text-transform: uppercase;
        letter-spacing: 0.16em;
        color: #9ca3af;
    }
    .ta-meta {
        font-size: 0.65rem;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        color: #9ca3af;
    }
    .ta-title {
        font-size: 0.95rem;
        font-weight: 600;
        color: #111827;
        margin-top: 0.7rem;
    }
    .ta-subtitle {
        font-size: 0.75rem;
        color: #6b7280;
        margin-top: 0.15rem;
    }

    .bg-sky   { background:#0284c7; }
    .bg-rose  { background:#e11d48; }
    .bg-amber { background:#f59e0b; }
    .bg-emerald { background:#059669; }
    .bg-indigo { background:#4f46e5; }
    .bg-slate { background:#111827; }

    /* make URL input white & clean */
    div[data-testid="stTextInput"] input {
        background-color: #ffffff !important;
        border: 1px solid #d1d5db !important;
        border-radius: 10px !important;
        color: #111827 !important;
    }
    div[data-testid="stTextInput"] input:focus {
        border-color: #2563eb !important;
        box-shadow: 0 0 0 1px #2563eb inset !important;
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
    """items: list of dicts with keys icon, icon_color, pill, title, subtitle, meta"""
    if not items:
        return '<div style="font-size:0.75rem;color:#9ca3af;">No data.</div>'

    parts = ['<div class="ta-card-grid">']
    for it in items:
        card_html = textwrap.dedent(f"""
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
        """)
        parts.append(card_html.strip("\n"))
    parts.append("</div>")
    return "\n".join(parts)




def render_card_grid(items):
    # IMPORTANT: markdown with unsafe_allow_html -> renders, not raw text
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
    ]:
        st.session_state.pop(key, None)
    st.session_state["has_results"] = False
    st.rerun()


# -----------------------------
# SCREEN 1: Landing
# -----------------------------
if not st.session_state["has_results"]:
    # Short, clean intro (no long paragraph)
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
            tag_by_tag_df, tag_by_page_df = build_tag_inventory(df_summary)

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
        st.markdown('<div class="ti-section-card">', unsafe_allow_html=True)

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
        pii_exposure_pages = (
            int(df_summary["pii_exposure"].sum())
            if "pii_exposure" in df_summary
            else 0
        )
        data_quality_issues_count = len(issues)
        unique_tags_count = len(unique_tags)
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
                "subtitle": "GA4 / Adobe / FB pixels detected.",
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
                "subtitle": "Pages with possible email / phone patterns.",
                "meta": "Risk",
            },
            {
                "icon": "🧪",
                "icon_color": color_cycle(5),
                "pill": "Data quality",
                "title": f"{data_quality_issues_count} issues",
                "subtitle": "Rule-based issues across pages.",
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

        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- PAGES TAB ----------
    with tabs[1]:
        st.markdown('<div class="ti-section-card">', unsafe_allow_html=True)
        st.subheader("Pages Scanned — Detail")

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
            subtitle = f"{'DataLayer present' if has_dl else 'No dataLayer'} • {tags_str}"
            meta = f"{status or '-'} • {round(load_time, 2) if pd.notna(load_time) else '-'}s"

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

        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- BROKEN PAGES ----------
    with tabs[2]:
        st.markdown('<div class="ti-section-card">', unsafe_allow_html=True)
        st.subheader("Broken Pages — Detail")
        broken_df = df_summary[df_summary["status"].fillna(0) >= 400]
        if broken_df.empty:
            st.info("No broken pages (HTTP >= 400) detected.")
        else:
            st.dataframe(broken_df[["url", "status", "load_time", "page_size_kb"]])
        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- TAG INVENTORY ----------
    with tabs[3]:
        st.markdown('<div class="ti-section-card">', unsafe_allow_html=True)
        st.subheader("Tag Inventory — Detail")

        st.markdown("**By tag**")
        st.dataframe(tag_by_tag_df)

        st.markdown("**By page**")
        st.dataframe(tag_by_page_df)
        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- DATALAYER ----------
    with tabs[4]:
        st.markdown('<div class="ti-section-card">', unsafe_allow_html=True)
        st.subheader("DataLayer Loaded — Detail")
        if dl_events_df.empty:
            st.info("No dataLayer events detected.")
        else:
            st.dataframe(dl_events_df)
        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- PII ----------
    with tabs[5]:
        st.markdown('<div class="ti-section-card">', unsafe_allow_html=True)
        st.subheader("PII Exposure — Detail")
        st.markdown(
            f"- **Total email matches:** {pii_overall['emails']}  \n"
            f"- **Total phone matches:** {pii_overall['phones']}  \n"
            f"- **Pages with possible PII:** {pii_overall['pages_with_pii']}"
        )
        st.markdown("**Per-page PII summary**")
        st.dataframe(pii_per_page)
        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- NAMING ----------
    with tabs[6]:
        st.markdown('<div class="ti-section-card">', unsafe_allow_html=True)
        st.subheader("Incorrect Naming Conventions — Detail")
        st.metric("Total naming issues", naming_total_issues)
        st.markdown("**By event name**")
        st.dataframe(naming_summary_df)
        st.markdown("**Event occurrences**")
        st.dataframe(naming_detail_df)
        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- ISSUES ----------
    with tabs[7]:
        st.markdown('<div class="ti-section-card">', unsafe_allow_html=True)
        st.subheader("Data Quality Issues — Detail")
        if not issues:
            st.success("No issues detected based on current rules.")
        else:
            st.dataframe(pd.DataFrame(issues))
        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- CONSENT ----------
    with tabs[8]:
        st.markdown('<div class="ti-section-card">', unsafe_allow_html=True)
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
            st.dataframe(consent_df)
        st.markdown("</div>", unsafe_allow_html=True)

    # Export section
    st.markdown(
        '<div class="ti-section-card" style="margin-top:0.6rem;">',
        unsafe_allow_html=True,
    )
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
    st.markdown("</div>", unsafe_allow_html=True)
