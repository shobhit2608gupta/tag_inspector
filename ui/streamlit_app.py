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

import os, sys, subprocess
import streamlit as st

import os, sys, subprocess
import streamlit as st

@st.cache_resource(show_spinner=False)
def ensure_playwright_browsers():
    """
    Streamlit Cloud cannot run sudo, so never use --with-deps at runtime.
    System deps must be provided via packages.txt.
    """
    try:
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/home/appuser/.cache/ms-playwright")

        # Only install the browser binaries (no sudo)
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    except Exception:
        pass

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
# Credit card pattern: 4 digits - 4 digits - 4 digits - 4 digits (16 total)
CREDIT_CARD_RE = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
# Google Consent Signal (GCS) detection
GCS_RE = re.compile(r"[?&]gcs=([A-Z0-9]+)")

# --- Extended PII patterns (SME) ---
# Phone numbers beyond tel: scheme (E.164-ish / common formats)
PHONE_RE = re.compile(r"(?:\+?\d[\d\s().-]{6,}\d)")
# IPv4 addresses (potential pseudonymous identifier)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# US SSN (basic)
SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b")
# Hex-hash like strings (md5/sha1/sha256) often used for hashed email/phone
HEX_HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.IGNORECASE)

# Keys that commonly carry user identifiers / PII into GA (SME-provided examples)
PII_KEY_HINTS = {
    "email", "e_mail", "signup_email",
    "phone", "phone_number", "mobile", "tel", "telephone",
    "first_name", "firstname", "fname",
    "last_name", "lastname", "lname",
    "profile_name", "user_name", "username",
    "user_id", "userid", "uid", "cid",
    "customer_id", "customerid", "customer_number", "customernumber",
    "membership_id", "membershipid",
    "user_pseudo_id", "userpseudoid",
    "ip", "ip_address", "client_ip",
    "gps", "lat", "latitude", "lon", "lng", "longitude",
    "ssn",
}

# URL/Event parameter keys that indicate PII transmission vectors
URL_PII_KEYS = {
    "page_location", "page_path", "page_referrer",
    "link_url", "video_url", "form_destination",
}

# Event parameter keys indicating user data
EVENT_PII_KEYS = {
    "link_url", "video_url", "form_destination",
    "page_location", "page_path", "page_referrer",
}

# Search box parameters
SEARCH_PII_KEYS = {
    "search_term", "search_query", "search_box",
}

# Form submission parameters indicating user data
FORM_PII_KEYS = {
    "email", "e_mail", "signup_email", "user_email",
    "phone", "phone_number", "mobile", "tel", "telephone",
    "first_name", "firstname", "fname",
    "last_name", "lastname", "lname",
    "user_id", "userid", "uid",
    "customer_id", "customerid", "customer_number",
    "membership_id", "membershipid",
    "profile_name", "user_name", "username",
}

# Cookie ID parameters
COOKIE_PII_KEYS = {
    "user_pseudo_id", "userpseudoid",
}

def _normalize_digits(s: str) -> str:
    return re.sub(r"\D+", "", s or "")

def _luhn_ok(number: str) -> bool:
    """Luhn checksum for credit cards; reduces false positives."""
    digits = _normalize_digits(number)
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    alt = False
    for ch in reversed(digits):
        if not ch.isdigit():
            return False
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0

def _key_has_hint(key: str, hint_set=PII_KEY_HINTS) -> bool:
    k = (key or "").strip().lower()
    if not k:
        return False
    # check segments for dotted keys like ep.user_data.email
    parts = re.split(r"[^a-z0-9_]+", k)
    return any(p in hint_set for p in parts if p)

def _is_valid_email(email: str) -> bool:
    """Check if email has proper format: @ followed by domain with letters."""
    if "@" not in email:
        return False
    parts = email.split("@")
    if len(parts) != 2:
        return False
    local, domain = parts
    # Ensure domain has at least one letter and a dot
    if not re.search(r"[a-zA-Z]", domain) or "." not in domain:
        return False
    # Reject version-like patterns (e.g., @2.14.0)
    if re.match(r"^\d+\.\d+", domain):
        return False
    return True

def _is_valid_phone(phone: str) -> bool:
    """Check if phone has valid format: MUST have tel: prefix or start with +"""
    phone_lower = phone.lower()
    # STRICT: Must have tel: prefix or start with +
    if "tel:" in phone_lower:
        return True
    if phone.startswith("+"):
        return True
    # Reject anything else (no tel: and no +)
    return False

def _count_phone_matches(text: str) -> int:
    """Count phone number matches in text using PHONE_RE."""
    if not text:
        return 0
    count = 0
    for m in PHONE_RE.findall(text):
        digits = _normalize_digits(m)
        if 7 <= len(digits) <= 15:
            if _is_valid_phone(m):
                count += 1
    return count

def _count_hash_if_pii_key(key: str, val: str) -> dict:
    """If key indicates email/phone and value looks hashed, count it as exposure."""
    out = {"email_hash": 0, "phone_hash": 0}
    if not key or not val:
        return out
    k = key.lower()
    v = str(val)
    if HEX_HASH_RE.search(v):
        if "email" in k:
            out["email_hash"] += 1
        if "phone" in k or "mobile" in k or "tel" in k:
            out["phone_hash"] += 1
    return out

def _detect_consent_status(cookies: dict, datalayer: dict) -> str:
    """Detect consent status from cookies or dataLayer.
    Returns: 'given' or 'denied'
    
    Default is 'denied' (conservative/privacy-protective):
    - If no consent evidence found → denied (assume no consent)
    - If explicit denial found → denied
    - Only if explicit consent given → given
    """
    cookies_str = json.dumps(cookies).lower() if cookies else ""
    dl_str = json.dumps(datalayer).lower() if datalayer else ""
    
    # Check for EXPLICIT consent given (only then return 'given')
    if ("consent" in cookies_str and "true" in cookies_str) or \
       ("consent" in dl_str and "true" in dl_str) or \
       ("consent_status" in cookies_str and "accepted" in cookies_str) or \
       ("consent_status" in dl_str and "accepted" in dl_str):
        return "given"
    
    # Everything else defaults to 'denied' (no explicit consent found = denied)
    return "denied"

def _detect_gcs_violations(requests: list) -> dict:
    """
    Detect Google Consent Signal (GCS) violations.
    
    GCS Rules (SME feedback):
    - GCS=G100 (consent denied): email, phone, cid, uid MUST be blank/undefined
    - GCS=G111 (consent given): These parameters CAN have values
    
    Returns:
    {
        'gcs_detected': bool,
        'gcs_value': 'G100'/'G111'/None,
        'gcs_status': 'denied'/'given'/None,
        'violations': [list of violations],
        'violation_count': int,
        'violated_urls': [list of URLs with violations]
    }
    """
    result = {
        'gcs_detected': False,
        'gcs_value': None,
        'gcs_status': None,
        'violations': [],
        'violation_count': 0,
        'violated_urls': []
    }
    
    # PII parameters to check
    pii_params = {'email', 'phone', 'cid', 'uid', 'user_id', 'userid', 'user_pseudo_id'}
    
    for req in requests or []:
        url = req.get("url", "")
        
        # Look for GCS parameter
        gcs_match = GCS_RE.search(url)
        if not gcs_match:
            continue
        
        gcs_value = gcs_match.group(1)
        result['gcs_detected'] = True
        result['gcs_value'] = gcs_value
        
        # Determine if consent is denied (G100) or given (G111)
        is_denied = gcs_value == "G100"
        result['gcs_status'] = 'denied' if is_denied else 'given'
        
        # If GCS=G100 (denied), check for PII parameters
        if is_denied:
            for param in pii_params:
                # Check if parameter exists and has a value
                if f"{param}=" in url:
                    # Extract parameter value
                    param_match = re.search(f"{param}=([^&]*)", url)
                    if param_match:
                        param_value = param_match.group(1)
                        # Only flag if value is not empty or blank
                        if param_value and param_value not in ("", "undefined", "null"):
                            violation = f"GCS=G100 (denied) but {param}={param_value[:30]}"
                            result['violations'].append(violation)
                            if url not in result['violated_urls']:
                                result['violated_urls'].append(url[:80])
    
    result['violation_count'] = len(result['violations'])
    return result

def _extract_user_id_from_page(p: dict) -> dict:
    """Extract user_id values from form submissions or events.
    Returns dict with: {
        'user_id_value': value if found,
        'source': 'form'/'event'/'unknown',
        'found': True/False
    }
    """
    result = {
        'user_id_value': None,
        'source': 'unknown',
        'found': False
    }
    
    # Check dataLayer for user_id (common in form events)
    datalayer = p.get("dataLayer") or {}
    if isinstance(datalayer, list):
        for item in datalayer:
            if isinstance(item, dict):
                if "user_id" in item:
                    result['user_id_value'] = item["user_id"]
                    result['source'] = 'event'
                    result['found'] = True
                    return result
    elif isinstance(datalayer, dict):
        if "user_id" in datalayer:
            result['user_id_value'] = datalayer["user_id"]
            result['source'] = 'event'
            result['found'] = True
            return result
    
    # Check form audit data
    form_audit = p.get("form_audit") or {}
    if form_audit.get("success"):
        # If form was submitted successfully, flag user_id capture
        result['source'] = 'form'
        result['found'] = True
        result['user_id_value'] = "FORM_SUBMITTED"
    
    return result

def _analyze_form_pii_leakage(p: dict) -> dict:
    """
    Enhanced Form Audit: Compare what was entered in form vs what leaked to analytics.
    
    Returns dict with:
    {
        'form_filled': True/False,
        'form_submitted': True/False,
        'entered_data': {field_name: value, ...},
        'form_fields': [list of fields],
        'leaked_data': {field_name: [leaked_values], ...},
        'leakage_detected': {field_name: True/False, ...},
        'risky_leakage': [list of field names with leakage],
        'pii_entered': {email, phone, name, ...},
        'pii_leaked': {email, phone, ...}
    }
    """
    result = {
        'form_filled': False,
        'form_submitted': False,
        'entered_data': {},
        'form_fields': [],
        'leaked_data': {},
        'leakage_detected': {},
        'risky_leakage': [],
        'pii_entered': set(),
        'pii_leaked': set()
    }
    
    # Get form audit data
    form_audit = p.get("form_audit") or {}
    
    if not form_audit.get("attempted"):
        return result
    
    result['form_filled'] = True
    result['form_submitted'] = form_audit.get("success", False)
    result['entered_data'] = form_audit.get("entered_data", {})
    result['form_fields'] = form_audit.get("form_fields", [])
    
    # Track what PII was entered
    for field_name, field_value in result['entered_data'].items():
        field_name_lower = str(field_name).lower()
        if 'email' in field_name_lower:
            result['pii_entered'].add(('email', field_value))
        elif 'phone' in field_name_lower or 'tel' in field_name_lower:
            result['pii_entered'].add(('phone', field_value))
        elif 'name' in field_name_lower:
            result['pii_entered'].add(('name', field_value))
    
    # Now check what leaked to network/dataLayer
    requests = p.get("requests") or []
    datalayer = p.get("dataLayer") or {}
    
    # Check requests for entered data
    for req in requests:
        url = req.get("url", "")
        for field_name, field_value in result['entered_data'].items():
            # Check if form value appears in URL
            if field_value and field_value in url:
                if field_name not in result['leaked_data']:
                    result['leaked_data'][field_name] = []
                result['leaked_data'][field_name].append({
                    'source': 'network_request',
                    'url': url[:100]
                })
                result['leakage_detected'][field_name] = True
                
                # Track leaked PII
                field_name_lower = str(field_name).lower()
                if 'email' in field_name_lower:
                    result['pii_leaked'].add(('email', field_value))
                elif 'phone' in field_name_lower or 'tel' in field_name_lower:
                    result['pii_leaked'].add(('phone', field_value))
                elif 'name' in field_name_lower:
                    result['pii_leaked'].add(('name', field_value))
    
    # Check dataLayer for entered data
    if isinstance(datalayer, dict):
        datalayer_str = json.dumps(datalayer).lower()
        for field_name, field_value in result['entered_data'].items():
            if field_value and field_value.lower() in datalayer_str:
                if field_name not in result['leaked_data']:
                    result['leaked_data'][field_name] = []
                result['leaked_data'][field_name].append({
                    'source': 'datalayer',
                    'detected': True
                })
                result['leakage_detected'][field_name] = True
    
    # Identify risky leakage (PII that shouldn't leak)
    risky_fields = {'email', 'phone', 'password', 'email_hash', 'phone_hash'}
    for field_name in result['leakage_detected']:
        field_name_lower = str(field_name).lower()
        if any(risky in field_name_lower for risky in risky_fields):
            result['risky_leakage'].append(field_name)
    
    return result

def scan_pii_in_url(url: str) -> dict:
    """Scan URL + its query params for PII. Returns counts and actual values by type."""
    counts = {
        "emails": 0,
        "phones": 0,
        "email_hash": 0,
        "phone_hash": 0,
        "cards": 0,
        "ids": 0,
        "ips": 0,
        "ssn": 0,
        "url_pii": 0,  # URLs containing PII (page_location, page_path, page_referrer, etc.)
        "event_pii": 0,  # Event parameters with PII
        "search_pii": 0,  # Search box parameters
        "form_pii": 0,  # Form submission parameters
        "cookie_id": 0,  # Cookie ID parameters
    }
    # Store actual detected values
    values = {
        "emails": [],
        "phones": [],
        "email_hash": [],
        "phone_hash": [],
        "cards": [],
        "ids": [],
        "ips": [],
        "ssn": [],
    }
    if not url:
        counts["values"] = values
        return counts

    # 1) Raw URL string patterns
    for m in EMAIL_RE.findall(url):
        if _is_valid_email(m):  # Filter with strict validation
            counts["emails"] += 1
            values["emails"].append(m)
    
    for m in TEL_SCHEME_RE.findall(url):
        counts["phones"] += 1
        values["phones"].append(m)
    
    for m in PHONE_RE.findall(url):
        if _is_valid_phone(m):  # Filter with strict validation
            digits = _normalize_digits(m)
            if 7 <= len(digits) <= 15:
                counts["phones"] += 1
                values["phones"].append(m)
    
    for m in IPV4_RE.findall(url):
        counts["ips"] += 1
        values["ips"].append(m)
    
    for m in SSN_RE.findall(url):
        counts["ssn"] += 1
        values["ssn"].append(m)

    # 2) Query parameter semantic scan
    try:
        parsed = up.urlsplit(url)
        q = up.parse_qs(parsed.query, keep_blank_values=True)
        for k, vals in q.items():
            k_l = (k or "").lower()
            
            # Check for specific PII transmission vectors
            if k_l in URL_PII_KEYS:
                for v in vals:
                    if v and str(v).strip():
                        counts["url_pii"] += 1
            
            if k_l in EVENT_PII_KEYS:
                for v in vals:
                    if v and str(v).strip():
                        counts["event_pii"] += 1
            
            if k_l in SEARCH_PII_KEYS:
                for v in vals:
                    if v and str(v).strip():
                        # Check if search term contains email/phone
                        v_str = str(v)
                        if EMAIL_RE.search(v_str) or _count_phone_matches(v_str) > 0:
                            counts["search_pii"] += 1
            
            if k_l in FORM_PII_KEYS:
                for v in vals:
                    if v and str(v).strip():
                        counts["form_pii"] += 1
            
            if k_l in COOKIE_PII_KEYS:
                for v in vals:
                    if v and str(v).strip():
                        counts["cookie_id"] += 1
            
            if _key_has_hint(k_l):
                # treat any non-empty value as an identifier leak at least
                for v in vals:
                    if v is None:
                        continue
                    v_str = str(v)
                    if v_str.strip():
                        counts["ids"] += 1
                        values["ids"].append(f"{k}={v_str[:50]}")  # Store key=value pair
                    # hashed email/phone signals
                    hh = _count_hash_if_pii_key(k_l, v_str)
                    if hh["email_hash"] > 0:
                        counts["email_hash"] += hh["email_hash"]
                        values["email_hash"].append(f"{k}={v_str[:50]}")
                    if hh["phone_hash"] > 0:
                        counts["phone_hash"] += hh["phone_hash"]
                        values["phone_hash"].append(f"{k}={v_str[:50]}")
                    # direct patterns inside values
                    for m in EMAIL_RE.findall(v_str):
                        if _is_valid_email(m):  # Strict validation
                            counts["emails"] += 1
                            values["emails"].append(m)
                    for m in PHONE_RE.findall(v_str):
                        if _is_valid_phone(m):  # Strict validation
                            digits = _normalize_digits(m)
                            if 7 <= len(digits) <= 15:
                                counts["phones"] += 1
                                values["phones"].append(m)
                    for m in IPV4_RE.findall(v_str):
                        counts["ips"] += 1
                        values["ips"].append(m)
                    for m in SSN_RE.findall(v_str):
                        counts["ssn"] += 1
                        values["ssn"].append(m)
            else:
                # even without key hints, still catch explicit emails
                for v in vals:
                    v_str = str(v)
                    for m in EMAIL_RE.findall(v_str):
                        if _is_valid_email(m):  # Strict validation
                            counts["emails"] += 1
                            values["emails"].append(m)
    except Exception:
        pass

    # 3) Credit cards (validate with Luhn)
    for m in CREDIT_CARD_RE.findall(url):
        if _luhn_ok(m):
            counts["cards"] += 1
            values["cards"].append(m[:4] + "****" + m[-4:])  # Mask for security

    counts["values"] = values
    return counts

def scan_pii_in_json(obj) -> dict:
    """Recursively scan JSON-like structures for PII."""
    counts = {
        "emails": 0,
        "phones": 0,
        "email_hash": 0,
        "phone_hash": 0,
        "cards": 0,
        "ids": 0,
        "ips": 0,
        "ssn": 0,
        "url_pii": 0,
        "event_pii": 0,
        "search_pii": 0,
        "form_pii": 0,
        "cookie_id": 0,
    }
    # Store actual detected values
    values = {
        "emails": [],
        "phones": [],
        "email_hash": [],
        "phone_hash": [],
        "cards": [],
        "ids": [],
        "ips": [],
        "ssn": [],
    }

    def walk(x, parent_key=""):
        if x is None:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                k_str = str(k) if k is not None else ""
                k_l = k_str.lower()
                
                # Check for specific PII transmission vectors
                if k_l in URL_PII_KEYS:
                    if v is not None and str(v).strip():
                        counts["url_pii"] += 1
                
                if k_l in EVENT_PII_KEYS:
                    if v is not None and str(v).strip():
                        counts["event_pii"] += 1
                
                if k_l in SEARCH_PII_KEYS:
                    if v is not None and str(v).strip():
                        v_str = str(v)
                        if EMAIL_RE.search(v_str) or _count_phone_matches(v_str) > 0:
                            counts["search_pii"] += 1
                
                if k_l in FORM_PII_KEYS:
                    if v is not None and str(v).strip():
                        counts["form_pii"] += 1
                
                if k_l in COOKIE_PII_KEYS:
                    if v is not None and str(v).strip():
                        counts["cookie_id"] += 1
                
                # key-based identifier detection
                if _key_has_hint(k_str):
                    if v is not None and str(v).strip():
                        counts["ids"] += 1
                        values["ids"].append(f"{k_str}={str(v)[:50]}")
                    hh = _count_hash_if_pii_key(k_str.lower(), str(v))
                    if hh["email_hash"] > 0:
                        counts["email_hash"] += hh["email_hash"]
                        values["email_hash"].append(f"{k_str}={str(v)[:50]}")
                    if hh["phone_hash"] > 0:
                        counts["phone_hash"] += hh["phone_hash"]
                        values["phone_hash"].append(f"{k_str}={str(v)[:50]}")
                walk(v, k_str)
            return
        if isinstance(x, list):
            for it in x:
                walk(it, parent_key)
            return

        # scalar
        s = str(x)
        for m in EMAIL_RE.findall(s):
            if _is_valid_email(m):  # Strict validation
                counts["emails"] += 1
                values["emails"].append(m)
        
        for m in TEL_SCHEME_RE.findall(s):
            counts["phones"] += 1
            values["phones"].append(m)
        
        for m in PHONE_RE.findall(s):
            if _is_valid_phone(m):  # Strict validation
                digits = _normalize_digits(m)
                if 7 <= len(digits) <= 15:
                    counts["phones"] += 1
                    values["phones"].append(m)
        
        for m in IPV4_RE.findall(s):
            counts["ips"] += 1
            values["ips"].append(m)
        
        for m in SSN_RE.findall(s):
            counts["ssn"] += 1
            values["ssn"].append(m)
        
        for m in CREDIT_CARD_RE.findall(s):
            if _luhn_ok(m):
                counts["cards"] += 1
                values["cards"].append(m[:4] + "****" + m[-4:])  # Mask for security

    walk(obj)
    counts["values"] = values
    return counts

# -----------------------------
# Helpers: PII scanning
# -----------------------------
def scan_pii_in_text(text: str):
    """Return (email_count, tel_count, cc_count) in a single text blob.
    Note: tel_count includes broader phone detection (not only tel: scheme).
    Credit-card matches are Luhn-validated to reduce false positives.
    """
    if not text:
        return 0, 0, 0
    email_count = len(EMAIL_RE.findall(text))
    tel_count = len(TEL_SCHEME_RE.findall(text)) + _count_phone_matches(text)
    cc_count = 0
    for m in CREDIT_CARD_RE.findall(text):
        if _luhn_ok(m):
            cc_count += 1
    return email_count, tel_count, cc_count


def scan_pii_for_page(p: dict):
    """Scan network requests + dataLayer only, for PII patterns.

    SME-driven enhancements:
      - Detect emails/phones in URL query params and common GA event params (page_location/page_path/page_referrer, etc.)
      - Detect hashed email/phone when the parameter key indicates email/phone (e.g., user_data.email)
      - Detect other identifiers (user_id, uid, cid, customer_id, user_pseudo_id, etc.) in params/dataLayer
      - Validate credit-card patterns using Luhn
      - Also flags IPv4 + SSN patterns (stored on the page dict for reporting / future UI use)
      - NEW: Categorizes PII by transmission vector (URLs, event parameters, search, forms, cookie IDs)
      - NEW: Tracks hashed email/phone separately
      - NEW: Detects consent denial violations (user_pseudo_id sent despite consent denied)
      - NEW: Stores actual detected values for detailed reporting
    """
    totals = {
        "emails": 0,
        "phones": 0,
        "email_hash": 0,
        "phone_hash": 0,
        "cards": 0,
        "ids": 0,
        "ips": 0,
        "ssn": 0,
        "url_pii": 0,
        "event_pii": 0,
        "search_pii": 0,
        "form_pii": 0,
        "cookie_id": 0,
    }
    all_values = {
        "emails": [],
        "phones": [],
        "email_hash": [],
        "phone_hash": [],
        "cards": [],
        "ids": [],
        "ips": [],
        "ssn": [],
    }

    # Network requests URLs
    for r in p.get("requests", []):
        url_r = r.get("url") or ""
        c = scan_pii_in_url(url_r)
        for k in totals:
            totals[k] += int(c.get(k, 0))
        # Collect actual values
        vals = c.get("values", {})
        for key in all_values:
            if vals and key in vals:
                all_values[key].extend(vals[key])

    # dataLayer payloads (structured scan)
    if p.get("dataLayer") is not None:
        c = scan_pii_in_json(p.get("dataLayer"))
        for k in totals:
            totals[k] += int(c.get(k, 0))
        # Collect actual values
        vals = c.get("values", {})
        for key in all_values:
            if vals and key in vals:
                all_values[key].extend(vals[key])

    # Store all counters and values on page object for detailed reporting
    p["pii_id_count"] = totals["ids"]
    p["pii_ip_count"] = totals["ips"]
    p["pii_ssn_count"] = totals["ssn"]
    p["pii_email_hash_count"] = totals["email_hash"]
    p["pii_phone_hash_count"] = totals["phone_hash"]
    p["pii_url_count"] = totals["url_pii"]
    p["pii_event_count"] = totals["event_pii"]
    p["pii_search_count"] = totals["search_pii"]
    p["pii_form_count"] = totals["form_pii"]
    p["pii_cookie_id_count"] = totals["cookie_id"]
    
    # Store deduplicated actual values
    p["pii_emails"] = list(set(all_values["emails"]))
    p["pii_phones"] = list(set(all_values["phones"]))
    p["pii_email_hashes"] = list(set(all_values["email_hash"]))
    p["pii_phone_hashes"] = list(set(all_values["phone_hash"]))
    p["pii_cards"] = list(set(all_values["cards"]))
    p["pii_ids"] = list(set(all_values["ids"]))
    p["pii_ips"] = list(set(all_values["ips"]))
    p["pii_ssns"] = list(set(all_values["ssn"]))

    # Detect consent status
    cookies = p.get("cookies") or {}
    datalayer = p.get("dataLayer") or {}
    consent_status = _detect_consent_status(cookies, datalayer)
    p["consent_status"] = consent_status
    
    # Detect Google Consent Signal (GCS) violations
    gcs_analysis = _detect_gcs_violations(p.get("requests", []))
    p["gcs_analysis"] = gcs_analysis
    
    # Extract user_id information
    user_id_info = _extract_user_id_from_page(p)
    p["user_id_value"] = user_id_info['user_id_value']
    p["user_id_source"] = user_id_info['source']
    p["user_id_found"] = user_id_info['found']
    
    # Flag: user_id captured without consent
    user_id_without_consent = user_id_info['found'] and consent_status == 'denied'
    p["user_id_without_consent"] = user_id_without_consent

    # Detect consent denial violation: user_pseudo_id sent despite consent denied
    has_cookie_id = totals["cookie_id"] > 0
    cookies_str = json.dumps(cookies).lower()
    dl_str = json.dumps(datalayer).lower()
    
    # Check if consent is explicitly denied
    consent_denied = (
        ("consent" in cookies_str and "false" in cookies_str) or
        ("consent" in dl_str and "false" in dl_str) or
        ("consent_status" in cookies_str and "denied" in cookies_str) or
        ("consent_status" in dl_str and "denied" in dl_str)
    )
    p["pii_consent_denial_violation"] = has_cookie_id and consent_denied

    # Keep backwards-compatible tuple used by current UI
    return totals["emails"], totals["phones"], totals["cards"]


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

        # Analyze form PII leakage
        form_pii_analysis = _analyze_form_pii_leakage(p)
        p["form_pii_analysis"] = form_pii_analysis

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
                "pii_email_hash_count": int(p.get("pii_email_hash_count", 0) or 0),
                "pii_phone_hash_count": int(p.get("pii_phone_hash_count", 0) or 0),
                "pii_id_count": int(p.get("pii_id_count", 0) or 0),
                "pii_ip_count": int(p.get("pii_ip_count", 0) or 0),
                "pii_ssn_count": int(p.get("pii_ssn_count", 0) or 0),
                "pii_url_count": int(p.get("pii_url_count", 0) or 0),
                "pii_event_count": int(p.get("pii_event_count", 0) or 0),
                "pii_search_count": int(p.get("pii_search_count", 0) or 0),
                "pii_form_count": int(p.get("pii_form_count", 0) or 0),
                "pii_cookie_id_count": int(p.get("pii_cookie_id_count", 0) or 0),
                "pii_consent_denial_violation": bool(p.get("pii_consent_denial_violation", False)),
                "consent_status": p.get("consent_status", "unknown"),
                "user_id_captured": "Yes" if p.get("user_id_found", False) else "No",
                "user_id_value": str(p.get("user_id_value", "")) if p.get("user_id_value") else "",
                "user_id_source": p.get("user_id_source", "unknown"),
                "user_id_without_consent": bool(p.get("user_id_without_consent", False)),
                # Store actual detected PII values - ensure lists are converted to strings
                "pii_emails": "; ".join([str(x) for x in (p.get("pii_emails") or [])[:10]]) if p.get("pii_emails") else "",
                "pii_phones": "; ".join([str(x) for x in (p.get("pii_phones") or [])[:10]]) if p.get("pii_phones") else "",
                "pii_cards": "; ".join([str(x) for x in (p.get("pii_cards") or [])[:10]]) if p.get("pii_cards") else "",
                "pii_ips": "; ".join([str(x) for x in (p.get("pii_ips") or [])[:10]]) if p.get("pii_ips") else "",
                "pii_ids": "; ".join([str(x) for x in (p.get("pii_ids") or [])[:10]]) if p.get("pii_ids") else "",
                "pii_ssns": "; ".join([str(x) for x in (p.get("pii_ssns") or [])[:10]]) if p.get("pii_ssns") else "",
                "pii_email_hashes": "; ".join([str(x) for x in (p.get("pii_email_hashes") or [])[:5]]) if p.get("pii_email_hashes") else "",
                "pii_phone_hashes": "; ".join([str(x) for x in (p.get("pii_phone_hashes") or [])[:5]]) if p.get("pii_phone_hashes") else "",
                # Form audit analysis
                "form_filled": p.get("form_pii_analysis", {}).get("form_filled", False),
                "form_submitted": p.get("form_pii_analysis", {}).get("form_submitted", False),
                "form_entered_data": json.dumps(p.get("form_pii_analysis", {}).get("entered_data", {})),
                "form_leaked_fields": "; ".join(p.get("form_pii_analysis", {}).get("risky_leakage", [])),
                "form_risky_leakage_count": len(p.get("form_pii_analysis", {}).get("risky_leakage", [])),
                # GCS (Google Consent Signal) analysis
                "gcs_detected": p.get("gcs_analysis", {}).get("gcs_detected", False),
                "gcs_value": p.get("gcs_analysis", {}).get("gcs_value", ""),
                "gcs_violation_count": p.get("gcs_analysis", {}).get("violation_count", 0),
                "gcs_violations": "; ".join(p.get("gcs_analysis", {}).get("violations", [])[:3]),
            }
        )

    df = pd.DataFrame(rows)
    # Compute an aggregate `pii_count` column so downstream code can rely on it.
    # Prefer explicit numeric count columns if present, otherwise fall back
    # to checking the string PII columns for presence.
    if not df.empty:
        possible_count_cols = [
            'pii_email_count', 'pii_tel_count', 'pii_cc_count', 'pii_id_count',
            'pii_ip_count', 'pii_ssn_count', 'pii_url_count', 'pii_event_count',
            'pii_search_count', 'pii_form_count', 'pii_cookie_id_count'
        ]
        count_cols = [c for c in possible_count_cols if c in df.columns]
        if count_cols:
            df['pii_count'] = df[count_cols].sum(axis=1).astype(int)
        else:
            # Fallback: treat non-empty string fields as 1
            fallback_cols = [c for c in ['pii_emails', 'pii_phones', 'pii_cards', 'pii_ids', 'pii_ips', 'pii_ssns'] if c in df.columns]
            if fallback_cols:
                df['pii_count'] = df[fallback_cols].fillna('').astype(bool).sum(axis=1).astype(int)
            else:
                df['pii_count'] = 0
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
    Build overall + per-page PII stats based on columns:
      - pii_email_count, pii_tel_count, pii_cc_count
      - pii_email_hash_count, pii_phone_hash_count (hashed PII)
      - pii_id_count, pii_ip_count, pii_ssn_count (extended identifiers)
      - pii_url_count, pii_event_count, pii_search_count, pii_form_count, pii_cookie_id_count (transmission vectors)
      - pii_consent_denial_violation (compliance risk)
    """
    if df_summary.empty:
        overall = {
            "emails": 0,
            "tels": 0,
            "email_hash": 0,
            "phone_hash": 0,
            "cards": 0,
            "ids": 0,
            "ips": 0,
            "ssn": 0,
            "url_pii": 0,
            "event_pii": 0,
            "search_pii": 0,
            "form_pii": 0,
            "cookie_id": 0,
            "pages_with_pii": 0,
            "consent_violations": 0,
        }
        per_page = pd.DataFrame(columns=[
            "url", "emails", "tels", "cards", "email_hash", "phone_hash", "ids", "ips", "ssn",
            "url_pii", "event_pii", "search_pii", "form_pii", "cookie_id", "consent_violation"
        ])
        return overall, per_page

    per_page = df_summary[
        (df_summary["pii_email_count"] > 0)
        | (df_summary["pii_tel_count"] > 0)
        | (df_summary["pii_cc_count"] > 0)
        | (df_summary.get("pii_id_count", 0) > 0)
        | (df_summary.get("pii_ip_count", 0) > 0)
        | (df_summary.get("pii_ssn_count", 0) > 0)
        | (df_summary.get("pii_email_hash_count", 0) > 0)
        | (df_summary.get("pii_phone_hash_count", 0) > 0)
        | (df_summary.get("pii_url_count", 0) > 0)
        | (df_summary.get("pii_event_count", 0) > 0)
        | (df_summary.get("pii_search_count", 0) > 0)
        | (df_summary.get("pii_form_count", 0) > 0)
        | (df_summary.get("pii_cookie_id_count", 0) > 0)
        | (df_summary.get("pii_consent_denial_violation", False))
    ][
        ["url", "pii_email_count", "pii_tel_count", "pii_cc_count", "pii_email_hash_count", "pii_phone_hash_count", 
         "pii_id_count", "pii_ip_count", "pii_ssn_count", "pii_url_count", "pii_event_count", "pii_search_count", 
         "pii_form_count", "pii_cookie_id_count", "pii_consent_denial_violation"]
    ].rename(
        columns={
            "pii_email_count": "emails",
            "pii_tel_count": "tels",
            "pii_cc_count": "cards",
            "pii_email_hash_count": "email_hash",
            "pii_phone_hash_count": "phone_hash",
            "pii_id_count": "ids",
            "pii_ip_count": "ips",
            "pii_ssn_count": "ssn",
            "pii_url_count": "url_pii",
            "pii_event_count": "event_pii",
            "pii_search_count": "search_pii",
            "pii_form_count": "form_pii",
            "pii_cookie_id_count": "cookie_id",
            "pii_consent_denial_violation": "consent_violation",
        }
    )

    overall = {
        "emails": int(df_summary["pii_email_count"].sum()),
        "tels": int(df_summary["pii_tel_count"].sum()),
        "cards": int(df_summary["pii_cc_count"].sum()),
        "email_hash": int(df_summary.get("pii_email_hash_count", pd.Series(dtype=int)).sum()) if "pii_email_hash_count" in df_summary.columns else 0,
        "phone_hash": int(df_summary.get("pii_phone_hash_count", pd.Series(dtype=int)).sum()) if "pii_phone_hash_count" in df_summary.columns else 0,
        "ids": int(df_summary.get("pii_id_count", pd.Series(dtype=int)).sum()) if "pii_id_count" in df_summary.columns else 0,
        "ips": int(df_summary.get("pii_ip_count", pd.Series(dtype=int)).sum()) if "pii_ip_count" in df_summary.columns else 0,
        "ssn": int(df_summary.get("pii_ssn_count", pd.Series(dtype=int)).sum()) if "pii_ssn_count" in df_summary.columns else 0,
        "url_pii": int(df_summary.get("pii_url_count", pd.Series(dtype=int)).sum()) if "pii_url_count" in df_summary.columns else 0,
        "event_pii": int(df_summary.get("pii_event_count", pd.Series(dtype=int)).sum()) if "pii_event_count" in df_summary.columns else 0,
        "search_pii": int(df_summary.get("pii_search_count", pd.Series(dtype=int)).sum()) if "pii_search_count" in df_summary.columns else 0,
        "form_pii": int(df_summary.get("pii_form_count", pd.Series(dtype=int)).sum()) if "pii_form_count" in df_summary.columns else 0,
        "cookie_id": int(df_summary.get("pii_cookie_id_count", pd.Series(dtype=int)).sum()) if "pii_cookie_id_count" in df_summary.columns else 0,
        "pages_with_pii": int(per_page.shape[0]),
        "consent_violations": int(df_summary.get("pii_consent_denial_violation", pd.Series(dtype=bool)).sum()) if "pii_consent_denial_violation" in df_summary.columns else 0,
        "user_id_without_consent": int(df_summary.get("user_id_without_consent", pd.Series(dtype=bool)).sum()) if "user_id_without_consent" in df_summary.columns else 0,
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

    # Add dual consent mode toggle
    st.write("---")
    col_consent1, col_consent2 = st.columns([1, 3])
    with col_consent1:
        dual_consent_mode = st.checkbox(
            "🔄 Dual Consent Mode",
            value=False,
            help="Run scan twice: once with consent DENIED (GCS=G100) and once ACCEPTED (GCS=G111). Compare PII leakage."
        )
    with col_consent2:
        if dual_consent_mode:
            st.info("📊 Will scan twice to compare PII leakage with/without consent")

    if run_btn and start_url:
        status_text = st.empty()
        
        # Dual consent scanning
        if dual_consent_mode:
            status_text.info("🔄 Starting DUAL CONSENT scanning (Deny → Accept)...")
            
            results_denied = None
            results_accepted = None
            
            # First scan: Consent DENIED (GCS=G100)
            with st.spinner("Step 1/2: Scanning with consent DENIED (GCS=G100)..."):
                try:
                    crawler_denied = Crawler(
                        start_url,
                        max_pages=int(max_pages),
                        max_depth=int(max_depth),
                        headless=True,
                        auto_submit_form=True,
                        auto_play_video=True,
                        wait_until="load",
                        auto_accept_cookies=True,
                        gcs_mode="G100",  # CONSENT DENIED
                    )
                    results_denied = crawler_denied.crawl()
                    st.success(f"✓ Consent DENIED scan: {len(results_denied)} pages")
                except Exception as e:
                    st.error(f"Error in consent DENIED scan: {e}")
                    results_denied = []
            
            # Second scan: Consent ACCEPTED (GCS=G111)
            with st.spinner("Step 2/2: Scanning with consent ACCEPTED (GCS=G111)..."):
                try:
                    crawler_accepted = Crawler(
                        start_url,
                        max_pages=int(max_pages),
                        max_depth=int(max_depth),
                        headless=True,
                        auto_submit_form=True,
                        auto_play_video=True,
                        wait_until="load",
                        auto_accept_cookies=True,
                        gcs_mode="G111",  # CONSENT ACCEPTED
                    )
                    results_accepted = crawler_accepted.crawl()
                    st.success(f"✓ Consent ACCEPTED scan: {len(results_accepted)} pages")
                except Exception as e:
                    st.error(f"Error in consent ACCEPTED scan: {e}")
                    results_accepted = []
            
            # Store comparison data in session (kept separate for comparison tab)
            st.session_state.results_g100 = results_denied
            st.session_state.results_g111 = results_accepted
            st.session_state.dual_consent_comparison = True
            
            # For other tabs: Use only the G111 (accepted) results to avoid duplicate URLs
            # The comparison is handled separately in the Consent Comparison tab
            results = results_accepted or []
            status_text.success(f"✅ Dual consent scan complete: {len(results_denied or [])} pages (denied) + {len(results_accepted or [])} pages (accepted)")
        
        else:
            # Normal single scan
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
            st.session_state.dual_consent_comparison = False

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

    tab_labels = [
        "📊 Summary",
        "📄 Pages",
        "🚫 Broken Pages",
        "🏷️ Tag Inventory",
        "🧱 DataLayer",
        "🔐 PII Exposure",
        "📝 Form Audit",
        "🔤 Naming",
        "⚠️ Issues",
        "✅ Consent",
    ]
    
    # Add dual consent comparison tab if enabled
    if st.session_state.get("dual_consent_comparison"):
        tab_labels.append("🔄 Consent Comparison")
    
    tabs = st.tabs(tab_labels)

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
        
        # Consent violation warning
        if pii_overall.get('consent_violations', 0) > 0:
            st.warning(
                f"⚠️ **Compliance Risk**: {pii_overall['consent_violations']} page(s) have user IDs/cookies "
                f"transmitted to GA despite consent being denied. This violates privacy regulations.",
                icon="🚨"
            )
        
        # User ID without consent warning
        if pii_overall.get('user_id_without_consent', 0) > 0:
            st.warning(
                f"🚨 **Privacy Violation**: {pii_overall['user_id_without_consent']} page(s) captured UserID "
                f"without user consent. This is a direct privacy/GDPR violation.",
                icon="🚨"
            )
        
        # Summary metrics in columns for organization
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Email matches", pii_overall['emails'])
            st.metric("Hashed emails", pii_overall['email_hash'])
            st.metric("Phone matches", pii_overall['tels'])
        
        with c2:
            st.metric("Hashed phones", pii_overall['phone_hash'])
            st.metric("Credit-card matches", pii_overall['cards'])
            st.metric("User IDs/Customer IDs", pii_overall['ids'])
        
        with c3:
            st.metric("IP addresses", pii_overall['ips'])
            st.metric("SSNs", pii_overall['ssn'])
            st.metric("Pages with PII", pii_overall['pages_with_pii'])
        
        with c4:
            st.metric("Search terms with PII", pii_overall['search_pii'])
            st.metric("Consent violations", pii_overall.get('consent_violations', 0))
            st.metric("❌ UserID without consent", pii_overall.get('user_id_without_consent', 0))
        
        # PII transmission vectors breakdown
        st.markdown("---")
        st.markdown("### PII Transmission Vectors")
        
        t1, t2, t3, t4 = st.columns(4)
        with t1:
            st.info(f"**URLs/Paths**\n{pii_overall['url_pii']} instances", icon="🔗")
        with t2:
            st.info(f"**Event Parameters**\n{pii_overall['event_pii']} instances", icon="📊")
        with t3:
            st.info(f"**Search Terms**\n{pii_overall['search_pii']} instances", icon="🔍")
        with t4:
            st.info(f"**Cookie IDs**\n{pii_overall['cookie_id']} instances", icon="🍪")
        
        st.markdown("---")
        st.markdown("**Detected PII Details — By Page**")
        
        # Create a detailed view of detected PII values
        if not df_summary.empty:
            # Columns to display with actual detected values (PII only - no consent tracking here)
            pii_detail_cols = ["url", 
                              "pii_emails", "pii_phones", "pii_cards", 
                              "pii_ips", "pii_ssns", "pii_ids", "pii_email_hashes", "pii_phone_hashes"]
            
            # Check which columns exist
            available_cols = [col for col in pii_detail_cols if col in df_summary.columns]
            
            if available_cols and len(available_cols) > 1:  # At least URL + one data column
                pii_detail_df = df_summary[available_cols].copy()
                
                # Filter to only pages with PII detected (non-empty strings)
                has_pii = pd.Series(False, index=pii_detail_df.index)
                
                # Check for any PII values
                for col in ["pii_emails", "pii_phones", "pii_cards", "pii_ips", "pii_ssns", "pii_ids", "pii_email_hashes", "pii_phone_hashes"]:
                    if col in pii_detail_df.columns:
                        has_pii = has_pii | (pii_detail_df[col].astype(str).str.strip().str.len() > 0)
                
                pii_detail_df = pii_detail_df[has_pii].reset_index(drop=True)
                
                if not pii_detail_df.empty:
                    # Rename columns for better readability
                    rename_map = {
                        "pii_emails": "📧 Emails",
                        "pii_phones": "☎️ Phone Numbers",
                        "pii_cards": "💳 Credit Cards (Masked)",
                        "pii_ips": "🌐 IP Addresses",
                        "pii_ssns": "🔢 SSNs",
                        "pii_ids": "👤 User/Customer IDs",
                        "pii_email_hashes": "🔐 Hashed Emails",
                        "pii_phone_hashes": "🔐 Hashed Phones",
                    }
                    pii_detail_df = pii_detail_df.rename(columns=rename_map)
                    
                    st.dataframe(pii_detail_df, use_container_width=True, height=400)
                else:
                    # Fallback: show counts table if no detailed values
                    st.info("📊 Showing PII counts per page (detailed values table):")
                    st.dataframe(pii_per_page, use_container_width=True)
            else:
                st.info("📋 Per-page PII summary")
                st.dataframe(pii_per_page, use_container_width=True)

    # ---------- FORM AUDIT ----------
    with tabs[6]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("Form Auto-Fill & PII Leakage Detection")
        
        # Count forms with leakage
        forms_with_leakage = df_summary[df_summary["form_risky_leakage_count"] > 0] if "form_risky_leakage_count" in df_summary.columns else pd.DataFrame()
        forms_attempted = df_summary[df_summary["form_filled"] == True] if "form_filled" in df_summary.columns else pd.DataFrame()
        forms_success = df_summary[df_summary["form_submitted"] == True] if "form_submitted" in df_summary.columns else pd.DataFrame()
        
        # Metrics
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Forms Detected", len(forms_attempted))
        with c2:
            st.metric("Forms Submitted", len(forms_success))
        with c3:
            st.metric("PII Leakage Cases", len(forms_with_leakage))
        with c4:
            st.metric("Risky Fields Leaked", 
                     int(df_summary["form_risky_leakage_count"].sum()) if "form_risky_leakage_count" in df_summary.columns else 0)
        
        st.markdown("---")
        st.markdown("### What Happens:")
        st.info("""
        ✅ **Auto-Fill Process**:
        1. Detects form fields (email, phone, name, password)
        2. Fills with test data (testuser@example.com, +15551234567, etc.)
        3. Submits the form
        4. Monitors network traffic after submission
        
        🚨 **PII Leakage Detection**:
        - Tracks what data was entered in the form
        - Checks if that data appears in:
          - Network requests to analytics (GA, Facebook)
          - DataLayer events
          - Browser cookies
        - Flags "risky" fields (email, phone, password) if leaked
        """)
        
        st.markdown("---")
        st.markdown("### Forms with Detected PII Leakage")
        
        if not df_summary.empty and "form_risky_leakage_count" in df_summary.columns:
            # Filter to pages with forms and leakage
            form_audit_df = df_summary[
                (df_summary["form_filled"] == True) & 
                (df_summary["form_risky_leakage_count"] > 0)
            ][["url", "form_filled", "form_submitted", "form_risky_leakage_count", "form_leaked_fields"]].copy()
            
            if not form_audit_df.empty:
                form_audit_df = form_audit_df.rename(columns={
                    "form_filled": "Form Auto-Filled",
                    "form_submitted": "Form Submitted",
                    "form_risky_leakage_count": "🚨 Risky Fields Leaked",
                    "form_leaked_fields": "Leaked Field Names"
                })
                st.dataframe(form_audit_df, use_container_width=True, height=400)
            else:
                st.success("✅ No forms with PII leakage detected!")
        else:
            st.info("No form data collected yet. Run scan with auto-fill enabled.")
        
        st.markdown("---")
        st.markdown("### Detailed Form Audit Per Page")
        
        # Show detailed form data for pages with forms
        for idx, row in df_summary.iterrows():
            if row.get("form_filled", False):
                with st.expander(f"📝 {row['url'][:60]}..."):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Form Status**")
                        st.write(f"- Filled: {'✅' if row.get('form_filled') else '❌'}")
                        st.write(f"- Submitted: {'✅' if row.get('form_submitted') else '❌'}")
                        st.write(f"- Risky Leaks: {row.get('form_risky_leakage_count', 0)}")
                    with col2:
                        st.write("**Leaked Fields**")
                        if row.get('form_leaked_fields'):
                            for field in str(row['form_leaked_fields']).split(';'):
                                if field.strip():
                                    st.write(f"- 🚨 {field.strip()}")
                    
                    # Show entered data
                    try:
                        entered_data = json.loads(row.get('form_entered_data', '{}'))
                        if entered_data:
                            st.write("**Test Data Entered**")
                            for field, value in entered_data.items():
                                # Mask sensitive data
                                if 'password' in str(field).lower():
                                    display_value = "***REDACTED***"
                                else:
                                    display_value = value
                                st.write(f"- {field}: `{display_value}`")
                    except:
                        pass

    # ---------- NAMING ----------
    with tabs[7]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("Incorrect Naming Conventions — Detail")
        st.metric("Total naming issues", naming_total_issues)
        st.markdown("**By event name**")
        st.dataframe(naming_summary_df, use_container_width=True)
        st.markdown("**Event occurrences**")
        st.dataframe(naming_detail_df, use_container_width=True)

    # ---------- ISSUES / DATA QUALITY ----------
    with tabs[8]:
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
    with tabs[9]:
        st.caption("← Use the **Summary** tab above to go back.")
        st.subheader("Consent Status & Compliance — Detail")
        
        st.markdown("""
        ### Understanding Consent Status & GCS:
        - **🟢 Given**: User explicitly allowed analytics/tracking
        - **🔴 Denied**: User explicitly rejected or no consent found (default = denied for privacy)
        - **⚠️ Violation**: Data tracked despite denied consent (GDPR violation)
        
        ### Google Consent Signal (GCS) Rules:
        - **GCS=G100** (consent denied): email, phone, cid, uid MUST be blank/undefined
        - **GCS=G111** (consent given): These parameters CAN have values
        - **🚨 GCS Violation**: Sensitive parameters sent despite GCS=G100
        """)
        
        # Build consent tracking table
        consent_rows = []
        for p in results:
            url = p.get("url")
            consent_status = p.get("consent_status", "denied")
            
            # Check for violations
            user_id_without_consent = p.get("user_id_without_consent", False)
            pii_consent_denial_violation = p.get("pii_consent_denial_violation", False)
            
            # GCS violations
            gcs_analysis = p.get("gcs_analysis", {})
            gcs_violation_count = gcs_analysis.get("violation_count", 0)
            
            # Collect PII if found
            pii_emails = p.get("pii_emails", [])
            pii_phones = p.get("pii_phones", [])
            pii_ids = p.get("pii_ids", [])
            
            # Form submitted
            form_audit = p.get("form_audit") or {}
            form_submitted = form_audit.get("success", False)
            
            consent_rows.append({
                "url": url,
                "Consent Status": "🟢 Given" if consent_status == "given" else "🔴 Denied",
                "Form Submitted": "✅ Yes" if form_submitted else "❌ No",
                "PII Detected": len(pii_emails) + len(pii_phones) + len(pii_ids),
                "User ID Tracked": "✅ Yes" if pii_ids else "❌ No",
                "🚨 UserID Without Consent": "🚨 VIOLATION" if user_id_without_consent else "✓ OK",
                "🚨 PII Cookie Violation": "🚨 VIOLATION" if pii_consent_denial_violation else "✓ OK",
                "🚨 GCS Violation": f"🚨 {gcs_violation_count}" if gcs_violation_count > 0 else "✓ OK",
            })
        
        if consent_rows:
            consent_df = pd.DataFrame(consent_rows)
            
            # Summary metrics
            given_count = len([r for r in consent_rows if "Given" in r["Consent Status"]])
            denied_count = len([r for r in consent_rows if "Denied" in r["Consent Status"]])
            user_id_violations = len([r for r in consent_rows if "VIOLATION" in r["🚨 UserID Without Consent"]])
            pii_violations = len([r for r in consent_rows if "VIOLATION" in r["🚨 PII Cookie Violation"]])
            gcs_violations = len([r for r in consent_rows if "VIOLATION" not in r.get("🚨 GCS Violation", "✓ OK")])
            
            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                st.metric("Pages with Consent Given", given_count)
            with col2:
                st.metric("Pages with Consent Denied", denied_count)
            with col3:
                st.metric("🚨 UserID Violations", user_id_violations)
            with col4:
                st.metric("🚨 PII Cookie Violations", pii_violations)
            with col5:
                st.metric("🚨 GCS Violations", gcs_violations)
            
            st.markdown("---")
            st.markdown("### Consent Summary Per Page")
            st.dataframe(consent_df, use_container_width=True, height=400)
            
            # Detailed breakdown
            st.markdown("---")
            st.markdown("### Detailed Analysis")
            
            # Show violations
            violations_found = False
            
            for idx, row in consent_df.iterrows():
                has_violation = ("VIOLATION" in row.get("🚨 UserID Without Consent", "")) or \
                               ("VIOLATION" in row.get("🚨 PII Cookie Violation", "")) or \
                               ("VIOLATION" not in row.get("🚨 GCS Violation", "✓ OK"))
                
                if has_violation:
                    violations_found = True
                    with st.expander(f"🚨 {row['url'][:60]}... — VIOLATION DETECTED"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write("**Status**")
                            st.write(f"- Consent: {row['Consent Status']}")
                            st.write(f"- Form Submitted: {row['Form Submitted']}")
                            st.write(f"- PII Detected: {row['PII Detected']}")
                        with col2:
                            st.write("**Violations**")
                            if "VIOLATION" in row.get("🚨 UserID Without Consent", ""):
                                st.write("🚨 UserID tracked without consent")
                            if "VIOLATION" in row.get("🚨 PII Cookie Violation", ""):
                                st.write("🚨 PII cookies sent without consent")
                            if "VIOLATION" not in row.get("🚨 GCS Violation", "✓ OK"):
                                st.write(f"🚨 GCS Violation: {row['🚨 GCS Violation']}")
                        
                        # Get detailed data from original result
                        p = results[idx]
                        pii_emails = p.get("pii_emails", [])
                        pii_phones = p.get("pii_phones", [])
                        pii_ids = p.get("pii_ids", [])
                        
                        # GCS violations
                        gcs_analysis = p.get("gcs_analysis", {})
                        gcs_violations = gcs_analysis.get("violations", [])
                        
                        if pii_emails or pii_phones or pii_ids:
                            st.write("**PII Leaked:**")
                            if pii_emails:
                                st.write(f"- Emails: {', '.join(pii_emails[:3])}")
                            if pii_phones:
                                st.write(f"- Phones: {', '.join(pii_phones[:3])}")
                            if pii_ids:
                                st.write(f"- IDs: {', '.join(pii_ids[:3])}")
                        
                        if gcs_violations:
                            st.write("**Google Consent Signal (GCS) Violations:**")
                            for violation in gcs_violations[:3]:
                                st.write(f"- {violation}")
                        
                        st.warning("⚠️ This violates GDPR. User data should not be tracked when consent is denied.", icon="🚨")
            
            if not violations_found:
                st.success("✅ No compliance violations detected! Data tracking respects user consent.")
        else:
            st.info("No consent data found in scan results.")

    # ---------- DUAL CONSENT COMPARISON TAB ----------
    if st.session_state.get("dual_consent_comparison"):
        with tabs[10]:
            st.subheader("🔄 Dual Consent Comparison: PII Leakage with/without Consent")
            
            results_g100 = st.session_state.get("results_g100", [])
            results_g111 = st.session_state.get("results_g111", [])
            
            if not results_g100 or not results_g111:
                st.warning("Comparison data not available. Please run a dual consent scan.")
            else:
                # Process both scans
                df_g100, _ = aggregate_results(results_g100)
                df_g111, _ = aggregate_results(results_g111)
                
                st.write("**Comparison Overview**")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("📊 Pages (Consent Denied)", len(df_g100))
                with col2:
                    st.metric("📊 Pages (Consent Accepted)", len(df_g111))
                with col3:
                    st.metric("🔄 Total Scans", len(df_g100) + len(df_g111))
                
                # Compare PII Leakage
                st.write("---")
                st.markdown("### PII Leakage Comparison")
                
                # Extract PII metrics (robust to missing columns)
                def extract_pii_metrics(df):
                    """Extract PII leakage metrics from dataframe safely.

                    Prefers explicit count columns (e.g. `pii_email_count`) when
                    available, otherwise falls back to checking the string/value
                    columns (e.g. `pii_emails`). Computes total pages with any
                    PII by checking available count columns or the `pii_exposure`
                    boolean column.
                    """
                    if df is None or df.empty:
                        return {
                            'emails_leaked': 0,
                            'phones_leaked': 0,
                            'cards_leaked': 0,
                            'ips_leaked': 0,
                            'ssns_leaked': 0,
                            'ids_leaked': 0,
                            'total_pii_pages': 0,
                        }

                    def _count_by_countcol(df, col_name, fallback_col=None):
                        if col_name in df.columns:
                            return int((df[col_name] > 0).sum())
                        if fallback_col and fallback_col in df.columns:
                            # non-empty string values
                            return int(df[fallback_col].astype(bool).sum())
                        return 0

                    emails = _count_by_countcol(df, 'pii_email_count', 'pii_emails')
                    phones = _count_by_countcol(df, 'pii_tel_count', 'pii_phones')
                    cards = _count_by_countcol(df, 'pii_cc_count', 'pii_cards')
                    ips = _count_by_countcol(df, 'pii_ip_count', 'pii_ips')
                    ssns = _count_by_countcol(df, 'pii_ssn_count', 'pii_ssns')
                    ids = _count_by_countcol(df, 'pii_id_count', 'pii_ids')

                    # Determine total pages with any PII
                    if 'pii_exposure' in df.columns:
                        total_pages = int(df['pii_exposure'].astype(bool).sum())
                    else:
                        cols_to_check = [c for c in (
                            'pii_email_count', 'pii_tel_count', 'pii_cc_count',
                            'pii_ip_count', 'pii_id_count', 'pii_ssn_count'
                        ) if c in df.columns]
                        if cols_to_check:
                            total_pages = int((df[cols_to_check].sum(axis=1) > 0).sum())
                        else:
                            # Fallback: check any of the string PII columns
                            total_pages = int((df[['pii_emails','pii_phones','pii_cards','pii_ips','pii_ids','pii_ssns']].fillna('').astype(bool).sum(axis=1) > 0).sum())

                    return {
                        'emails_leaked': emails,
                        'phones_leaked': phones,
                        'cards_leaked': cards,
                        'ips_leaked': ips,
                        'ssns_leaked': ssns,
                        'ids_leaked': ids,
                        'total_pii_pages': total_pages,
                    }
                
                metrics_g100 = extract_pii_metrics(df_g100)
                metrics_g111 = extract_pii_metrics(df_g111)
                
                # Create comparison table
                comparison_data = {
                    'PII Type': ['📧 Emails', '☎️ Phones', '💳 Cards', '🌐 IP Addresses', '🔒 SSNs', '🆔 User IDs', '📊 Total Pages with PII'],
                    'Consent DENIED (G100)': [
                        metrics_g100['emails_leaked'],
                        metrics_g100['phones_leaked'],
                        metrics_g100['cards_leaked'],
                        metrics_g100['ips_leaked'],
                        metrics_g100['ssns_leaked'],
                        metrics_g100['ids_leaked'],
                        metrics_g100['total_pii_pages'],
                    ],
                    'Consent ACCEPTED (G111)': [
                        metrics_g111['emails_leaked'],
                        metrics_g111['phones_leaked'],
                        metrics_g111['cards_leaked'],
                        metrics_g111['ips_leaked'],
                        metrics_g111['ssns_leaked'],
                        metrics_g111['ids_leaked'],
                        metrics_g111['total_pii_pages'],
                    ],
                }
                
                comparison_df = pd.DataFrame(comparison_data)
                comparison_df['Difference'] = comparison_df['Consent DENIED (G100)'] - comparison_df['Consent ACCEPTED (G111)']
                comparison_df['Status'] = comparison_df.apply(
                    lambda row: '✅ COMPLIANT' if row['Difference'] <= 0 else f'🚨 VIOLATION +{row["Difference"]}',
                    axis=1
                )
                
                st.dataframe(comparison_df, use_container_width=True)
                
                # Key findings
                st.markdown("### 🔍 Key Findings")
                
                total_extra_leakage = comparison_df['Difference'].sum()
                
                if total_extra_leakage > 0:
                    st.error(
                        f"🚨 **CRITICAL FINDING**: {total_extra_leakage} more PII items leaked when consent is ACCEPTED!\n"
                        f"\nThis indicates the website is properly respecting user consent settings. "
                        f"PII is only leaked when users accept consent (GCS=G111)."
                    )
                elif total_extra_leakage < 0:
                    st.warning(
                        f"⚠️ **CONCERN**: {abs(total_extra_leakage)} less PII items leaked when consent is ACCEPTED.\n"
                        f"\nThis may indicate inconsistent consent enforcement. "
                        f"Expected more PII leakage when users accept consent."
                    )
                else:
                    st.info(
                        "ℹ️ **NEUTRAL**: Same amount of PII leaked in both scenarios.\n"
                        f"\nThis suggests the website either:\n"
                        f"- Does not track PII differently based on consent\n"
                        f"- Has other sources of PII leakage independent of consent"
                    )
                
                # Detailed page-by-page comparison
                st.markdown("---")
                st.markdown("### 📋 Page-by-Page Comparison")
                
                # Merge dataframes on URL
                comparison_pages = pd.merge(
                    df_g100[['url', 'pii_count', 'pii_emails', 'pii_phones', 'pii_ids']].rename(columns={
                        'pii_count': 'pii_count_denied',
                        'pii_emails': 'emails_denied',
                        'pii_phones': 'phones_denied',
                        'pii_ids': 'ids_denied',
                    }),
                    df_g111[['url', 'pii_count', 'pii_emails', 'pii_phones', 'pii_ids']].rename(columns={
                        'pii_count': 'pii_count_accepted',
                        'pii_emails': 'emails_accepted',
                        'pii_phones': 'phones_accepted',
                        'pii_ids': 'ids_accepted',
                    }),
                    on='url',
                    how='outer'
                ).fillna(0)
                
                # Find pages with differential leakage
                comparison_pages['pii_diff'] = comparison_pages['pii_count_accepted'] - comparison_pages['pii_count_denied']
                comparison_pages_sorted = comparison_pages.sort_values('pii_diff', ascending=False)
                
                if len(comparison_pages_sorted) > 0:
                    st.dataframe(
                        comparison_pages_sorted[[
                            'url', 'pii_count_denied', 'pii_count_accepted', 'pii_diff'
                        ]].head(20),
                        use_container_width=True
                    )
                    
                    # Pages with increased leakage (positive change)
                    increased_pages = comparison_pages_sorted[comparison_pages_sorted['pii_diff'] > 0]
                    if len(increased_pages) > 0:
                        with st.expander(f"ℹ️ Pages with MORE PII leakage when consent ACCEPTED ({len(increased_pages)})"):
                            st.write("These pages properly respect consent - they leak more PII when user accepts consent.")
                            for _, row in increased_pages.head(10).iterrows():
                                st.write(
                                    f"- **{row['url']}**: "
                                    f"{int(row['pii_count_denied'])} → {int(row['pii_count_accepted'])} "
                                    f"(+{int(row['pii_diff'])} items)"
                                )
                    
                    # Pages with same leakage
                    same_pages = comparison_pages_sorted[comparison_pages_sorted['pii_diff'] == 0]
                    if len(same_pages) > 0:
                        with st.expander(f"❔ Pages with SAME PII leakage in both scenarios ({len(same_pages)})"):
                            st.write("These pages leak the same amount of PII regardless of consent status.")
                            for _, row in same_pages.head(10).iterrows():
                                if int(row['pii_count_denied']) > 0:
                                    st.write(f"- **{row['url']}**: {int(row['pii_count_denied'])} items in both scenarios")
                    
                    # Pages with decreased leakage (negative change - concerning)
                    decreased_pages = comparison_pages_sorted[comparison_pages_sorted['pii_diff'] < 0]
                    if len(decreased_pages) > 0:
                        with st.expander(f"🚨 Pages with LESS PII leakage when consent ACCEPTED ({len(decreased_pages)})"):
                            st.error(
                                "⚠️ These pages leak LESS PII when user accepts consent. "
                                "This is unexpected and suggests inconsistent consent enforcement."
                            )
                            for _, row in decreased_pages.head(10).iterrows():
                                st.write(
                                    f"- **{row['url']}**: "
                                    f"{int(row['pii_count_denied'])} → {int(row['pii_count_accepted'])} "
                                    f"({int(row['pii_diff'])} items)"
                                )
                else:
                    st.info("No matching pages found in both scans.")

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
    # Prepare raw JSON for download — ensure all objects are JSON-serializable.
    def _json_default(o):
        # Convert common non-serializable types to JSON-friendly ones
        try:
            if isinstance(o, set):
                return list(o)
            if isinstance(o, bytes):
                return o.decode("utf-8", errors="replace")
            # Fallback: try to convert to string
            return str(o)
        except Exception:
            return str(o)

    try:
        json_bytes = json.dumps(results, indent=2, default=_json_default).encode()
    except Exception:
        # As a last resort, stringify the results
        json_bytes = json.dumps([str(r) for r in (results or [])], indent=2).encode()
    st.download_button(
        "Download raw JSON",
        data=json_bytes,
        file_name="scan_results_raw.json",
        mime="application/json",
    )
