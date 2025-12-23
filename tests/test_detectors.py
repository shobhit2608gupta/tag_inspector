import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'src')
sys.path.insert(0, SRC)

from op_lite.detectors import detect_from_requests, detect_from_html

def test_detect_from_requests():
    reqs = [{'url': 'https://www.google-analytics.com/g/collect?v=1'}, {'url':'https://example.com/static.js'}]
    found = detect_from_requests(reqs)
    assert found['ga4'] is True
    assert found['fb'] is False

def test_detect_from_html():
    html = '<script>window.dataLayer = [];</script><script src="https://connect.facebook.net/en_US/fbevents.js"></script>'
    found = detect_from_html(html)
    assert found['fb'] is True
    assert found['ga4'] is False
