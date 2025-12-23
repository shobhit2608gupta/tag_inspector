# examples/run_scan.py
import sys, os, json, argparse

# Ensure src is importable when invoking from repo root
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, 'src')
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from op_lite.crawler import Crawler
from op_lite.detectors import detect_from_requests, detect_from_html
from op_lite.validator import validate_datalayer
from op_lite.reporting import to_json, to_csv


def postprocess_and_save(results, out_json, out_csv):
    """Run detectors + validator on each page result and save JSON/CSV."""
    for r in results:
        dets = detect_from_requests(r.get('requests', []))
        det_html = detect_from_html(r.get('html', '') or "")
        merged = {
            "ga4": dets.get("ga4") or det_html.get("ga4"),
            "fb": dets.get("fb") or det_html.get("fb"),
            "adobe": dets.get("adobe") or det_html.get("adobe"),
        }
        r['detectors'] = merged
        r['datalayer_validation'] = validate_datalayer(r.get('dataLayer'))

    os.makedirs(os.path.dirname(out_json) or '.', exist_ok=True)
    to_json(results, out_json)
    to_csv(results, out_csv)
    print(f"Saved {out_json} and {out_csv}")


def run_crawl(
    start_url: str,
    max_pages: int = 3,
    max_depth: int = 1,
    out_json: str = 'examples/latest_scan.json',
    out_csv: str = 'examples/latest_scan.csv',
):
    """Site-wide crawl mode."""
    c = Crawler(
        start_url,
        max_pages=max_pages,
        max_depth=max_depth,
        headless=False,          # you can use True later; False is nice to debug
        auto_submit_form=True,   # 🔴 THIS ENABLES THE AUTO FORM SUBMIT
        auto_play_video=True,
        wait_until="load",
    )
    results = c.crawl()
    postprocess_and_save(results, out_json, out_csv)


def run_journey(
    urls,
    out_json: str = 'examples/journey_latest_scan.json',
    out_csv: str = 'examples/journey_latest_scan.csv',
):
    """User journey mode: visit given URLs in order and scan each once."""
    combined = []
    for u in urls:
        print(f"Scanning journey URL: {u}")
        c = Crawler(
            u,
            max_pages=1,
            max_depth=0,
            headless=False,          # again, False is easier to see what happens
            auto_submit_form=True,   # 🔴 ENABLE AUTO FORM SUBMIT FOR JOURNEY STEPS
        )
        res = c.crawl()
        combined.extend(res)
    postprocess_and_save(combined, out_json, out_csv)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-url", help="Start URL to crawl (for site crawl mode)")
    parser.add_argument("--max-pages", type=int, default=3)
    parser.add_argument("--max-depth", type=int, default=1)
    parser.add_argument("--out-json", default="examples/latest_scan.json")
    parser.add_argument("--out-csv", default="examples/latest_scan.csv")
    parser.add_argument(
        "--journey-urls-file",
        help="JSON file containing a list of URLs for journey mode",
    )
    args = parser.parse_args()

    if args.journey_urls_file:
        # Journey mode
        with open(args.journey_urls_file, "r", encoding="utf-8") as f:
            urls = json.load(f)
        run_journey(urls, args.out_json, args.out_csv)
    else:
        # Crawl mode
        if not args.start_url:
            print(
                "Error: --start-url is required when not using --journey-urls-file",
                file=sys.stderr,
            )
            sys.exit(1)
        run_crawl(args.start_url, args.max_pages, args.max_depth, args.out_json, args.out_csv)
