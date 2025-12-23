# src/op_lite/crawler.py

from playwright.sync_api import sync_playwright, Error as PWError
from urllib.parse import urlparse, urljoin
import time
import logging
from typing import List, Dict, Any, Tuple

DEFAULT_TIMEOUT = 60_000  # 60 seconds

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Crawler:
    def __init__(
        self,
        start_url: str,
        max_pages: int = 50,
        max_depth: int = 2,
        headless: bool = True,
        auto_submit_form: bool = False,
        auto_play_video: bool = False,
        wait_until: str = "load",  # "load" | "domcontentloaded" | "networkidle"
        auto_accept_cookies: bool = True,
    ):
        self.start_url = start_url
        self.max_pages = int(max_pages)
        self.max_depth = int(max_depth)
        self.visited = set()
        self.results: List[Dict[str, Any]] = []

        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc

        self.headless = headless
        self.auto_submit_form = auto_submit_form
        self.auto_play_video = auto_play_video
        self.wait_until = wait_until
        self.auto_accept_cookies = auto_accept_cookies

    # ------------------------------------------------------------------
    # Helper functions
    # ------------------------------------------------------------------

    def _is_same_domain(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.base_domain
        except Exception:
            return False

    def _normalize_url(self, base: str, href: str):
        if not href:
            return None
        if href.startswith(("javascript:", "mailto:")):
            return None
        return urljoin(base, href.split("#")[0])

    # ------------------------------------------------------------------
    # Cookie consent handler
    # ------------------------------------------------------------------

    def _handle_cookie_consent(self, page) -> bool:
        """
        Best-effort cookie banner handler.
        Tries to click 'Accept all' / 'Agree' buttons on common CMPs.
        Returns True if it clicked something, else False.
        """
        clicked = False
        try:
            # 1) OneTrust-style banner
            try:
                banner = page.query_selector("#onetrust-banner-sdk")
                if banner:
                    btn = banner.query_selector(
                        "#onetrust-accept-btn-handler, "
                        "button[aria-label*='Accept'], "
                        "button[title*='Accept']"
                    )
                    if btn:
                        btn.click()
                        page.wait_for_timeout(1000)
                        logger.info("Cookie banner accepted via OneTrust heuristic.")
                        return True
            except Exception:
                pass

            # 2) Generic buttons with matching text
            patterns = [
                "accept all",
                "accept cookies",
                "accept all cookies",
                "i agree",
                "agree",
                "allow all",
                "ok",
                "got it",
            ]

            buttons = page.query_selector_all(
                "button, [role='button'], input[type='button'], input[type='submit']"
            )

            for b in buttons:
                try:
                    txt = (b.inner_text() or "") + " " + (
                        b.get_attribute("aria-label") or ""
                    )
                    txt_low = txt.lower()
                    if any(pat in txt_low for pat in patterns):
                        b.click()
                        page.wait_for_timeout(1000)
                        logger.info(
                            "Cookie banner accepted via generic button heuristic: %r",
                            txt.strip(),
                        )
                        clicked = True
                        break
                except Exception:
                    continue

        except Exception as e:
            logger.warning("Cookie consent handling failed: %s", e)

        return clicked

    # ------------------------------------------------------------------
    # Form auto-submit (best-effort)
    # ------------------------------------------------------------------

    def _auto_fill_and_submit_form(self, page):
        """
        Try to auto-fill and submit the first <form> on the page.
        Returns a small audit dict with attempt/success/error.
        """
        try:
            forms = page.query_selector_all("form")
        except Exception as e:
            logger.warning("Error querying forms: %s", e)
            return {
                "attempted": True,
                "success": False,
                "error": "query_selector_all failed",
            }

        if not forms:
            return {
                "attempted": False,
                "success": False,
                "error": "no form found",
            }

        logger.info("Auto-submitting first form on page")
        form = forms[0]

        try:
            form.scroll_into_view_if_needed()
        except Exception:
            pass

        # Fill inputs / textareas
        inputs = form.query_selector_all("input, textarea")
        for el in inputs:
            try:
                el_type = (el.get_attribute("type") or "text").lower()
                name = (el.get_attribute("name") or "").lower()
                id_ = (el.get_attribute("id") or "").lower()

                if el_type in ("hidden", "checkbox", "radio", "file"):
                    continue

                if "email" in name or "email" in id_ or el_type == "email":
                    value = "test@example.com"
                elif "name" in name or "name" in id_:
                    value = "Test User"
                elif el_type == "password":
                    value = "Password123!"
                else:
                    value = "test"

                try:
                    el.fill(value)
                except Exception:
                    # JS fallback
                    page.evaluate(
                        """
                        (el, val) => {
                          el.value = val;
                          el.dispatchEvent(new Event('input', { bubbles: true }));
                          el.dispatchEvent(new Event('change', { bubbles: true }));
                        }
                        """,
                        el,
                        value,
                    )
            except Exception:
                continue

        # Submit the form
        submit = form.query_selector(
            "button[type='submit'], input[type='submit'], button"
        )

        try:
            if submit:
                try:
                    submit.click()
                except Exception:
                    page.evaluate("(el) => el.click()", submit)
            else:
                page.evaluate("f => f.submit()", form)

            # Wait for navigation/load after submit
            page.wait_for_load_state("load")

            return {
                "attempted": True,
                "success": True,
                "error": None,
            }

        except Exception as e:
            logger.warning("Form auto-submit failed: %s", e)
            return {
                "attempted": True,
                "success": False,
                "error": str(e),
            }

    # ------------------------------------------------------------------
    # Video auto-play
    # ------------------------------------------------------------------

    def _auto_play_video(self, page):
        """
        Attempt to auto-play the first HTML5 <video> element on the page.
        Returns a dict describing what happened.
        """
        result = {
            "video_found": False,
            "play_attempted": False,
            "play_started": False,
            "paused": None,
            "current_time": None,
            "error": None,
        }

        try:
            videos = page.query_selector_all("video")
        except Exception as e:
            result["error"] = f"query_selector_all failed: {e}"
            return result

        if not videos:
            return result

        video = videos[0]
        result["video_found"] = True

        try:
            try:
                video.scroll_into_view_if_needed()
            except Exception:
                pass

            result["play_attempted"] = True

            # Mute + request play
            page.evaluate(
                """
                (vid) => {
                  vid.muted = true;
                  const p = vid.play();
                  if (p && p.catch) { p.catch(() => {}); }
                }
                """,
                video,
            )

            # Wait a bit for playback to start
            page.wait_for_timeout(4000)

            playback = page.evaluate(
                """
                (vid) => ({
                  paused: vid.paused,
                  currentTime: vid.currentTime
                })
                """,
                video,
            )

            result["paused"] = playback["paused"]
            result["current_time"] = playback["currentTime"]

            if playback["currentTime"] > 0 and playback["paused"] is False:
                result["play_started"] = True

        except Exception as e:
            result["error"] = str(e)

        return result

    # ------------------------------------------------------------------
    # Main crawl
    # ------------------------------------------------------------------

    def crawl(self) -> List[Dict[str, Any]]:
        """
        BFS crawl within same domain, collecting analytics-relevant data.
        """
        queue: List[Tuple[str, int]] = [(self.start_url, 0)]

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.headless)

            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1366, "height": 768},
                locale="en-US",
            )

            page = context.new_page()

            requests: List[Dict[str, Any]] = []

            def on_request(req):
                try:
                    requests.append(
                        {
                            "url": req.url,
                            "method": req.method,
                            "resource_type": req.resource_type,
                        }
                    )
                except Exception:
                    pass

            page.on("request", on_request)

            while queue and len(self.visited) < self.max_pages:
                url, depth = queue.pop(0)
                if url in self.visited:
                    continue

                logger.info("Visiting %s (depth %d)", url, depth)
                self.visited.add(url)
                requests.clear()

                try:
                    start = time.time()
                    resp = page.goto(
                        url,
                        timeout=DEFAULT_TIMEOUT,
                        wait_until=self.wait_until,
                    )
                    load_time = time.time() - start
                    status = resp.status if resp else None
                except PWError as e:
                    logger.warning("Navigation error on %s: %s", url, e)
                    self.results.append(
                        {"url": url, "status": None, "error": str(e)}
                    )
                    continue

                # -------- Cookie consent --------
                if self.auto_accept_cookies:
                    try:
                        self._handle_cookie_consent(page)
                    except Exception as e:
                        logger.warning(
                            "Cookie consent handler error on %s: %s", url, e
                        )

                # -------- Form submit (optional) --------
                form_result = None
                if self.auto_submit_form:
                    form_result = self._auto_fill_and_submit_form(page)

                # -------- Video auto-play (optional) --------
                video_result = None
                if self.auto_play_video:
                    video_result = self._auto_play_video(page)

                # -------- Capture page state --------
                try:
                    data_layer = page.evaluate("() => window.dataLayer || null")
                except Exception:
                    data_layer = None

                try:
                    html = page.content()
                except Exception:
                    html = None

                try:
                    cookies = context.cookies()
                except Exception:
                    cookies = []

                page_result = {
                    "url": url,
                    "status": status,
                    "load_time": load_time,
                    "requests": list(requests),
                    "cookies": cookies,
                    "dataLayer": data_layer,
                    "html": html[:10000] if html else None,
                    "form_audit": form_result,
                    "video_audit": video_result,
                }

                self.results.append(page_result)

                # -------- Discover links for BFS --------
                if depth + 1 <= self.max_depth:
                    try:
                        links = page.eval_on_selector_all(
                            "a", "as => as.map(a => a.href)"
                        )
                        for link in links:
                            norm = self._normalize_url(url, link)
                            if norm and self._is_same_domain(norm):
                                queue.append((norm, depth + 1))
                    except Exception:
                        pass

                time.sleep(1)

            browser.close()

        return self.results


if __name__ == "__main__":
    # quick manual test
    c = Crawler(
        "https://httpbin.org/forms/post",
        max_pages=1,
        max_depth=0,
        headless=False,
        auto_submit_form=True,
        auto_play_video=False,
        wait_until="load",
        auto_accept_cookies=True,
    )
    res = c.crawl()
    import json

    print(json.dumps(res, indent=2)[:2000])
