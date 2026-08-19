import logging
from typing import Dict, Any, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from .safety import URLSafetyChecker, URLSafetyException
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    sync_playwright = None

    class PlaywrightTimeoutError(Exception):
        pass


logger = logging.getLogger(__name__)


class BrowserFetcher:
    """
    Stage B browser-based URL inspection.

    Renders JavaScript-heavy pages and extracts the final browser-visible
    content and important DOM/network indicators.
    """

    PAGE_TIMEOUT_MS = 15000
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024

    @classmethod
    def fetch(cls, start_url: str) -> Dict[str, Any]:
        if sync_playwright is None:
            return cls._build_result(
                start_url,
                error="Playwright is not installed",
            )
        try:
            URLSafetyChecker.validate_url(start_url)
        except URLSafetyException as exc:
            return cls._build_result(
                start_url,
                error=f"Safety blocked: {str(exc)}",
                blocked=True,
            )
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)

                page = browser.new_page(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    )
                )

                requests_seen: List[Dict[str, Any]] = []
                responses_seen: List[Dict[str, Any]] = []

                blocked_request = {"blocked": False, "error": None}

                def handle_request(request):
                    try:
                        URLSafetyChecker.validate_url(request.url)
                    except URLSafetyException as exc:
                        blocked_request["blocked"] = True
                        blocked_request["error"] = str(exc)
                        try:
                            request.abort()
                        except Exception:
                            pass
                        return

                    cls._capture_request(
                        request,
                        requests_seen,
                    )

                page.on("request", handle_request)

                page.on(
                    "response",
                    lambda response: cls._capture_response(
                        response,
                        responses_seen,
                    ),
                )

                try:
                    response = page.goto(
                        start_url,
                        wait_until="domcontentloaded",
                        timeout=cls.PAGE_TIMEOUT_MS,
                    )

                    try:
                        page.wait_for_load_state(
                            "networkidle",
                            timeout=5000,
                        )
                    except PlaywrightTimeoutError:
                        pass

                    final_url = page.url
                    status_code = response.status if response else 0

                    try:
                        URLSafetyChecker.validate_url(final_url)
                    except URLSafetyException as exc:
                        browser.close()
                        return cls._build_result(
                            final_url,
                            status_code=status_code,
                            requests_seen=requests_seen,
                            responses_seen=responses_seen,
                            error=f"Safety blocked: {str(exc)}",
                            blocked=True,
                        )

                    if blocked_request["blocked"]:
                        browser.close()
                        return cls._build_result(
                            final_url,
                            status_code=status_code,
                            requests_seen=requests_seen,
                            responses_seen=responses_seen,
                            error=(
                                "Browser request blocked: "
                                f"{blocked_request['error']}"
                            ),
                            blocked=True,
                        )

                    html = page.content()

                    if len(html.encode("utf-8")) > cls.MAX_CONTENT_LENGTH:
                        browser.close()
                        return cls._build_result(
                            final_url,
                            status_code=status_code,
                            error="Rendered content too large",
                        )

                    extracted = cls._extract_page(page, html)

                    browser.close()

                    return cls._build_result(
                        final_url,
                        status_code=status_code,
                        extracted=extracted,
                        requests_seen=requests_seen,
                        responses_seen=responses_seen,
                    )

                except PlaywrightTimeoutError:
                    final_url = page.url

                    try:
                        URLSafetyChecker.validate_url(final_url)
                    except URLSafetyException as exc:
                        browser.close()
                        return cls._build_result(
                            final_url,
                            status_code=0,
                            requests_seen=requests_seen,
                            responses_seen=responses_seen,
                            error=f"Safety blocked: {str(exc)}",
                            blocked=True,
                        )

                    try:
                        html = page.content()
                        extracted = cls._extract_page(page, html)
                    except Exception:
                        extracted = None

                    browser.close()

                    return cls._build_result(
                        final_url,
                        status_code=0,
                        extracted=extracted,
                        requests_seen=requests_seen,
                        responses_seen=responses_seen,
                        error="Browser navigation timeout",
                    )

        except Exception as exc:
            logger.exception("Browser fetch failed for %s", start_url)

            return cls._build_result(
                start_url,
                error=f"Browser fetch failed: {str(exc)}",
            )

    @classmethod
    def _extract_page(cls, page, html: str) -> Dict[str, Any]:
        soup = BeautifulSoup(html, "html.parser")

        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        for element in soup(
            ["script", "style", "noscript", "meta", "link"]
        ):
            element.extract()

        visible_text = soup.get_text(
            separator=" ",
            strip=True,
        )

        forms = soup.find_all("form")

        password_fields = len(
            soup.find_all("input", type="password")
        )

        email_fields = len(
            soup.find_all("input", type="email")
        )

        for inp in soup.find_all("input"):
            input_type = (inp.get("type") or "text").lower()

            if input_type != "text":
                continue

            name = (inp.get("name") or "").lower()
            id_attr = (inp.get("id") or "").lower()

            if (
                "email" in name
                or "email" in id_attr
                or "user" in name
                or "login" in name
            ):
                email_fields += 1

        submit_buttons = len(
            soup.find_all(
                ["button", "input"],
                type="submit",
            )
        )

        if submit_buttons == 0:
            submit_buttons = len(soup.find_all("button"))

        links = []

        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href")

            if href:
                links.append(href)

        iframes = []

        for iframe in soup.find_all("iframe", src=True):
            src = iframe.get("src")

            if src:
                iframes.append(src)

        scripts = []

        for script in soup.find_all("script", src=True):
            src = script.get("src")

            if src:
                scripts.append(src)

        return {
            "title": title,
            "visible_text": visible_text,
            "word_count": len(visible_text.split()),
            "forms": {
                "count": len(forms),
                "password_fields": password_fields,
                "email_fields": email_fields,
                "submit_buttons": submit_buttons,
            },
            "browser": {
                "rendered": True,
                "links": links,
                "iframes": iframes,
                "scripts": scripts,
            },
        }

    @staticmethod
    def _capture_request(request, requests_seen):
        try:
            requests_seen.append(
                {
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                }
            )
        except Exception:
            pass

    @staticmethod
    def _capture_response(response, responses_seen):
        try:
            responses_seen.append(
                {
                    "url": response.url,
                    "status": response.status,
                    "resource_type": response.request.resource_type,
                }
            )
        except Exception:
            pass

    @classmethod
    def _build_result(
        cls,
        final_url: str,
        status_code: int = 0,
        extracted: Dict[str, Any] = None,
        requests_seen: List[Dict[str, Any]] = None,
        responses_seen: List[Dict[str, Any]] = None,
        error: str = None,
        blocked: bool = False,
    ) -> Dict[str, Any]:

        result = {
            "http": {
                "final_url": final_url,
                "status_code": status_code,
            },
            "security": {
                "blocked": blocked,
                "error": error,
            },
            "redirects": [],
            "browser": {
                "rendered": False,
                "requests": requests_seen or [],
                "responses": responses_seen or [],
            },
        }

        if extracted:
            result.update(extracted)

            result["browser"].update(
                extracted.get("browser", {})
            )

        else:
            result.update(
                {
                    "title": "",
                    "visible_text": "",
                    "word_count": 0,
                    "forms": {
                        "count": 0,
                        "password_fields": 0,
                        "email_fields": 0,
                        "submit_buttons": 0,
                    },
                }
            )

        return result
