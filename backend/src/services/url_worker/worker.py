import logging
from typing import Dict, Any
from .http_fetcher import HTTPFetcher
from .browser_fetcher import BrowserFetcher

logger = logging.getLogger(__name__)

class URLWorker:
    """
    Coordinates the two-stage URL inspection fetch.

    Responsibility:
        - Stage A: lightweight HTTP inspection
        - Stage B: browser fallback for JS-heavy/empty pages

    DNS/TLS inspection is intentionally NOT performed here.
    The authoritative DNS/TLS inspection belongs to
    URLInspectionService.inspect().
    """

    MIN_VISIBLE_TEXT = 50

    @classmethod
    def inspect(cls, url: str) -> Dict[str, Any]:
        logger.info(
            "Worker starting inspection for %s",
            url,
        )

        # ====================================================
        # STAGE A - Lightweight HTTP fetch
        # ====================================================

        result = HTTPFetcher.fetch(url)

        if result.get(
            "security",
            {},
        ).get("blocked"):
            return result

        word_count = result.get(
            "word_count",
            0,
        )

        forms_count = (
            result.get(
                "forms",
                {},
            )
            or {}
        ).get(
            "count",
            0,
        )

        # ====================================================
        # STAGE B - Browser fallback
        #
        # Browser fallback is used only when the lightweight
        # HTTP fetch produced insufficient visible content.
        #
        # IMPORTANT:
        # Do NOT call URLInspectionService.inspect() here.
        #
        # DNS/TLS is authoritative at the service layer and
        # calling it here would duplicate DNS/TLS inspection.
        # ====================================================

        if (
            word_count < cls.MIN_VISIBLE_TEXT
            and forms_count == 0
        ):
            logger.info(
                "Insufficient content for %s in Stage A, "
                "using browser fallback.",
                url,
            )

            browser_result = BrowserFetcher.fetch(
                url
            )

            if browser_result:

                merged_result = dict(
                    result
                )

                # Browser content should replace the
                # lightweight HTTP content where available.
                merged_result.update(
                    browser_result
                )

                # Preserve redirect information discovered
                # by the lightweight HTTP fetch.
                if result.get(
                    "redirects"
                ):
                    merged_result[
                        "redirects"
                    ] = result[
                        "redirects"
                    ]

                return merged_result

        return result