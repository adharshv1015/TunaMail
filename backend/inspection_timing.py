import time

from src.services.url_inspection_service import URLInspectionService

service = URLInspectionService()

urls = [
    "https://us.list-manage.com/",
    "https://oneteamsolutions.us6.list-manage.com/",
    "http://www.w3.org/",
    "https://mcusercontent.com/",
]

print("--- URL INSPECTION TIMING ---")

for url in urls:
    start = time.perf_counter()

    try:
        result = service.inspect(url)

        elapsed = (time.perf_counter() - start) * 1000

        print()
        print("URL:", url)
        print("TOTAL_MS:", round(elapsed, 2))
        print("STATUS:", result.get("analysis_status"))
        print("DNS:", result.get("dns"))
        print("TLS:", result.get("tls"))
        print("REDIRECTS:", result.get("redirects"))

    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000

        print()
        print("URL:", url)
        print("TOTAL_MS:", round(elapsed, 2))
        print("ERROR:", type(exc).__name__, str(exc))