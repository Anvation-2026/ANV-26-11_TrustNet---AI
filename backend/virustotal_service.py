"""Optional, read-only lookups of existing URL reports in VirusTotal."""

import base64
import json
import os
import threading
import time
from collections import deque
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

API_BASE = "https://www.virustotal.com/api/v3/urls/"
TIMEOUT_SECONDS = 10
MAX_REQUESTS_PER_MINUTE = 4
_request_times: deque[float] = deque()
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_lock = threading.Lock()


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _reserve_quota() -> bool:
    now = time.monotonic()
    with _lock:
        while _request_times and now - _request_times[0] >= 60:
            _request_times.popleft()
        if len(_request_times) >= MAX_REQUESTS_PER_MINUTE:
            return False
        _request_times.append(now)
        return True


def check_url(url: str) -> dict[str, Any]:
    """Retrieve an existing report only; never submit or rescan a URL."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"status": "not_configured", "malicious": 0, "suspicious": 0}

    now = time.monotonic()
    with _lock:
        cached = _cache.get(url)
        if cached and now - cached[0] < 30 * 60:
            return dict(cached[1])

    if not _reserve_quota():
        return {"status": "rate_limited", "malicious": 0, "suspicious": 0}

    request = Request(
        API_BASE + _url_id(url),
        headers={"x-apikey": api_key, "Accept": "application/json", "User-Agent": "TrustNet-AI/1.0"},
    )
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        result = {
            "status": "match" if malicious > 0 or suspicious > 0 else "no_match",
            "malicious": malicious,
            "suspicious": suspicious,
        }
    except HTTPError as exc:
        if exc.code == 404:
            result = {"status": "not_found", "malicious": 0, "suspicious": 0}
        elif exc.code == 401:
            result = {"status": "unauthorized", "malicious": 0, "suspicious": 0}
        elif exc.code == 429:
            result = {"status": "rate_limited", "malicious": 0, "suspicious": 0}
        else:
            result = {"status": "unavailable", "malicious": 0, "suspicious": 0}
    except (URLError, TimeoutError, OSError, ValueError, TypeError):
        result = {"status": "unavailable", "malicious": 0, "suspicious": 0}

    if result["status"] in {"match", "no_match", "not_found"}:
        with _lock:
            _cache[url] = (time.monotonic(), result)
    return result


def check_urls(urls: list[str]) -> dict[str, dict[str, Any]]:
    """Look up URLs sequentially to respect the free public API quota."""
    if not os.getenv("VIRUSTOTAL_API_KEY", "").strip():
        return {}
    return {url: check_url(url) for url in dict.fromkeys(urls)}
