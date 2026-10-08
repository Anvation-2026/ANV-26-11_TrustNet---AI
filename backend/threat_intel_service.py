"""Local lookups against a periodically refreshed, public phishing URL feed."""

import os
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen

import virustotal_service

PROVIDER = "Phishing.Database"
DEFAULT_FEED_URL = (
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
    "master/phishing-links-ACTIVE.txt"
)
FEED_REFRESH_SECONDS = 60 * 60
TIMEOUT_SECONDS = 12
MAX_URLS_PER_SCAN = 100

_feed_keys: set[tuple[str, str]] | None = None
_root_domains: set[str] = set()
_feed_loaded_at = 0.0
_feed_checked_at: str | None = None
_feed_lock = threading.Lock()


def _url_key(value: str) -> tuple[str, str] | None:
    candidate = value.strip().strip("\"'")
    if not candidate or candidate.startswith(("#", "!")):
        return None
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return None
    path = unquote(parsed.path or "/").rstrip("/") or "/"
    return host, path


def _refresh_feed(force: bool = False) -> tuple[set[tuple[str, str]] | None, set[str], str, str | None]:
    global _feed_keys, _root_domains, _feed_loaded_at, _feed_checked_at
    with _feed_lock:
        now = time.monotonic()
        if not force and _feed_keys is not None and now - _feed_loaded_at < FEED_REFRESH_SECONDS:
            return _feed_keys, _root_domains, "checked", _feed_checked_at

        feed_url = os.getenv("PHISHING_FEED_URL", DEFAULT_FEED_URL).strip()
        request = Request(feed_url, headers={"User-Agent": "TrustNet-AI/1.0", "Accept": "text/plain"})
        try:
            with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                body = response.read().decode("utf-8", errors="replace")
            keys = {key for line in body.splitlines() if (key := _url_key(line))}
            if not keys:
                raise ValueError("The phishing feed contained no usable entries.")
            roots = {host for host, path in keys if path == "/"}
            _feed_keys = keys
            _root_domains = roots
            _feed_loaded_at = time.monotonic()
            _feed_checked_at = datetime.now(timezone.utc).isoformat()
            return _feed_keys, _root_domains, "checked", _feed_checked_at
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, UnicodeError):
            if _feed_keys is not None:
                return _feed_keys, _root_domains, "stale", _feed_checked_at
            return None, set(), "unavailable", None


def check_urls(urls: list[str]) -> dict[str, Any]:
    """Check the local feed, then optionally query existing VirusTotal reports."""
    unique_urls = list(dict.fromkeys(urls))
    keys, roots, feed_status, checked_at = _refresh_feed()
    selected = unique_urls[:MAX_URLS_PER_SCAN]
    results = []
    for url in unique_urls:
        key = _url_key(url)
        if keys is None:
            status, threat_types = "unavailable", []
        elif url not in selected:
            status, threat_types = "not_checked_limit", []
        elif feed_status == "stale":
            status, threat_types = "stale_feed", []
        elif key is None:
            status, threat_types = "unavailable", []
        elif key in keys or (key[1] == "/" and key[0] in roots):
            status, threat_types = "match", ["phishing_url"]
        else:
            status, threat_types = "no_match", []
        results.append({"url": url, "status": status, "threat_types": threat_types})

    vt_results = virustotal_service.check_urls(
        [item["url"] for item in results if item["status"] != "match"]
    )
    for item in results:
        vt = vt_results.get(item["url"])
        item["virustotal_status"] = vt["status"] if vt else (
            "not_configured" if not os.getenv("VIRUSTOTAL_API_KEY", "").strip() else "not_queried"
        )
        item["virustotal_malicious"] = vt["malicious"] if vt else 0
        item["virustotal_suspicious"] = vt["suspicious"] if vt else 0
        if vt and vt["status"] == "match":
            if vt["malicious"]:
                item["status"] = "match"
                item["threat_types"] = list(dict.fromkeys(item["threat_types"] + ["virustotal_malicious"]))
            elif item["status"] != "match":
                item["status"] = "suspicious"
                item["threat_types"] = list(dict.fromkeys(item["threat_types"] + ["virustotal_suspicious"]))

    vt_enabled = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())
    unavailable = any(item["status"] in {"unavailable", "stale_feed", "not_checked_limit"} for item in results)
    provider = f"{PROVIDER} + VirusTotal" if vt_enabled else PROVIDER
    note = (
        "URLs were compared locally with the public phishing feed and existing VirusTotal reports were queried. "
        "VirusTotal receives each queried URL; no-match is not proof of safety."
        if vt_enabled else
        "URLs were compared locally against a community phishing feed; no-match is not proof of safety."
    )
    return {
        "provider": provider,
        "status": feed_status if keys is not None else "unavailable",
        "checked_at": checked_at,
        "feed_entries": len(keys) if keys is not None else 0,
        "results": results,
        "virustotal_enabled": vt_enabled,
        "note": note if not unavailable else note + " The feed is stale or unavailable for some URLs; no conclusion is drawn for them.",
    }
