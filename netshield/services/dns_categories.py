"""DNS categories + the runtime-fetched adult-content blocklist.

Category system:
  * Curated categories with small hand-maintained domain lists (WhatsApp,
    YouTube, Facebook/Instagram, X/Twitter, TikTok, Spotify, Netflix,
    gaming, Reddit...). Each is user-editable from the Settings page.
  * The adult-content category is FETCHED AT RUNTIME — never hardcoded —
    from the actively-maintained StevenBlack/hosts project. We pull the
    "fakenews-gambling-porn" alternates hosts file first and fall back to
    the base hosts file on failure, parse "0.0.0.0 domain.tld" lines into a
    domain set, and cache the parsed set to disk with a fetch timestamp so
    it still works offline and stays current on a daily refresh schedule.

Matching is by BASE (registrable) domain so all subdomains are covered.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading

import requests

import config
from netshield.extensions import db
from netshield.models.models import Setting, utcnow

logger = logging.getLogger("netshield.categories")

# ---------------------------------------------------------------------------
# Curated categories — small hand-maintained domain lists
# ---------------------------------------------------------------------------
CURATED_CATEGORIES: dict[str, dict] = {
    "whatsapp": {
        "label": "WhatsApp",
        "domains": ["whatsapp.net", "whatsapp.com", "whatsapp.org"],
    },
    "youtube": {
        "label": "YouTube",
        # "=host" entries are exact/subdomain host rules (block only that
        # host, not the whole registrable base domain — e.g. only
        # youtubei.googleapis.com, not every googleapis.com service)
        "domains": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
                    "youtube-nocookie.com", "ytstatic.com",
                    "=youtubei.googleapis.com", "=yt3.ggpht.com",
                    "=ytimg.googleusercontent.com"],
    },
    "facebook_instagram": {
        "label": "Facebook / Instagram",
        "domains": ["facebook.com", "fb.com", "fbcdn.net", "messenger.com",
                    "instagram.com", "cdninstagram.com", "facebook.net",
                    "fbsbx.com", "fb.gg", "threads.net", "ig.me",
                    "igcdn.com"],
    },
    "x_twitter": {
        "label": "X / Twitter",
        "domains": ["x.com", "twitter.com", "t.co", "twimg.com"],
    },
    "tiktok": {
        "label": "TikTok",
        "domains": ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "musical.ly",
                    "byteoversea.com"],
    },
    "spotify": {
        "label": "Spotify",
        "domains": ["spotify.com", "scdn.co", "spotifycdn.com", "spotify.link"],
    },
    "netflix": {
        "label": "Netflix",
        "domains": ["netflix.com", "nflxvideo.net", "nflximg.net",
                    "nflxso.net", "nflxext.com"],
    },
    "gaming": {
        "label": "Gaming platforms",
        "domains": ["steampowered.com", "steamcommunity.com", "epicgames.com",
                    "easports.com", "playstation.com", "playstation.net",
                    "xbox.com", "xboxlive.com", "nintendo.com", "roblox.com",
                    "discord.com", "discord.gg", "riotgames.com",
                    "leagueoflegends.com", "twitch.tv", "battle.net",
                    "minecraft.net", "mojang.com"],
    },
    "reddit": {
        "label": "Reddit",
        "domains": ["reddit.com", "redd.it"],
    },
}

# Fetched categories come from the StevenBlack alternates file (combined
# fakenews + gambling + porn set). One set backs the adult category per spec.
FETCHED_CATEGORY_KEY = "adult"
FETCHED_CATEGORY_LABEL = "Adult content (StevenBlack hosts)"

STEVENBLACK_URLS = [
    # Primary: combined fakenews-gambling-porn alternates file
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/"
    "alternates/fakenews-gambling-porn/hosts",
    # Fallback: the base hosts file
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]
BLOCKLIST_CACHE = os.path.join(config.BLOCKLIST_DIR, "stevenblack.json")
_LINE_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([0-9a-zA-Z.\-]+)\s*$")

_memory_domains: set[str] | None = None
_memory_source: str | None = None
_memory_fetched_at: str | None = None
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Registrable-domain ("base domain") matching
# ---------------------------------------------------------------------------
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au",
    "org.au", "co.nz", "org.nz", "net.nz", "co.za", "org.za", "net.za",
    "co.jp", "or.jp", "ne.jp", "com.br", "com.mx", "com.ar", "co.in",
    "co.id", "co.kr", "com.sg", "com.my", "com.ph", "com.tw", "co.th",
    "com.tr", "com.pl", "com.ua", "co.il", "com.eg", "com.sa", "co.ke",
    "com.ng", "com.pk", "com.bd", "com.vn", "com.hk", "com.cn", "com.co",
}


def base_domain(domain: str) -> str:
    """Reduce a domain to its registrable base (all subdomains match)."""
    d = (domain or "").strip().lower().rstrip(".").strip()
    if not d:
        return ""
    labels = d.split(".")
    if len(labels) <= 2:
        return d
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES and len(labels) > 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# StevenBlack fetch + parse + disk cache
# ---------------------------------------------------------------------------
def fetch_stevenblack(force: bool = False) -> dict:
    """Fetch + parse + cache the blocklist. Returns status info dict.

    Parses "0.0.0.0 domain.tld" lines (also accepts 127.0.0.1 lines, which
    some alternates use). Cache survives offline operation; a daily refresh
    keeps it current.
    """
    with _lock:
        cached = _load_cache()
        fresh = (cached is not None and not force and cached.get("fetched_at")
                 and (utcnow() - _parse_iso(cached["fetched_at"])).total_seconds()
                 < config.BLOCKLIST_REFRESH_INTERVAL)
        if fresh:
            return {"source": cached["source"], "count": len(cached["domains"]),
                    "fetched_at": cached["fetched_at"], "cached": True}

        last_error = None
        for url in STEVENBLACK_URLS:
            try:
                resp = requests.get(url, timeout=30)
                if resp.status_code != 200:
                    last_error = f"HTTP {resp.status_code} from {url}"
                    continue
                domains = _parse_hosts_text(resp.text)
                if not domains:
                    last_error = f"no domains parsed from {url}"
                    continue
                payload = {
                    "source": url,
                    "fetched_at": utcnow().isoformat(),
                    "domains": sorted(domains),
                }
                _save_cache(payload)
                _set_memory(payload)
                Setting.set("blocklist_last_fetch", payload["fetched_at"])
                Setting.set("blocklist_source", url)
                Setting.set("blocklist_count", len(domains))
                return {"source": url, "count": len(domains),
                        "fetched_at": payload["fetched_at"], "cached": False}
            except Exception as exc:  # network failure -> try next source
                last_error = str(exc)
                logger.warning("blocklist fetch failed for %s: %s", url, exc)

        if cached is not None:
            # offline: serve the last good cache; it stays valid + refreshable
            return {"source": cached["source"], "count": len(cached["domains"]),
                    "fetched_at": cached["fetched_at"], "cached": True,
                    "error": last_error or "fetch failed — using cached copy"}
        return {"source": None, "count": 0, "fetched_at": None,
                "error": last_error or "fetch failed — no cache available"}


def _parse_hosts_text(text: str) -> set[str]:
    domains: set[str] = set()
    for line in text.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        dom = m.group(1).strip().lower()
        if not dom or dom in ("localhost", "localhost.localdomain", "broadcasthost"):
            continue
        if not re.match(r"^[0-9a-z.\-]+$", dom) or dom.count(".") < 1:
            continue
        domains.add(dom)
    return domains


def _load_cache() -> dict | None:
    try:
        with open(BLOCKLIST_CACHE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("domains"), list):
            return data
    except (OSError, ValueError):
        pass
    return None


def _save_cache(payload: dict) -> None:
    try:
        with open(BLOCKLIST_CACHE, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
    except OSError as exc:
        logger.warning("could not write blocklist cache: %s", exc)


def _parse_iso(iso: str):
    from datetime import datetime
    try:
        return datetime.fromisoformat(iso)
    except ValueError:
        return utcnow()


def _set_memory(payload: dict) -> None:
    global _memory_domains, _memory_source, _memory_fetched_at
    _memory_domains = set(payload["domains"])
    _memory_source = payload["source"]
    _memory_fetched_at = payload["fetched_at"]


def adult_domains() -> set[str]:
    """The fetched adult-content domain set (from cache or memory)."""
    global _memory_domains
    if _memory_domains is None:
        cached = _load_cache()
        if cached:
            _set_memory(cached)
        else:
            _memory_domains = set()
    return _memory_domains


def blocklist_status() -> dict:
    """Status shown on the Settings page (works offline via cache)."""
    cached = _load_cache()
    status = {
        "source": Setting.get("blocklist_source"),
        "last_fetch": Setting.get("blocklist_last_fetch"),
        "count": Setting.get("blocklist_count", 0),
    }
    if cached and not status["last_fetch"]:
        status["source"] = cached["source"]
        status["last_fetch"] = cached["fetched_at"]
        status["count"] = len(cached["domains"])
    return status


# ---------------------------------------------------------------------------
# Category registry (curated + fetched + user overrides)
# ---------------------------------------------------------------------------
def get_categories() -> dict[str, dict]:
    """Merged category map: name -> {label, domains, source, editable}."""
    cats = {k: dict(v, source="curated", editable=True)
            for k, v in CURATED_CATEGORIES.items()}
    cats[FETCHED_CATEGORY_KEY] = {
        "label": FETCHED_CATEGORY_LABEL,
        "domains": [],           # fetched set is stored separately
        "source": "fetched",
        "editable": False,
        "fetched_count": len(adult_domains()),
    }
    overrides = Setting.get("category_overrides", {}) or {}
    for name, domains in overrides.items():
        if name in cats and isinstance(domains, list):
            cats[name]["domains"] = [str(d).lower() for d in domains]
    return cats


def save_category_overrides(overrides: dict[str, list[str]]) -> None:
    cleaned = {k: [d.strip().lower() for d in v if d.strip()]
               for k, v in overrides.items()
               if k in CURATED_CATEGORIES}
    Setting.set("category_overrides", cleaned)


def reset_category_overrides() -> None:
    Setting.set("category_overrides", {})


def classify(domain: str) -> list[str]:
    """Category names matching a queried domain (badge list, not a replacement
    for showing the real domain)."""
    base = base_domain(domain)
    if not base:
        return []
    found: list[str] = []
    for name, cat in get_categories().items():
        if base in (cat["domains"] or []):
            found.append(name)
    if base in adult_domains():
        found.append(FETCHED_CATEGORY_KEY)
    return found


def categories_for_bases(bases: set[str]) -> dict[str, list[str]]:
    """Map a set of blocked base domains back to their category labels.

    Display-only helper — never touches the DB, so it is safe to call from
    session info() outside a request context.
    {"YouTube": ["youtube.com", "youtu.be", ...],
     "Adult content (StevenBlack hosts)": ["(N domains — StevenBlack list)"]}
    """
    result: dict[str, list[str]] = {}
    try:
        cats = get_categories()
    except Exception:
        cats = {k: dict(v, source="curated", editable=True)
                for k, v in CURATED_CATEGORIES.items()}
        cats[FETCHED_CATEGORY_KEY] = {
            "label": FETCHED_CATEGORY_LABEL, "domains": [],
            "source": "fetched",
        }
    for name, cat in cats.items():
        doms = [d for d in (cat["domains"] or []) if d in bases]
        if cat["source"] == "fetched":
            adult_hits = [b for b in bases if b in adult_domains()]
            if adult_hits:
                result[cat["label"]] = [f"({len(adult_hits)} domains — "
                                        "StevenBlack list)"]
        elif doms:
            # display "=host" rules without the marker
            result[cat["label"]] = [d[1:] if d.startswith("=") else d
                                    for d in doms]
    return result


def effective_blocked_domains(category_names: list[str]) -> set[str]:
    """Base-domain set for a list of category names (device+group+rule merge)."""
    blocked: set[str] = set()
    cats = get_categories()
    for name in category_names or []:
        cat = cats.get(name)
        if not cat:
            continue
        if cat["source"] == "fetched":
            blocked.update(adult_domains())
        else:
            blocked.update(cat["domains"] or [])
    return blocked
