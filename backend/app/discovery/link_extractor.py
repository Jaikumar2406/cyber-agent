"""Link extraction from HTML (phases.md §1.2 crawler).

Uses only the stdlib `html.parser` so it works offline with zero third-party
dependencies in an air-gapped deployment (rules.md §3). Extracts candidate URLs
from anchors, links, script/src, iframe/src, img/src and form actions, then
resolves them against the page URL and discards non-http(s) schemes.
"""

import urllib.parse
from html.parser import HTMLParser

_LINK_ATTRS = {
    "a": "href",
    "link": "href",
    "script": "src",
    "iframe": "src",
    "img": "src",
    "source": "src",
    "frame": "src",
}

_NON_HTTP_SCHEMES = {
    "javascript",
    "mailto",
    "tel",
    "data",
    "about",
    "blob",
    "ftp",
    "file",
    "ws",
    "wss",
    "viber",
    "whatsapp",
    "sms",
    "skype",
}


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[tuple[str, str]] = []  # (action, method)

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: N802
        attrs = dict(attrs)
        if tag in _LINK_ATTRS:
            value = (attrs.get(_LINK_ATTRS[tag]) or "").strip()
            if value:
                self.links.append(value)
        elif tag == "form":
            action = (attrs.get("action") or "").strip()
            if action:
                self.forms.append((action, (attrs.get("method") or "GET").upper()))


def _is_http_url(parsed: urllib.parse.SplitResult) -> bool:
    if parsed.scheme not in _NON_HTTP_SCHEMES and parsed.scheme not in ("http", "https"):
        return False
    return parsed.scheme in ("http", "https")


def extract_links(html: str, base_url: str) -> list[str]:
    """Extract absolute http(s) URLs from an HTML document.

    Fragments (#...) are stripped; scheme-relative (//host/path) and relative
    URLs resolve against `base_url`. Empty schemes (relative paths) resolve to
    http(s) via urljoin.
    """
    parser = _LinkExtractor()
    parser.feed(html or "")
    raw = parser.links
    raw += [action for action, _ in parser.forms]

    resolved: list[str] = []
    for value in raw:
        value = value.strip()
        if not value or value.startswith("#"):
            continue
        try:
            absolute = urllib.parse.urljoin(base_url, value)
        except ValueError:
            continue
        parsed = urllib.parse.urlsplit(absolute)
        if not _is_http_url(parsed):
            continue
        if parsed.scheme not in ("http", "https"):
            continue
        # Normalize: drop fragment, keep rest.
        normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        resolved.append(normalized)
    return resolved


def extract_forms(html: str, base_url: str) -> list[tuple[str, str]]:
    """Extract (absolute_url, method) pairs from <form> elements."""
    parser = _LinkExtractor()
    parser.feed(html or "")
    forms: list[tuple[str, str]] = []
    for action, method in parser.forms:
        try:
            absolute = urllib.parse.urljoin(base_url, action)
        except ValueError:
            continue
        parsed = urllib.parse.urlsplit(absolute)
        if not _is_http_url(parsed):
            continue
        normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        forms.append((normalized, method))
    return forms


def is_same_host(url_a: str, url_b: str) -> bool:
    """True when both URLs share the same resolved host (ports ignored)."""
    a = urllib.parse.urlsplit(url_a)
    b = urllib.parse.urlsplit(url_b)
    return (a.hostname or "").lower() == (b.hostname or "").lower()