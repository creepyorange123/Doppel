"""Breakage probe (original plan, stretch).

Reloads a page in headless Playwright with one company's requests blocked and
compares a screenshot and key page elements against a normal load. If the page
looks and works the same, the request wasn't needed for you, only for someone
else (+10); if the page breaks, it's minimum utility (-20).

Safety (step-by-step plan, security #12): a fresh browser profile each run and
GET requests only, so nothing is ever submitted or repeated.

    python -m demo.breakage_probe https://news.example/ ads.criteo.com
"""

from __future__ import annotations

import argparse
import io
from dataclasses import dataclass
from urllib.parse import urlsplit

from analyzer.identify import registrable_domain
from shared import db

TEXT_DROP = 0.7        # page lost more than 30% of its text
LINK_DROP = 0.7
PIXEL_CHANGE = 0.15    # more than 15% of the screenshot changed


@dataclass
class PageSnapshot:
    title: str
    text_length: int
    links: int
    images: int
    pixels: bytes  # greyscale screenshot, same size for both loads


def compare(normal: PageSnapshot, blocked: PageSnapshot) -> str:
    if normal.title and not blocked.title:
        return "breaks"
    if normal.text_length and blocked.text_length < normal.text_length * TEXT_DROP:
        return "breaks"
    if normal.links and blocked.links < normal.links * LINK_DROP:
        return "breaks"
    n = min(len(normal.pixels), len(blocked.pixels))
    if n:
        changed = sum(1 for a, b in zip(normal.pixels[:n], blocked.pixels[:n]) if abs(a - b) > 32)
        if changed / n > PIXEL_CHANGE:
            return "breaks"
    return "works"


def should_abort(url: str, method: str, blocked_domains: set[str]) -> bool:
    if method.upper() != "GET":
        return True
    host = (urlsplit(url).hostname or "").lower()
    return registrable_domain(host) in blocked_domains


def save_result(conn, dest_domain: str, result: str, page_site: str | None) -> None:
    conn.execute(
        "INSERT INTO breakage (domain, result, page_site, probed_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(domain) DO UPDATE SET result = excluded.result, page_site = excluded.page_site, "
        "probed_at = excluded.probed_at",
        (registrable_domain(dest_domain), result, page_site, db.now_ms()),
    )


def _snapshot(page) -> PageSnapshot:
    from PIL import Image  # from requirements-demo.txt

    png = page.screenshot(full_page=False)
    img = Image.open(io.BytesIO(png)).convert("L").resize((160, 100))
    return PageSnapshot(
        title=page.title(),
        text_length=page.evaluate("document.body ? document.body.innerText.length : 0"),
        links=page.locator("a[href]").count(),
        images=page.locator("img").count(),
        pixels=img.tobytes(),
    )


def probe(url: str, dest_domain: str, extra_domains: set[str] | None = None) -> str:
    from playwright.sync_api import sync_playwright

    blocked = {registrable_domain(dest_domain)} | (extra_domains or set())
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        def load(block: bool) -> PageSnapshot:
            context = browser.new_context(viewport={"width": 1280, "height": 800})  # fresh profile
            page = context.new_page()
            page.route("**/*", lambda route, req: route.abort()
                       if should_abort(req.url, req.method, blocked if block else set()) else route.continue_())
            page.goto(url, wait_until="networkidle", timeout=45_000)
            snap = _snapshot(page)
            context.close()
            return snap

        result = compare(load(False), load(True))
        browser.close()
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="demo.breakage_probe")
    ap.add_argument("page_url")
    ap.add_argument("dest_domain")
    a = ap.parse_args(argv)
    result = probe(a.page_url, a.dest_domain)
    conn = db.open_db()
    save_result(conn, a.dest_domain, result, urlsplit(a.page_url).hostname)
    print(f"{a.dest_domain}: page {'works' if result == 'works' else 'breaks'} without it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
