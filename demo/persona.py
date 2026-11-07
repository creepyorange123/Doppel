"""Phase 7: Playwright persona, run the night before the demo so the first
'since last open' report is full.

    pip install -r requirements-demo.txt && python -m playwright install chromium
    python -m demo.persona            # with the recorder running

The persona only navigates (GET) public pages in a fresh, throwaway browser
profile: no logins, no forms, no searches, no personal data.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Visit:
    url: str
    actions: tuple[str, ...] = ("scroll", "wait")
    note: str = ""


# A reader who checks the news, a health worry, money, a recipe and some shopping.
VISITS: list[Visit] = [
    Visit("https://www.cnn.com/", note="news"),
    Visit("https://www.theguardian.com/international", ("scroll", "wait", "click_first_article"), "news"),
    Visit("https://www.webmd.com/", note="health (sensitive)"),
    Visit("https://www.mayoclinic.org/diseases-conditions", note="health (sensitive)"),
    Visit("https://www.healthline.com/", note="health (sensitive)"),
    Visit("https://www.nerdwallet.com/", note="personal finance (sensitive)"),
    Visit("https://www.bankrate.com/", note="personal finance (sensitive)"),
    Visit("https://www.allrecipes.com/", note="food"),
    Visit("https://www.weather.com/", note="weather"),
    Visit("https://www.espn.com/", note="sports"),
    Visit("https://www.imdb.com/", note="movies"),
    Visit("https://www.target.com/", note="shopping"),
]

LAUNCH_OPTIONS = {"persistent": False, "headless": False}


def run(visits: list[Visit] = VISITS, dwell: tuple[float, float] = (6, 12)) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=LAUNCH_OPTIONS["headless"])
        context = browser.new_context()  # fresh profile every run; discarded at the end
        page = context.new_page()
        for v in visits:
            try:
                page.goto(v.url, wait_until="domcontentloaded", timeout=45_000)
                for action in v.actions:
                    if action == "scroll":
                        for _ in range(6):
                            page.mouse.wheel(0, 900)
                            time.sleep(0.8)
                    elif action == "wait":
                        time.sleep(random.uniform(*dwell))
                    elif action == "click_first_article":
                        link = page.locator("article a[href^='https://']").first
                        if link.count():
                            link.click(timeout=10_000)
                            time.sleep(random.uniform(*dwell))
                print(f"visited {v.url} ({v.note})")
            except Exception as exc:  # a slow site shouldn't stop the persona
                print(f"skipped {v.url}: {type(exc).__name__}")
        context.close()
        browser.close()


if __name__ == "__main__":
    run()
