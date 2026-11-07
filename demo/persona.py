"""Phase 7: Playwright persona, run the night before the demo so the first
'since last open' report is full.

Original plan: "a made-up persona, say someone researching a medical condition,
comparing loans and reading news, across about 15 sites".

    pip install -r requirements-demo.txt && python -m playwright install chromium
    python -m demo.persona            # with the recorder running

The persona only navigates (GET) public pages in a fresh, throwaway browser
profile: no logins, no forms, no searches, no personal data.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Visit:
    url: str
    theme: str  # "medical" | "loans" | "news"
    actions: tuple[str, ...] = ("scroll", "wait")


VISITS: list[Visit] = [
    # Researching a medical condition (type 2 diabetes).
    Visit("https://www.webmd.com/diabetes/type-2-diabetes", "medical"),
    Visit("https://www.mayoclinic.org/diseases-conditions/type-2-diabetes/symptoms-causes/syc-20351193", "medical"),
    Visit("https://www.healthline.com/health/type-2-diabetes", "medical"),
    Visit("https://www.medicalnewstoday.com/articles/317462", "medical"),
    Visit("https://www.everydayhealth.com/type-2-diabetes/", "medical"),
    # Comparing loans.
    Visit("https://www.nerdwallet.com/personal-loans", "loans"),
    Visit("https://www.bankrate.com/loans/personal-loans/", "loans"),
    Visit("https://www.lendingtree.com/personal/", "loans"),
    Visit("https://www.creditkarma.com/personal-loans", "loans"),
    Visit("https://www.investopedia.com/best-personal-loans-4773296", "loans"),
    # Reading news.
    Visit("https://www.cnn.com/", "news", ("scroll", "wait", "click_first_article")),
    Visit("https://www.theguardian.com/international", "news", ("scroll", "wait", "click_first_article")),
    Visit("https://www.usatoday.com/", "news"),
    Visit("https://www.foxnews.com/", "news"),
    Visit("https://www.washingtonpost.com/", "news"),
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
                print(f"visited {v.url} ({v.theme})")
            except Exception as exc:  # a slow site shouldn't stop the persona
                print(f"skipped {v.url}: {type(exc).__name__}")
        context.close()
        browser.close()


if __name__ == "__main__":
    run()
