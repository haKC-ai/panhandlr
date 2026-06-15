"""
search_backends.py

Multi-backend search engine for panhandlr.
All backends implement search(query) -> list[{name, title, url}]
and can be used interchangeably. Results always write to the same
CSV format so the rest of the pipeline is unaffected.

Backends:
  GoogleCSE   — existing, needs GOOGLE_SEARCH_API_KEY + GOOGLE_CSE_ID
  DuckDuckGo  — no key, uses duckduckgo-search library
  Reddit      — no key, uses Reddit JSON search API + Selenium scroll
  Twitter     — Selenium scroll (iWorkThereToo approach), no key
  Brave       — needs BRAVE_SEARCH_API_KEY, free tier 2k/mo
"""
import csv
import json
import os
import time
import logging
from abc import ABC, abstractmethod
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")
logger = logging.getLogger(__name__)

REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# Reddit requires a descriptive user-agent or it 403s
REDDIT_HEADERS = {
    "User-Agent": "ghostkey-osint/1.0 (security research tool)",
    "Accept": "application/json",
}
DEFAULT_RESULTS_DIR = "analysis"
OUTPUT_CSV_HEADERS = ["dork", "title", "dork_url"]


# ── base ─────────────────────────────────────────────────────────────────────

class SearchBackend(ABC):
    name: str = "base"

    @abstractmethod
    def search(self, query: str, dork_name: str = "") -> list[dict]:
        """Return list of {dork, title, dork_url}."""

    def is_available(self) -> bool:
        return True


# ── Google CSE ────────────────────────────────────────────────────────────────

class GoogleCSEBackend(SearchBackend):
    name = "google"

    def __init__(self):
        self.api_key = os.getenv("GOOGLE_SEARCH_API_KEY")
        self.cse_id = os.getenv("GOOGLE_CSE_ID")

    def is_available(self) -> bool:
        return bool(self.api_key and self.cse_id)

    def search(self, query: str, dork_name: str = "") -> list[dict]:
        from googleapiclient.discovery import build
        results = []
        try:
            service = build("customsearch", "v1", developerKey=self.api_key)
            res = service.cse().list(q=query, cx=self.cse_id, num=10).execute()
            for item in res.get("items", []):
                results.append({
                    "dork": dork_name or query,
                    "title": item.get("title", ""),
                    "dork_url": item.get("link", ""),
                })
            time.sleep(1.5)
        except Exception as e:
            logger.warning("[google] query failed: %s", e)
        return results


# ── DuckDuckGo ────────────────────────────────────────────────────────────────

class DuckDuckGoBackend(SearchBackend):
    name = "duckduckgo"

    def is_available(self) -> bool:
        try:
            from duckduckgo_search import DDGS
            return True
        except ImportError:
            return False

    def search(self, query: str, dork_name: str = "") -> list[dict]:
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            return []
        results = []
        try:
            with DDGS() as ddgs:
                for r in ddgs.text(query, max_results=10):
                    results.append({
                        "dork": dork_name or query,
                        "title": r.get("title", ""),
                        "dork_url": r.get("href", ""),
                    })
            time.sleep(0.5)
        except Exception as e:
            logger.warning("[ddg] query failed: %s", e)
        return results


# ── Brave Search ─────────────────────────────────────────────────────────────

class BraveBackend(SearchBackend):
    name = "brave"
    API_URL = "https://api.search.brave.com/res/v1/web/search"

    def __init__(self):
        self.api_key = os.getenv("BRAVE_SEARCH_API_KEY")

    def is_available(self) -> bool:
        return bool(self.api_key)

    def search(self, query: str, dork_name: str = "") -> list[dict]:
        results = []
        try:
            resp = requests.get(
                self.API_URL,
                headers={**REQUEST_HEADERS, "Accept": "application/json",
                         "X-Subscription-Token": self.api_key},
                params={"q": query, "count": 10},
                timeout=10,
            )
            resp.raise_for_status()
            for item in resp.json().get("web", {}).get("results", []):
                results.append({
                    "dork": dork_name or query,
                    "title": item.get("title", ""),
                    "dork_url": item.get("url", ""),
                })
            time.sleep(0.5)
        except Exception as e:
            logger.warning("[brave] query failed: %s", e)
        return results


# ── Reddit via pullpush.io ────────────────────────────────────────────────────

class RedditBackend(SearchBackend):
    """
    Uses pullpush.io (Pushshift alternative) — no key, no 403s.
    Searches by keyword + subreddit, filters for image posts only.
    """
    name = "reddit"

    PULLPUSH_URL = "https://api.pullpush.io/reddit/search/submission"

    # Best queries for surfacing physical key photos — global Reddit search
    KEY_QUERIES = [
        "got the keys new house",
        "house keys photo",
        "new apartment keys",
        "accidentally used wrong key",
        "spare key made",
        "closing day keys photo",
    ]

    # Subreddits with highest key photo density — used only for targeted bonus pass
    IMAGE_SUBS = ["mildlyinteresting", "pics", "homeowners"]

    @staticmethod
    def _strip_google_ops(query: str) -> str:
        import re
        q = re.sub(r'\b\w+:\S+', '', query)
        q = re.sub(r'\s+', ' ', q).strip().strip('"')
        return q

    def _pullpush_search(self, q: str, subreddit: str | None, dork_name: str, seen: set) -> list[dict]:
        results = []
        params = {"q": q, "limit": 25, "sort_type": "score", "is_self": "false"}
        if subreddit:
            params["subreddit"] = subreddit

        try:
            resp = requests.get(
                self.PULLPUSH_URL, params=params,
                headers={"User-Agent": "Mozilla/5.0"}, timeout=15,
            )
            resp.raise_for_status()
            for post in resp.json().get("data", []):
                url = post.get("url", "")
                permalink = f"https://www.reddit.com{post.get('permalink', '')}"
                if permalink in seen:
                    continue
                if not (url.endswith((".jpg", ".jpeg", ".png")) or
                        "i.redd.it" in url or "imgur.com" in url or
                        "reddit.com/gallery" in url):
                    continue
                seen.add(permalink)
                results.append({
                    "dork": dork_name or q,
                    "title": post.get("title", ""),
                    "dork_url": url if url.endswith((".jpg", ".jpeg", ".png")) else permalink,
                    "score": post.get("score", 0),
                    "subreddit": post.get("subreddit", ""),
                })
            time.sleep(12)  # pullpush rate limit: ~5 req/min max
        except Exception as e:
            if "429" in str(e):
                logger.warning("[reddit/pullpush] rate limited — sleeping 60s")
                time.sleep(60)
            else:
                logger.warning("[reddit/pullpush] %s failed: %s", q[:40], e)
        return results

    def _playwright_search(self, query: str, subreddit: str, dork_name: str, seen: set) -> list[dict]:
        """
        iWorkThereToo-style: real browser, scroll old.reddit.com, extract post links.
        Runs in a subprocess to avoid asyncio conflict when called from FastAPI.
        """
        import subprocess, json as _json, sys as _sys

        url = (
            f"https://old.reddit.com/r/{subreddit}/search"
            f"?q={requests.utils.quote(query)}&restrict_sr=on&sort=top&t=all"
        )

        script = f"""
import json
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=["--no-sandbox","--disable-dev-shm-usage"])
    page = browser.new_page(user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0")
    page.goto({url!r}, timeout=20000, wait_until="domcontentloaded")
    page.wait_for_timeout(2000)
    for _ in range(2):
        page.keyboard.press("End")
        page.wait_for_timeout(1500)
    links = page.eval_on_selector_all('a[href*="/comments/"]', 'els => [...new Set(els.map(e => e.href))]')
    browser.close()
    print(json.dumps(links))
"""

        results = []
        try:
            proc = subprocess.run(
                [_sys.executable, "-c", script],
                capture_output=True, text=True, timeout=40
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr[:200])
            links = _json.loads(proc.stdout.strip())
            for href in links:
                if "/comments/" not in href:
                    continue
                href = href.replace("old.reddit.com", "www.reddit.com")
                if href in seen:
                    continue
                seen.add(href)
                results.append({
                    "dork": dork_name or query,
                    "title": f"Reddit: {query}",
                    "dork_url": href,
                    "subreddit": subreddit,
                })
            logger.info("[reddit/playwright] r/%s | %r → %d posts", subreddit, query[:40], len(results))
        except Exception as e:
            logger.warning("[reddit/playwright] r/%s | %r failed: %s", subreddit, query[:40], e)
            results = self._pullpush_search(query, None, dork_name, seen)

        return results

    def search(self, query: str, dork_name: str = "") -> list[dict]:
        clean_q = self._strip_google_ops(query)
        if not clean_q:
            return []
        seen = set()
        results = []
        for sub in self.IMAGE_SUBS:
            results.extend(self._playwright_search(clean_q, sub, dork_name, seen))
        return results

    def search_native(self) -> list[dict]:
        """iWorkThereToo-style proactive scan: real browser, curated queries, target subs."""
        results = []
        seen = set()
        subs = ["mildlyinteresting", "pics", "homeowners", "firstworldproblems"]
        for q in self.KEY_QUERIES:
            for sub in subs:
                results.extend(self._playwright_search(q, sub, "reddit_native", seen))
        return results

        return results

    def scroll_subreddit_images(self, query: str, dork_name: str = "") -> list[dict]:
        """
        Selenium scroll — same approach as iWorkThereToo.
        Extracts direct image URLs from Reddit CDN (i.redd.it, preview.redd.it).
        """
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service as ChromeService
        from selenium.webdriver.common.by import By
        from selenium.common.exceptions import StaleElementReferenceException
        from webdriver_manager.chrome import ChromeDriverManager

        results = []
        image_urls = set()

        search_url = (
            f"https://www.reddit.com/search/?q={requests.utils.quote(query)}"
            f"&type=link&sort=top&t=all"
        )

        opts = Options()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument(f"user-agent={REQUEST_HEADERS['User-Agent']}")

        try:
            driver = webdriver.Chrome(
                service=ChromeService(ChromeDriverManager().install()), options=opts
            )
            driver.get(search_url)
            time.sleep(4)

            last_height = driver.execute_script("return document.body.scrollHeight")
            scrolls = 0

            while scrolls < 8:
                try:
                    imgs = driver.find_elements(By.TAG_NAME, "img")
                    for img in imgs:
                        src = img.get_attribute("src") or ""
                        if any(cdn in src for cdn in ("i.redd.it", "preview.redd.it",
                                                       "external-preview.redd.it")):
                            image_urls.add(src)
                    # Also grab post links
                    links = driver.find_elements(By.CSS_SELECTOR, "a[data-click-id='body']")
                    for link in links:
                        href = link.get_attribute("href") or ""
                        if "/r/" in href and href not in {r["dork_url"] for r in results}:
                            title = link.text.strip()[:200]
                            results.append({
                                "dork": dork_name or query,
                                "title": title,
                                "dork_url": href,
                            })
                except StaleElementReferenceException:
                    pass

                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(3)
                new_height = driver.execute_script("return document.body.scrollHeight")
                if new_height == last_height:
                    break
                last_height = new_height
                scrolls += 1

            driver.quit()

        except Exception as e:
            logger.warning("[reddit/selenium] scroll failed: %s", e)

        # Add direct image URLs as synthetic results
        for img_url in image_urls:
            results.append({
                "dork": dork_name or query,
                "title": f"Reddit image: {img_url.split('/')[-1]}",
                "dork_url": img_url,
            })

        return results


# ── Twitter / X ───────────────────────────────────────────────────────────────

class TwitterBackend(SearchBackend):
    """
    Selenium scroll — direct port of iWorkThereToo approach.
    No API key. Extracts pbs.twimg.com/media image URLs.
    """
    name = "twitter"

    def is_available(self) -> bool:
        try:
            from selenium import webdriver
            return True
        except ImportError:
            return False

    def search(self, query: str, dork_name: str = "") -> list[dict]:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service as ChromeService
        from selenium.webdriver.common.by import By
        from selenium.common.exceptions import StaleElementReferenceException
        from webdriver_manager.chrome import ChromeDriverManager

        results = []
        image_urls = set()
        post_urls = set()

        encoded = requests.utils.quote(query)
        search_url = f"https://twitter.com/search?q={encoded}&src=typed_query&f=live"

        opts = Options()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument(f"user-agent={REQUEST_HEADERS['User-Agent']}")

        try:
            driver = webdriver.Chrome(
                service=ChromeService(ChromeDriverManager().install()), options=opts
            )
            driver.get(search_url)
            time.sleep(5)

            last_height = driver.execute_script("return document.body.scrollHeight")
            scrolls = 0

            while scrolls < 10:
                try:
                    # Grab tweet images (iWorkThereToo approach)
                    imgs = driver.find_elements(By.TAG_NAME, "img")
                    for img in imgs:
                        src = img.get_attribute("src") or ""
                        if "pbs.twimg.com/media" in src:
                            image_urls.add(src)

                    # Also grab tweet post links for context
                    links = driver.find_elements(By.CSS_SELECTOR, "a[href*='/status/']")
                    for link in links:
                        href = link.get_attribute("href") or ""
                        if "/status/" in href and href not in post_urls:
                            post_urls.add(href)

                except StaleElementReferenceException:
                    pass

                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(3)
                new_height = driver.execute_script("return document.body.scrollHeight")
                if new_height == last_height:
                    break
                last_height = new_height
                scrolls += 1

            driver.quit()
            logger.info("[twitter] %d images, %d posts for: %s",
                        len(image_urls), len(post_urls), query)

        except Exception as e:
            logger.warning("[twitter/selenium] failed: %s", e)

        # Images first — these go straight to vision scanner
        for img_url in image_urls:
            results.append({
                "dork": dork_name or query,
                "title": f"Twitter image: {img_url.split('/')[-1].split('?')[0]}",
                "dork_url": img_url,
            })
        # Post URLs as fallback
        for post_url in post_urls:
            if post_url not in {r["dork_url"] for r in results}:
                results.append({
                    "dork": dork_name or query,
                    "title": "Twitter post",
                    "dork_url": post_url,
                })

        return results


# ── LinkedIn ──────────────────────────────────────────────────────────────────

class LinkedInBackend(SearchBackend):
    """
    Selenium scroll on LinkedIn public search.
    No key. Requires being logged in for full results — uses session
    cookies if LINKEDIN_COOKIE env var is set (li_at cookie value).
    """
    name = "linkedin"

    def is_available(self) -> bool:
        try:
            from selenium import webdriver
            return True
        except ImportError:
            return False

    def search(self, query: str, dork_name: str = "") -> list[dict]:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service as ChromeService
        from selenium.webdriver.common.by import By
        from selenium.common.exceptions import StaleElementReferenceException
        from webdriver_manager.chrome import ChromeDriverManager

        results = []
        seen = set()
        li_at = os.getenv("LINKEDIN_COOKIE", "")

        encoded = requests.utils.quote(query)
        search_url = f"https://www.linkedin.com/search/results/content/?keywords={encoded}&origin=GLOBAL_SEARCH_HEADER"

        opts = Options()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument(f"user-agent={REQUEST_HEADERS['User-Agent']}")

        try:
            driver = webdriver.Chrome(
                service=ChromeService(ChromeDriverManager().install()), options=opts
            )
            driver.get("https://www.linkedin.com")
            time.sleep(2)

            if li_at:
                driver.add_cookie({"name": "li_at", "value": li_at,
                                   "domain": ".linkedin.com"})

            driver.get(search_url)
            time.sleep(4)

            last_height = driver.execute_script("return document.body.scrollHeight")
            scrolls = 0

            while scrolls < 6:
                try:
                    # Post links
                    links = driver.find_elements(
                        By.CSS_SELECTOR,
                        "a.app-aware-link[href*='/posts/'], a[href*='activity-']"
                    )
                    for link in links:
                        href = link.get_attribute("href") or ""
                        if href and href not in seen:
                            seen.add(href)
                            results.append({
                                "dork": dork_name or query,
                                "title": link.text.strip()[:200] or "LinkedIn post",
                                "dork_url": href,
                            })

                    # Images in feed
                    imgs = driver.find_elements(By.CSS_SELECTOR, "img.ivm-view-attr__img--centered")
                    for img in imgs:
                        src = img.get_attribute("src") or ""
                        if "media.licdn.com" in src and src not in seen:
                            seen.add(src)
                            results.append({
                                "dork": dork_name or query,
                                "title": f"LinkedIn image: {src.split('/')[-1][:60]}",
                                "dork_url": src,
                            })

                except StaleElementReferenceException:
                    pass

                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(3)
                new_height = driver.execute_script("return document.body.scrollHeight")
                if new_height == last_height:
                    break
                last_height = new_height
                scrolls += 1

            driver.quit()

        except Exception as e:
            logger.warning("[linkedin/selenium] failed: %s", e)

        return results


# ── multi-backend runner ──────────────────────────────────────────────────────

ALL_BACKENDS = {
    "google":     GoogleCSEBackend,
    "duckduckgo": DuckDuckGoBackend,
    "brave":      BraveBackend,
    "reddit":     RedditBackend,
    "twitter":    TwitterBackend,
    "linkedin":   LinkedInBackend,
}


def run_all(
    dork_queries: list[dict],
    results_dir: str = DEFAULT_RESULTS_DIR,
    backends: list[str] | None = None,
    domain: str | None = None,
) -> str:
    """
    Run dork_queries through all available (or specified) backends.
    Writes unified CSV. Returns output file path.
    """
    os.makedirs(results_dir, exist_ok=True)
    output_file = os.path.join(
        results_dir,
        f"{domain}_multi_search.csv" if domain else "global_multi_search.csv"
    )

    enabled = backends or list(ALL_BACKENDS.keys())
    active = []
    for name in enabled:
        cls = ALL_BACKENDS.get(name)
        if cls:
            b = cls()
            if b.is_available():
                active.append(b)
                logger.info("[search] backend available: %s", name)
            else:
                logger.info("[search] backend unavailable (missing key/dep): %s", name)

    if not active:
        logger.error("[search] no backends available")
        return output_file

    all_results = []
    seen_urls = set()

    # Always run Reddit native proactive scan first — guaranteed image results
    reddit_b = next((b for b in active if isinstance(b, RedditBackend)), None)
    if reddit_b:
        logger.info("[search] running Reddit native key scan...")
        for r in reddit_b.search_native():
            url = r.get("dork_url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                all_results.append(r)
        logger.info("[search] Reddit native: %d results so far", len(all_results))

    for dork in dork_queries:
        name = dork.get("name", "")
        category = dork.get("category", "")
        queries = dork.get("queries") or ([dork.get("dork")] if dork.get("dork") else [])

        for query in queries:
            if not query:
                continue
            if domain:
                query = query.replace("{domain}", domain)

            # Route by category: reddit_* queries only to Google/DDG/Brave (they handle site: ops)
            # social_media category goes to Reddit native backend only
            for backend in active:
                if category == "social_media" and not isinstance(backend, RedditBackend):
                    continue  # social_media queries are plain terms for Reddit
                if category == "social_media" and isinstance(backend, RedditBackend):
                    results = backend.search(query, dork_name=name)
                elif isinstance(backend, RedditBackend):
                    continue  # non-social_media dorks don't go to Reddit
                else:
                    results = backend.search(query, dork_name=name)

                for r in results:
                    url = r.get("dork_url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        all_results.append(r)

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_CSV_HEADERS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_results)

    logger.info("[search] %d unique results → %s", len(all_results), output_file)
    return output_file
