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
        from duckduckgo_search import DDGS
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


# ── Reddit ────────────────────────────────────────────────────────────────────

class RedditBackend(SearchBackend):
    """
    No key needed. Uses Reddit's JSON search API.
    Targets specific subreddits or global search.
    Falls back to Selenium scroll for image-heavy posts.
    """
    name = "reddit"

    SEARCH_URL = "https://www.reddit.com/search.json"
    SUBREDDIT_SEARCH = "https://www.reddit.com/r/{sub}/search.json"

    # Subreddits likely to have organic key photos
    TARGET_SUBS = [
        "mildlyinteresting", "pics", "funny", "firstworldproblems",
        "movingtips", "homeowners", "DIY", "lockpicking",
    ]

    @staticmethod
    def _reddit_query(query: str) -> str:
        """Strip Google-specific operators Reddit doesn't understand."""
        import re
        q = re.sub(r'site:\S+', '', query)
        q = re.sub(r'filetype:\S+', '', q)
        q = re.sub(r'inurl:\S+', '', q)
        q = re.sub(r'intitle:\S+', '', q)
        q = re.sub(r'\s+', ' ', q).strip().strip('"').strip()
        return q or query  # fall back to original if we wiped everything

    def _parse_posts(self, data: dict, dork_name: str, query: str, seen: set) -> list[dict]:
        results = []
        for child in data.get("data", {}).get("children", []):
            post = child.get("data", {})
            # Only include posts with images (url points to image or gallery)
            post_url = post.get("url", "")
            permalink = f"https://www.reddit.com{post.get('permalink', '')}"
            if permalink in seen:
                continue
            seen.add(permalink)
            results.append({
                "dork": dork_name or query,
                "title": post.get("title", ""),
                "dork_url": permalink,
                "image_url": post_url if post_url.endswith((".jpg", ".jpeg", ".png")) else "",
                "score": post.get("score", 0),
                "subreddit": post.get("subreddit", ""),
            })
        return results

    def search(self, query: str, dork_name: str = "") -> list[dict]:
        results = []
        seen = set()
        reddit_q = self._reddit_query(query)

        if not reddit_q:
            return results

        # Global search only — per-subreddit hammering causes rate-limits
        try:
            resp = requests.get(
                self.SEARCH_URL,
                headers=REDDIT_HEADERS,
                params={"q": reddit_q, "type": "link", "limit": 25,
                        "sort": "top", "t": "all"},
                timeout=15,
            )
            resp.raise_for_status()
            results.extend(self._parse_posts(resp.json(), dork_name, query, seen))
            time.sleep(2.0)  # Reddit rate limit: be polite
        except Exception as e:
            logger.warning("[reddit] search failed for %r: %s", reddit_q[:60], e)

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

    for dork in dork_queries:
        name = dork.get("name", "")
        # Support both old format (single "dork") and new key_photos.json format (list "queries")
        queries = dork.get("queries") or ([dork.get("dork")] if dork.get("dork") else [])

        for query in queries:
            if not query:
                continue
            if domain:
                query = query.replace("{domain}", domain)

            for backend in active:
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
