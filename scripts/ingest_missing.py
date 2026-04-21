#!/usr/bin/env python3
"""
ingest_missing.py — Fetch remaining 0xdf walkthroughs not in corpus.

Strategy:
1. Parse sitemap.xml for all htb-* URLs
2. Match against missing box names
3. For boxes not in sitemap, try the tags page links
4. Ingest each missing box

Usage:
    python3 ingest_missing.py [--limit N] [--dry-run]
"""

import json
import re
import sys
import time
import warnings
from pathlib import Path

import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

WALKTHROUGHS_DIR = Path("/home/kali/knowledge/walkthroughs")
MANIFEST_PATH = WALKTHROUGHS_DIR / "manifest.json"
BASE_URL = "https://0xdf.gitlab.io"
RATE_LIMIT = 1.2

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "TAR-WalkthroughIngest/2.0 (educational; HTB retired-box corpus)"
})


def fetch(url, timeout=30):
    try:
        r = SESSION.get(url, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as e:
        return None


def get_sitemap_urls():
    """Get ALL URLs from sitemap.xml."""
    xml = fetch(f"{BASE_URL}/sitemap.xml")
    if not xml:
        return {}
    soup = BeautifulSoup(xml, "html.parser")
    urls = {}
    for loc in soup.find_all("loc"):
        url = loc.text.strip()
        # Match htb-boxname pattern
        m = re.search(r"/htb-(\w+)\.html", url)
        if m:
            box = m.group(1).lower()
            urls[box] = url
    return urls


def get_tags_page_urls():
    """Get box→URL mapping from the tags page HTML."""
    html = fetch(f"{BASE_URL}/tags")
    if not html:
        return {}

    urls = {}
    soup = BeautifulSoup(html, "html.parser")

    # Find all links that look like HTB writeups
    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = a.get_text(strip=True).lower()

        # Match /YYYY/MM/DD/htb-boxname.html links
        m = re.search(r"/(\d{4}/\d{2}/\d{2})/htb-(\w+)\.html", href)
        if m:
            box = m.group(2).lower()
            full_url = href if href.startswith("http") else f"{BASE_URL}{href}"
            urls[box] = full_url
            continue

        # Match tag references like htb-boxname
        m2 = re.match(r"htb-(\w+)", text)
        if m2:
            box = m2.group(1).lower()
            # We know the tag exists but don't have the URL yet
            if box not in urls:
                urls[box] = None  # Mark as needing URL discovery

    return urls


def extract_content(html):
    """Extract writeup content from 0xdf HTML."""
    soup = BeautifulSoup(html, "html.parser")
    article = soup.find("article") or soup.find("div", class_="post-content") or soup.find("div", class_="entry-content")
    if not article:
        article = soup.find("body")
    if not article:
        return ""

    for tag in article.find_all(["nav", "footer", "script", "style", "aside"]):
        tag.decompose()

    lines = []
    for elem in article.descendants:
        if elem.name in ("h1", "h2", "h3", "h4"):
            level = int(elem.name[1])
            lines.append(f"\n{'#' * level} {elem.get_text(strip=True)}\n")
        elif elem.name == "p":
            text = elem.get_text(separator=" ", strip=True)
            if text:
                lines.append(text + "\n")
        elif elem.name == "pre" or elem.name == "code":
            if elem.parent and elem.parent.name == "pre" and elem.name == "code":
                continue
            code = elem.get_text()
            if code.strip():
                lines.append(f"\n```\n{code}\n```\n")

    content = "\n".join(lines)
    content = re.sub(r"\n{3,}", "\n\n", content)
    return content.strip()


def discover_url_for_box(box_name):
    """Try to find the URL for a box not in sitemap."""
    # Try fetching the tag page for this box
    tag_html = fetch(f"{BASE_URL}/tags#htb-{box_name}")
    if tag_html:
        soup = BeautifulSoup(tag_html, "html.parser")
        # Look for the writeup link under this tag
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if f"htb-{box_name}" in href.lower() and href.endswith(".html"):
                return href if href.startswith("http") else f"{BASE_URL}{href}"
    return None


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0, help="Max boxes to fetch (0=all)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--box", help="Fetch single box by name")
    args = parser.parse_args()

    # Load manifest
    manifest = json.loads(MANIFEST_PATH.read_text()) if MANIFEST_PATH.exists() else {"boxes": {}}

    # Get existing boxes
    existing = set()
    for d in WALKTHROUGHS_DIR.iterdir():
        if d.is_dir() and (d / "raw.md").exists():
            existing.add(d.name)

    print(f"[*] Currently have {len(existing)} walkthroughs")

    # Get all 0xdf URLs
    print("[*] Fetching sitemap...")
    sitemap_urls = get_sitemap_urls()
    print(f"[+] Sitemap has {len(sitemap_urls)} HTB writeup URLs")

    # Also parse tags page for additional URLs
    print("[*] Fetching tags page...")
    tags_urls = get_tags_page_urls()
    print(f"[+] Tags page has {len(tags_urls)} HTB references")

    # Merge: sitemap takes priority
    all_urls = {**tags_urls, **sitemap_urls}

    # Find missing boxes
    if args.box:
        missing = {args.box} - existing
    else:
        missing = set(all_urls.keys()) - existing

    print(f"[*] Missing: {len(missing)} boxes to ingest")

    if args.dry_run:
        for box in sorted(missing):
            url = all_urls.get(box, "???")
            print(f"  {box}: {url}")
        return 0

    # Ingest missing boxes
    ingested = 0
    failed = 0

    for box in sorted(missing):
        if args.limit and ingested >= args.limit:
            print(f"[*] Reached limit of {args.limit}")
            break

        url = all_urls.get(box)

        # If no URL from sitemap/tags, try to discover
        if not url:
            url = discover_url_for_box(box)

        if not url:
            print(f"  [!] No URL found for {box}")
            failed += 1
            continue

        print(f"  [>] Fetching {box} from {url}")
        html = fetch(url)
        if not html:
            print(f"  [!] Failed to fetch {box}")
            failed += 1
            manifest["boxes"][box] = {"status": "failed", "url": url}
            continue

        content = extract_content(html)
        if len(content) < 200:
            print(f"  [!] Content too short for {box} ({len(content)} chars)")
            failed += 1
            manifest["boxes"][box] = {"status": "failed_parse", "url": url}
            continue

        # Write
        box_dir = WALKTHROUGHS_DIR / box
        box_dir.mkdir(parents=True, exist_ok=True)
        raw_path = box_dir / "raw.md"

        header = f"# HTB: {box.capitalize()}\nSource: {url}\n\n"
        raw_path.write_text(header + content)

        # Classify difficulty
        lower = content.lower()
        difficulty = "unknown"
        for diff in ["insane", "hard", "medium", "easy"]:
            if diff in lower[:2000]:
                difficulty = diff
                break

        manifest["boxes"][box] = {
            "status": "done", "source": "0xdf", "url": url,
            "difficulty": difficulty, "size_chars": len(content)
        }

        ingested += 1
        print(f"  [+] {box} ({len(content)} chars, {difficulty})")

        # Save manifest periodically
        if ingested % 10 == 0:
            MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True))

        time.sleep(RATE_LIMIT)

    # Final save
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"\n[=] Ingested: {ingested}, Failed: {failed}, Total now: {len(existing) + ingested}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
