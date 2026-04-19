#!/usr/bin/env python3
"""
walkthrough_ingest.py — Fetch retired HTB walkthroughs from public sources.
Stores raw markdown at /home/kali/knowledge/walkthroughs/<box>/raw.md
Tracks progress in manifest.json for resume-on-failure.
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin

import warnings

import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

WALKTHROUGHS_DIR = Path("/home/kali/knowledge/walkthroughs")
MANIFEST_PATH = WALKTHROUGHS_DIR / "manifest.json"
BASE_URL = "https://0xdf.gitlab.io"
RATE_LIMIT = 1.5  # seconds between requests

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "TAR-WalkthroughIngest/1.0 (educational; HTB retired-box corpus)"
})


def load_manifest() -> dict:
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text())
    return {"boxes": {}, "source": "0xdf.gitlab.io", "version": 1}


def save_manifest(manifest: dict):
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True))


def fetch_page(url: str) -> str | None:
    try:
        resp = SESSION.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        print(f"  [!] Failed to fetch {url}: {e}", file=sys.stderr)
        return None


def discover_0xdf_htb_posts() -> list[dict]:
    """Parse 0xdf sitemap.xml to get all retired-box writeup URLs."""
    print("[*] Discovering HTB writeups from 0xdf.gitlab.io sitemap...")
    posts = []

    sitemap_html = fetch_page(f"{BASE_URL}/sitemap.xml")
    if not sitemap_html:
        print("[!] Cannot fetch sitemap.xml. Check network.", file=sys.stderr)
        return []

    soup = BeautifulSoup(sitemap_html, "html.parser")
    for loc in soup.find_all("loc"):
        url = loc.text.strip()
        match = re.search(r"/(\d{4}/\d{2}/\d{2})/htb-(\w+)\.html", url)
        if match:
            date_str = match.group(1).replace("/", "-")
            box_name = match.group(2).lower()
            posts.append({
                "name": box_name,
                "url": url,
                "date": date_str,
                "source": "0xdf",
            })

    print(f"[+] Discovered {len(posts)} HTB writeups")
    return posts


def extract_writeup_content(html: str) -> str:
    """Extract main article content from 0xdf post HTML, convert to clean markdown-ish text."""
    soup = BeautifulSoup(html, "html.parser")

    # 0xdf uses <article> or <div class="post-content">
    article = soup.find("article") or soup.find("div", class_="post-content") or soup.find("div", class_="entry-content")

    if not article:
        # Fallback: take the whole body
        article = soup.find("body")

    if not article:
        return ""

    # Remove nav, footer, scripts, styles
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
                continue  # handled by parent
            code = elem.get_text()
            if code.strip():
                lines.append(f"\n```\n{code.strip()}\n```\n")
        elif elem.name == "li":
            text = elem.get_text(separator=" ", strip=True)
            if text:
                lines.append(f"- {text}")
        elif elem.name == "img":
            alt = elem.get("alt", "")
            src = elem.get("src", "")
            if src:
                lines.append(f"![{alt}]({src})")

    content = "\n".join(lines)
    # Clean up excessive whitespace
    content = re.sub(r"\n{3,}", "\n\n", content)
    return content.strip()


def classify_difficulty(content: str) -> str:
    """Heuristic difficulty classification from writeup content."""
    lower = content.lower()
    for diff in ["insane", "hard", "medium", "easy"]:
        if diff in lower[:2000]:  # Usually in the intro
            return diff
    return "unknown"


def ingest_box(box: dict, manifest: dict) -> bool:
    """Download and store a single box walkthrough. Returns True if newly ingested."""
    name = box["name"]

    if name in manifest["boxes"] and manifest["boxes"][name].get("status") == "done":
        return False

    box_dir = WALKTHROUGHS_DIR / name
    box_dir.mkdir(parents=True, exist_ok=True)
    raw_path = box_dir / "raw.md"

    if raw_path.exists() and raw_path.stat().st_size > 500:
        manifest["boxes"][name] = {
            "status": "done",
            "source": box.get("source", "0xdf"),
            "url": box["url"],
            "date": box.get("date", ""),
            "difficulty": classify_difficulty(raw_path.read_text()),
        }
        save_manifest(manifest)
        return False

    print(f"  [>] Fetching {name} from {box['url']}")
    html = fetch_page(box["url"])
    if not html:
        manifest["boxes"][name] = {"status": "failed", "url": box["url"]}
        save_manifest(manifest)
        return False

    content = extract_writeup_content(html)
    if len(content) < 200:
        print(f"  [!] Extracted content too short for {name} ({len(content)} chars), skipping")
        manifest["boxes"][name] = {"status": "failed_parse", "url": box["url"]}
        save_manifest(manifest)
        return False

    # Write raw markdown
    header = f"# HTB: {name.capitalize()}\n"
    header += f"Source: {box['url']}\n"
    header += f"Date: {box.get('date', 'unknown')}\n\n"
    raw_path.write_text(header + content)

    difficulty = classify_difficulty(content)
    manifest["boxes"][name] = {
        "status": "done",
        "source": box.get("source", "0xdf"),
        "url": box["url"],
        "date": box.get("date", ""),
        "difficulty": difficulty,
        "size_chars": len(content),
    }
    save_manifest(manifest)
    print(f"  [+] {name} ingested ({len(content)} chars, difficulty={difficulty})")
    return True


def cmd_ingest(args):
    manifest = load_manifest()
    posts = discover_0xdf_htb_posts()

    if not posts:
        print("[!] No posts discovered. Exiting.")
        return 1

    # Sort by date descending (newer boxes first — more relevant)
    posts.sort(key=lambda p: p.get("date", ""), reverse=True)

    if args.limit:
        posts = posts[:args.limit]

    new_count = 0
    skip_count = 0
    fail_count = 0

    for i, post in enumerate(posts, 1):
        name = post["name"]
        if name in manifest["boxes"] and manifest["boxes"][name].get("status") == "done":
            skip_count += 1
            continue

        print(f"[{i}/{len(posts)}] Processing {name}...")
        try:
            if ingest_box(post, manifest):
                new_count += 1
        except Exception as e:
            print(f"  [!] Error: {e}", file=sys.stderr)
            fail_count += 1

        time.sleep(RATE_LIMIT)

    total_done = sum(1 for b in manifest["boxes"].values() if b.get("status") == "done")
    print(f"\n[=] Summary: {new_count} new, {skip_count} skipped, {fail_count} failed. Total corpus: {total_done}")
    return 0


def cmd_validate(args):
    manifest = load_manifest()
    total = 0
    healthy = 0
    issues = []

    for name, info in sorted(manifest["boxes"].items()):
        total += 1
        raw_path = WALKTHROUGHS_DIR / name / "raw.md"

        if info.get("status") != "done":
            issues.append(f"{name}: status={info.get('status')}")
            continue

        if not raw_path.exists():
            issues.append(f"{name}: raw.md missing despite status=done")
            continue

        size = raw_path.stat().st_size
        if size < 500:
            issues.append(f"{name}: raw.md too small ({size} bytes)")
            continue

        healthy += 1

    # Difficulty distribution
    diffs = {}
    for info in manifest["boxes"].values():
        if info.get("status") == "done":
            d = info.get("difficulty", "unknown")
            diffs[d] = diffs.get(d, 0) + 1

    print(f"Corpus health: {healthy}/{total} healthy")
    print(f"Difficulty distribution: {json.dumps(diffs, indent=2)}")

    if issues:
        print(f"\nIssues ({len(issues)}):")
        for issue in issues[:20]:
            print(f"  - {issue}")

    return 0 if not issues else 1


def cmd_stats(args):
    manifest = load_manifest()
    done = [n for n, i in manifest["boxes"].items() if i.get("status") == "done"]
    failed = [n for n, i in manifest["boxes"].items() if i.get("status") in ("failed", "failed_parse")]
    diffs = {}
    for info in manifest["boxes"].values():
        if info.get("status") == "done":
            d = info.get("difficulty", "unknown")
            diffs[d] = diffs.get(d, 0) + 1

    print(f"Total ingested: {len(done)}")
    print(f"Failed: {len(failed)}")
    print(f"Difficulty: {json.dumps(diffs)}")
    if failed:
        print(f"Failed boxes: {', '.join(failed[:10])}{'...' if len(failed) > 10 else ''}")


def main():
    parser = argparse.ArgumentParser(description="HTB walkthrough ingestion for TAR")
    sub = parser.add_subparsers(dest="command")

    p_ingest = sub.add_parser("ingest", help="Fetch walkthroughs from public sources")
    p_ingest.add_argument("--limit", type=int, help="Max boxes to fetch")
    p_ingest.set_defaults(func=cmd_ingest)

    p_validate = sub.add_parser("validate", help="Validate corpus health")
    p_validate.set_defaults(func=cmd_validate)

    p_stats = sub.add_parser("stats", help="Show corpus statistics")
    p_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
