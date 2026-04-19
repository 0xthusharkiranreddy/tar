#!/usr/bin/env python3
"""
APEX Knowledge Search Helper — read-only TF-IDF retrieval over /home/kali/knowledge/

STATUS: optional automation helper (non-authoritative)
- Does NOT modify any knowledge files.
- All authority remains in CLAUDE.md, session_state.md, and knowledge/.
- Use this to quickly surface the most relevant knowledge file for a query.

Usage:
    python3 query_knowledge.py '<query>'
    python3 query_knowledge.py 'active directory delegation' --top 5
    python3 query_knowledge.py 'sqli payload' --category references
"""

import os
import sys
import re
import math
import argparse
from collections import Counter

KNOWLEDGE_DIR = "/home/kali/knowledge"


def tokenize(text):
    return re.findall(r'\w+', text.lower())


def compute_tf(tokens):
    tf = Counter(tokens)
    total = len(tokens)
    return {k: v / float(total) for k, v in tf.items()} if total else {}


def compute_idf(docs):
    idf = {}
    total_docs = len(docs)
    all_tokens = {t for doc in docs for t in doc}
    for t in all_tokens:
        count = sum(1 for doc in docs if t in doc)
        idf[t] = math.log10(total_docs / float(count)) if count else 0.0
    return idf


def main():
    parser = argparse.ArgumentParser(description="APEX knowledge search (read-only)")
    parser.add_argument("query", help="Search query")
    parser.add_argument("--top", type=int, default=3, help="Number of results (default: 3)")
    parser.add_argument("--category", default=None,
                        choices=["doctrine", "playbooks", "references",
                                 "workflows", "archives", "examples"],
                        help="Restrict to a knowledge category")
    args = parser.parse_args()

    search_root = os.path.join(KNOWLEDGE_DIR, args.category) if args.category else KNOWLEDGE_DIR

    if not os.path.isdir(search_root):
        print(f"Knowledge directory not found: {search_root}", file=sys.stderr)
        sys.exit(1)

    query_tokens = tokenize(args.query)

    files = [
        os.path.join(r, f)
        for r, _, fs in os.walk(search_root)
        for f in fs
        if f.endswith('.md') or f.endswith('.yaml')
    ]

    if not files:
        print(f"No knowledge files found under {search_root}", file=sys.stderr)
        sys.exit(1)

    docs, file_contents = [], {}
    for filepath in files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as fp:
                content = fp.read()
                file_contents[filepath] = content
                docs.append(tokenize(content))
        except OSError:
            docs.append([])

    idf = compute_idf(docs)

    scores = []
    for i, doc in enumerate(docs):
        tf = compute_tf(doc)
        score = sum(tf.get(t, 0) * idf.get(t, 0) for t in query_tokens)
        if score > 0:
            scores.append((score, files[i]))

    scores.sort(reverse=True, key=lambda x: x[0])

    print(f"\n--- APEX Knowledge: Top {args.top} for '{args.query}' ---")
    if not scores:
        print("No relevant knowledge found.")
        sys.exit(0)

    for score, path in scores[:args.top]:
        rel = os.path.relpath(path, KNOWLEDGE_DIR)
        print(f"\n  [{score:.4f}] {rel}")
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#'):
                        print(f"           {line}")
                        break
        except OSError:
            pass

    print()


if __name__ == "__main__":
    main()
