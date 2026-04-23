#!/usr/bin/env python3
"""
xmind_parser.py — Parse the Orange Cyberdefense "Pentesting Active Directory"
.xmind source file into a structured JSON tree that TAR's planner and internal
red-team agent consume.

The .xmind file is a zip with content.json at its root. content.json is a
list of sheets; each sheet has a rootTopic with children split into two arrays:
  - attached: the canonical tree branches
  - detached: floating topics (state anchors: "Got valid username",
              "Administrator access", "Domain admin", etc.)

This parser walks both, normalises each node into:
  { id, title, path, depth, children, action_refs, is_command, missing_yaml }

action_refs links each node to existing TAR YAMLs in
/home/kali/Desktop/tar-repo/actions/ad/ by fuzzy matching title + description.

Subcommands:
  fetch      — download .xmind from GitHub, cache at knowledge/mindmaps/ocd_ad.xmind
  parse      — parse cached .xmind → knowledge/mindmaps/ocd_ad_tree.json
  gaps       — print mindmap nodes with no matching YAML (the authoring backlog)
  crosslink  — write references.ocd_mindmap_node_id back into each YAML
  stats      — print total nodes, matched, unmatched, per-branch counts
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
import yaml
import zipfile
from pathlib import Path
from typing import Iterator

# ── Constants ──────────────────────────────────────────────────────────
XMIND_URL = (
    "https://raw.githubusercontent.com/Orange-Cyberdefense/ocd-mindmaps/"
    "main/src/Pentesting_Active_directory_dark.xmind"
)
MINDMAP_DIR = Path("/home/kali/knowledge/mindmaps")
XMIND_CACHE = MINDMAP_DIR / "ocd_ad.xmind"
TREE_JSON = MINDMAP_DIR / "ocd_ad_tree.json"

# Repo roots — parser works against either the runtime or the repo
REPO_AD_ACTIONS = Path("/home/kali/Desktop/tar-repo/actions/ad")
REPO_WEB_ACTIONS = Path("/home/kali/Desktop/tar-repo/actions/web")

# Non-content detached topics we skip (credits, legend, meta)
SKIP_TITLES = {
    "Credits",
    "Legend",
    "inspired by / Sources",
    "Kindly provided by Orange Cyberdefense ;-)",
}

# Maps a branch_root title prefix → (access_level_name, rank).
# Rank lets the planner order gates and verify current >= required.
# Attached branches are network_only (rank 0) — no creds needed.
# Detached state-anchor branches carry the minimum access needed.
ACCESS_LEVEL_GATES: list[tuple[str, str, int]] = [
    # (prefix_to_match, level_name, rank)
    ("Entry point",                          "network_only",    0),
    ("Low hanging fruit",                    "network_only",    0),
    ("(MITM)",                               "network_only",    0),
    ("Crack Hash",                           "network_only",    0),
    ("Known vulnerabilities",                "network_only",    0),
    ("Got valid username",                   "valid_username",  1),
    ("Got Account on the domain",            "authenticated",   2),
    ("Low access",                           "authenticated",   2),
    ("Enumerate ldap",                       "authenticated",   2),
    ("ADCS weak configuration",              "authenticated",   2),
    ("Kerberos Delegation",                  "authenticated",   2),
    ("ACLs/ACEs",                            "authenticated",   2),
    ("Lateral move",                         "local_admin",     3),
    ("Administrator access",                 "local_admin",     3),
    ("Persistence",                          "local_admin",     3),
    ("Trust relationship",                   "domain_admin",    4),
    ("Domain admin",                         "domain_admin",    4),
    ("Enterprise Admin",                     "enterprise_admin",5),
]
_ACCESS_GATE_CACHE: dict[str, tuple[str, int]] = {}


def _access_gate_for_branch(branch_root: str) -> tuple[str, int]:
    """Return (level_name, rank) for a branch root title."""
    if branch_root in _ACCESS_GATE_CACHE:
        return _ACCESS_GATE_CACHE[branch_root]
    for prefix, level, rank in ACCESS_LEVEL_GATES:
        if branch_root.startswith(prefix):
            _ACCESS_GATE_CACHE[branch_root] = (level, rank)
            return level, rank
    # Default: attached branches → network_only
    result = ("network_only", 0)
    _ACCESS_GATE_CACHE[branch_root] = result
    return result


# ── Title normalisation ───────────────────────────────────────────────
_TITLE_STRIP = re.compile(r"[🔥🔵🟢🟡🔴⚠️✅❌➡️⬅️]+|#.*$|\s+")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _normalise(text: str) -> str:
    """Lowercase, strip emoji / trailing comments, collapse to tokens."""
    text = text or ""
    text = text.replace("\n", " ").replace("\r", " ")
    # Drop emoji decorations and in-line comment tails ("# explanation...")
    text = _TITLE_STRIP.sub(" ", text)
    return _NON_ALNUM.sub(" ", text.lower()).strip()


def _tokenise(text: str) -> set[str]:
    return {t for t in _normalise(text).split() if len(t) > 2}


# ── .xmind I/O ────────────────────────────────────────────────────────
def fetch_xmind(dest: Path = XMIND_CACHE, url: str = XMIND_URL) -> Path:
    """Download the .xmind from upstream to a cache path."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = resp.read()
    dest.write_bytes(data)
    return dest


def load_xmind_tree(xmind_path: Path = XMIND_CACHE) -> dict:
    """Read content.json out of the .xmind zip. Returns the first sheet dict."""
    with zipfile.ZipFile(xmind_path) as z:
        with z.open("content.json") as f:
            data = json.load(f)
    if isinstance(data, list):
        return data[0]
    return data


# ── Tree walking ──────────────────────────────────────────────────────
def _node_id(title: str, path: list[str]) -> str:
    """Stable short id from title + ancestor path."""
    material = "/".join(path + [title])
    return hashlib.sha1(material.encode("utf-8")).hexdigest()[:10]


def _is_command_leaf(title: str) -> bool:
    """Heuristic: leaf nodes that look like shell commands."""
    if not title:
        return False
    tokens = title.split()
    if not tokens:
        return False
    first = tokens[0].lower()
    # Common command prefixes in the OCD mindmap
    CMD_PREFIXES = {
        "nmap", "cme", "crackmapexec", "nxc", "smbclient", "smbmap",
        "enum4linux", "ldapsearch", "rpcclient", "impacket-", "getuserspns.py",
        "getnpusers.py", "secretsdump.py", "mimikatz", "python3", "sudo",
        "certipy", "bloodhound-python", "sharphound", "rubeus", "bettercap",
        "responder", "ntlmrelayx.py", "net", "nslookup", "dig", "kerbrute",
        "hashcat", "john", "evil-winrm", "psexec.py", "wmiexec.py", "atexec.py",
        "msfconsole", "curl", "wget", "socat", "proxychains", "ssh",
        "ldapdomaindump", "crackmapexec", "pypykatz", "mitm6",
    }
    return first in CMD_PREFIXES or "#" in title or title.startswith("./")


def walk_topic(node: dict, parent_path: list[str], depth: int = 0) -> Iterator[dict]:
    """Recursively yield a flat stream of normalised nodes from a topic subtree."""
    title = (node.get("title") or "").strip()
    path = parent_path + [title]
    out = {
        "id": _node_id(title, parent_path),
        "title": title,
        "path": path,
        "depth": depth,
        "is_command": _is_command_leaf(title),
        "children_ids": [],
    }

    child_container = node.get("children", {}) or {}
    attached = child_container.get("attached", []) or []
    for child in attached:
        child_id = _node_id((child.get("title") or "").strip(), path)
        out["children_ids"].append(child_id)

    yield out

    for child in attached:
        yield from walk_topic(child, path, depth + 1)


def walk_full_tree(sheet: dict) -> list[dict]:
    """Walk both attached and detached children from the sheet's rootTopic."""
    nodes: list[dict] = []
    root = sheet["rootTopic"]
    root_title = (root.get("title") or "").strip()

    # Emit the synthetic root
    nodes.append({
        "id": _node_id(root_title, []),
        "title": root_title,
        "path": [root_title],
        "depth": 0,
        "is_command": False,
        "children_ids": [],
        "branch_type": "root",
    })

    children = root.get("children", {}) or {}
    attached = children.get("attached", []) or []
    detached = children.get("detached", []) or []

    for branch in attached:
        btitle = (branch.get("title") or "").strip()
        if btitle in SKIP_TITLES:
            continue
        level, rank = _access_gate_for_branch(btitle)
        for n in walk_topic(branch, [root_title], depth=1):
            n["branch_type"] = "attached"
            n["branch_root"] = btitle
            n["access_level_gate"] = level
            n["access_level_rank"] = rank
            nodes.append(n)

    for branch in detached:
        btitle = (branch.get("title") or "").strip()
        if btitle in SKIP_TITLES:
            continue
        level, rank = _access_gate_for_branch(btitle)
        for n in walk_topic(branch, [root_title], depth=1):
            n["branch_type"] = "detached"
            n["branch_root"] = btitle
            n["access_level_gate"] = level
            n["access_level_rank"] = rank
            nodes.append(n)

    return nodes


# ── YAML action matching ──────────────────────────────────────────────
def load_action_index() -> dict[str, dict]:
    """Load all YAML actions, keyed by action name."""
    index: dict[str, dict] = {}
    for root in (REPO_AD_ACTIONS, REPO_WEB_ACTIONS):
        if not root.is_dir():
            continue
        for f in root.rglob("*.yml"):
            try:
                data = yaml.safe_load(f.read_text()) or {}
            except Exception:
                continue
            name = data.get("name")
            if not name:
                continue
            index[name] = {
                "name": name,
                "description": data.get("description", ""),
                "mechanism": data.get("mechanism", ""),
                "path": str(f),
                "_tokens": _tokenise(name) | _tokenise(data.get("description", "")),
            }
    return index


def match_actions(node_title: str, action_index: dict[str, dict]) -> list[str]:
    """Fuzzy-match a mindmap node title against the YAML action library.

    Returns action names with Jaccard similarity > threshold, best first.
    """
    node_tokens = _tokenise(node_title)
    if not node_tokens:
        return []

    scored: list[tuple[float, str]] = []
    for name, meta in action_index.items():
        action_tokens = meta["_tokens"]
        if not action_tokens:
            continue
        # Require at least one substantive token overlap
        overlap = node_tokens & action_tokens
        if not overlap:
            continue
        jaccard = len(overlap) / len(node_tokens | action_tokens)
        # Heavy bonus if any overlap token is also in the YAML name itself
        if overlap & _tokenise(name):
            jaccard += 0.3
        if jaccard >= 0.15:
            scored.append((jaccard, name))

    scored.sort(key=lambda x: -x[0])
    return [name for _, name in scored[:4]]


# ── Pipeline ──────────────────────────────────────────────────────────
def parse_and_write_tree() -> dict:
    """Parse cached .xmind, match actions, write tree JSON, return summary."""
    if not XMIND_CACHE.is_file():
        fetch_xmind()

    sheet = load_xmind_tree(XMIND_CACHE)
    nodes = walk_full_tree(sheet)
    actions = load_action_index()

    matched = 0
    for n in nodes:
        if n["depth"] == 0 or n["title"] in SKIP_TITLES:
            n["action_refs"] = []
            n["missing_yaml"] = False
            continue
        refs = match_actions(n["title"], actions)
        n["action_refs"] = refs
        n["missing_yaml"] = (not refs) and not n["is_command"]
        if refs:
            matched += 1

    gate_dist: dict[str, int] = {}
    for n in nodes:
        g = n.get("access_level_gate", "unknown")
        gate_dist[g] = gate_dist.get(g, 0) + 1

    summary = {
        "source": str(XMIND_CACHE),
        "total_nodes": len(nodes),
        "matched_nodes": matched,
        "unmatched_nodes": sum(1 for n in nodes if n.get("missing_yaml")),
        "command_leaves": sum(1 for n in nodes if n["is_command"]),
        "branches": sorted({n.get("branch_root", "") for n in nodes if n.get("branch_root")}),
        "access_gate_distribution": gate_dist,
    }

    TREE_JSON.parent.mkdir(parents=True, exist_ok=True)
    TREE_JSON.write_text(json.dumps({"summary": summary, "nodes": nodes},
                                    indent=2, ensure_ascii=False))
    return summary


def print_gaps() -> None:
    """Print mindmap nodes that have no matching YAML (authoring backlog)."""
    if not TREE_JSON.is_file():
        parse_and_write_tree()
    data = json.loads(TREE_JSON.read_text())
    gaps = [n for n in data["nodes"] if n.get("missing_yaml")]
    print(f"# Authoring backlog: {len(gaps)} mindmap nodes with no matching YAML\n")
    by_branch: dict[str, list[dict]] = {}
    for g in gaps:
        by_branch.setdefault(g.get("branch_root", "?"), []).append(g)
    for branch, items in sorted(by_branch.items()):
        print(f"## {branch}  ({len(items)} gaps)")
        for n in items[:20]:
            indent = "  " * (n["depth"] - 1)
            print(f"{indent}- {n['title'][:90]}")
        if len(items) > 20:
            print(f"  ... + {len(items) - 20} more")
        print()


def crosslink_yaml() -> int:
    """Write references.ocd_mindmap_node_id back into each YAML the parser matched."""
    if not TREE_JSON.is_file():
        parse_and_write_tree()
    data = json.loads(TREE_JSON.read_text())

    # name → list[node_id]
    action_to_nodes: dict[str, list[str]] = {}
    for n in data["nodes"]:
        for a in n.get("action_refs", []):
            action_to_nodes.setdefault(a, []).append(n["id"])

    updated = 0
    actions = load_action_index()
    for name, node_ids in action_to_nodes.items():
        meta = actions.get(name)
        if not meta:
            continue
        path = Path(meta["path"])
        try:
            raw = path.read_text()
            doc = yaml.safe_load(raw) or {}
        except Exception:
            continue
        refs = doc.setdefault("references", {})
        existing = refs.get("ocd_mindmap_node_ids") or []
        new = sorted(set(existing) | set(node_ids))
        if new != existing:
            refs["ocd_mindmap_node_ids"] = new
            path.write_text(yaml.safe_dump(doc, sort_keys=False, width=120))
            updated += 1
    return updated


def print_stats() -> None:
    """Compact stats about the parsed tree."""
    if not TREE_JSON.is_file():
        parse_and_write_tree()
    data = json.loads(TREE_JSON.read_text())
    s = data["summary"]
    print(f"Source:           {s['source']}")
    print(f"Total nodes:      {s['total_nodes']}")
    print(f"Matched (YAML):   {s['matched_nodes']}")
    print(f"Unmatched:        {s['unmatched_nodes']}")
    print(f"Command leaves:   {s['command_leaves']}")
    print(f"Branches:         {len(s['branches'])}")
    for b in s["branches"]:
        print(f"  - {b}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 1
    cmd = sys.argv[1]
    if cmd == "fetch":
        path = fetch_xmind()
        print(f"Fetched → {path} ({path.stat().st_size} bytes)")
    elif cmd == "parse":
        s = parse_and_write_tree()
        print(json.dumps(s, indent=2))
    elif cmd == "gaps":
        print_gaps()
    elif cmd == "crosslink":
        n = crosslink_yaml()
        print(f"Updated {n} YAML files with ocd_mindmap_node_ids references")
    elif cmd == "stats":
        print_stats()
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
