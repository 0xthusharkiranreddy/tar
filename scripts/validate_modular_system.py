#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path


ROOT = Path("/home/kali")

REQUIRED_PATHS = [
    ROOT / "CLAUDE.md",
    ROOT / "current" / "notes" / "session_state.md",
    ROOT / "knowledge" / "MANIFEST.md",
    ROOT / "knowledge" / "migration-map.md",
    ROOT / "knowledge" / "FINAL_PATH_INVENTORY.md",
    ROOT / "knowledge" / "archives" / "CLAUDE-large.original.md",
    ROOT / ".claude" / "hooks" / "session-start.sh",
    ROOT / ".claude" / "hooks" / "compact.sh",
    ROOT / ".claude" / "hooks" / "post-edit.sh",
    ROOT / ".claude" / "skills" / "router" / "SKILL.md",
    ROOT / ".claude" / "skills" / "reasoning-engine" / "SKILL.md",
    ROOT / ".claude" / "scripts" / "query_knowledge.py",
]

REQUIRED_SKILLS = [
    "context-management",
    "reasoning-engine",
    "router",
    "recon",
    "web",
    "cloud",
    "privesc",
    "injection-analysis",
    "ssrf-analysis",
    "chain-builder",
    "reporting",
    "research",
    "retrieval",
]

REQUIRED_KNOWLEDGE_INDEXES = [
    ROOT / "knowledge" / "doctrine" / "README.md",
    ROOT / "knowledge" / "workflows" / "README.md",
    ROOT / "knowledge" / "playbooks" / "README.md",
    ROOT / "knowledge" / "references" / "README.md",
    ROOT / "knowledge" / "examples" / "README.md",
    ROOT / "knowledge" / "archives" / "section-index.md",
]


def exists(path: Path) -> bool:
    return path.exists()


def load_router_references():
    router = ROOT / "knowledge" / "references" / "router-keywords.yaml"
    refs = []
    if not router.exists():
        return refs
    for line in router.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("- /home/kali/"):
            refs.append(Path(stripped[2:]))
    return refs


def main():
    missing = []
    warnings = []
    checked = []

    for path in REQUIRED_PATHS + REQUIRED_KNOWLEDGE_INDEXES:
        checked.append(str(path))
        if not exists(path):
            missing.append(str(path))

    for skill in REQUIRED_SKILLS:
        skill_path = ROOT / ".claude" / "skills" / skill / "SKILL.md"
        checked.append(str(skill_path))
        if not exists(skill_path):
            missing.append(str(skill_path))

    for ref in load_router_references():
        checked.append(str(ref))
        if not exists(ref):
            missing.append(str(ref))

    if not (ROOT / ".claude" / "settings.local.json").exists():
        warnings.append("settings.local.json is missing; hook activation may rely on external runtime behavior")
    else:
        warnings.append("settings.local.json exists, but no verified hook schema is enforced by this validator")

    optional_helpers = [
        ROOT / ".claude" / "scripts" / "query_knowledge.py",
        ROOT / ".claude" / "subagents" / "recon-agent.sh",
        ROOT / ".claude" / "subagents" / "vuln-agent.sh",
    ]
    for helper in optional_helpers:
        if not helper.exists():
            warnings.append(f"optional helper missing: {helper}")

    result = {
        "status": "pass" if not missing else "fail",
        "missing_paths": missing,
        "warnings": warnings,
        "checked_count": len(checked),
    }

    print(json.dumps(result, indent=2))
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
