#!/usr/bin/env python3
"""Memory Playbook Manager for OpenCode BC"""

import os
import json
import re
import sys
from datetime import datetime
from pathlib import Path

MEMORY_DIR = Path.home() / ".config" / "opencode" / "memory"
PLAYBOOK_MD = MEMORY_DIR / "playbook.md"
PLAYBOOK_JSON = MEMORY_DIR / "memory.json"
CONFIG_JSON = MEMORY_DIR / "config.json"

CATEGORIES = ["strategies", "errors", "preferences", "commands"]

def load_config():
    default = {
        "auto_learn": True,
        "learn_from_errors": True,
        "learn_from_feedback": True,
        "auto_vote": True
    }
    if not CONFIG_JSON.exists():
        CONFIG_JSON.write_text(json.dumps(default, indent=2))
        return default
    return json.loads(CONFIG_JSON.read_text())

def save_config(config):
    CONFIG_JSON.write_text(json.dumps(config, indent=2))

def ensure_dir():
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    if not PLAYBOOK_MD.exists():
        PLAYBOOK_MD.write_text("""# OpenCode BC Memory Playbook

## Strategies & Insights

## Common Errors

## User Preferences

## Commands

""")
    if not CONFIG_JSON.exists():
        load_config()

def load_playbook():
    if not PLAYBOOK_JSON.exists():
        return {"entries": {}, "next_id": {"str": 1, "err": 1, "usr": 1, "cmd": 1}}
    return json.loads(PLAYBOOK_JSON.read_text())

def save_playbook(data):
    PLAYBOOK_JSON.write_text(json.dumps(data, indent=2))
    regenerate_markdown(data)

def regenerate_markdown(data):
    md = """# OpenCode BC Memory Playbook

"""
    for cat in CATEGORIES:
        md += f"## {cat.replace('_', ' ').title()}\n\n"
        for entry_id, entry in data["entries"].items():
            if entry["category"] == cat:
                md += f"[{entry_id}] helpful={entry['helpful']} harmful={entry['harmful']} :: {entry['content']}\n"
        md += "\n"
    PLAYBOOK_MD.write_text(md)

def get_next_id(category):
    data = load_playbook()
    prefix = {"strategies": "str", "errors": "err", "preferences": "usr", "commands": "cmd"}.get(category, "str")
    
    max_id = 0
    for entry_id in data["entries"]:
        if entry_id.startswith(f"[{prefix}-"):
            num = int(entry_id.split("-")[1].split("]")[0])
            if num > max_id:
                max_id = num
    
    next_id = max_id + 1
    entry_id = f"[{prefix}-{next_id:05d}]"
    return entry_id

def add_entry(content, category="strategies"):
    ensure_dir()
    data = load_playbook()
    entry_id = get_next_id(category)
    data["entries"][entry_id] = {
        "content": content,
        "category": category,
        "helpful": 0,
        "harmful": 0,
        "created": datetime.now().isoformat(),
        "updated": datetime.now().isoformat()
    }
    save_playbook(data)
    return entry_id

def search_playbook(query=""):
    ensure_dir()
    data = load_playbook()
    results = []
    query_lower = query.lower() if query else ""
    
    for entry_id, entry in data["entries"].items():
        if not query_lower or query_lower in entry["content"].lower():
            results.append({
                "id": entry_id,
                "content": entry["content"],
                "category": entry["category"],
                "helpful": entry["helpful"],
                "harmful": entry["harmful"]
            })
    return results

def remove_entry(identifier):
    ensure_dir()
    data = load_playbook()
    
    identifier = identifier.strip()
    if not identifier.startswith("["):
        identifier = f"[{identifier}"
    if not identifier.endswith("]"):
        identifier = f"{identifier}]"
    
    for entry_id in list(data["entries"].keys()):
        if entry_id == identifier or identifier.strip("[]") in entry_id:
            del data["entries"][entry_id]
            save_playbook(data)
            return True
        if identifier.strip("[]") in data["entries"][entry_id]["content"].lower():
            del data["entries"][entry_id]
            save_playbook(data)
            return True
    return False

def export_playbook(filepath):
    ensure_dir()
    data = load_playbook()
    
    output = ["# OpenCode BC Memory Playbook", "", "## Strategies & Insights", ""]
    
    for entry_id, entry in data["entries"].items():
        if entry["category"] == "strategies":
            clean_id = entry_id.strip("[]")
            output.append(f"[{clean_id}] helpful={entry['helpful']} harmful={entry['harmful']} :: {entry['content']}")
    
    output.extend(["", "## Common Errors", ""])
    for entry_id, entry in data["entries"].items():
        if entry["category"] == "errors":
            clean_id = entry_id.strip("[]")
            output.append(f"[{clean_id}] helpful={entry['helpful']} harmful={entry['harmful']} :: {entry['content']}")
    
    output.extend(["", "## User Preferences", ""])
    for entry_id, entry in data["entries"].items():
        if entry["category"] == "preferences":
            clean_id = entry_id.strip("[]")
            output.append(f"[{clean_id}] helpful={entry['helpful']} harmful={entry['harmful']} :: {entry['content']}")
    
    output.extend(["", "## Commands", ""])
    for entry_id, entry in data["entries"].items():
        if entry["category"] == "commands":
            clean_id = entry_id.strip("[]")
            output.append(f"[{clean_id}] helpful={entry['helpful']} harmful={entry['harmful']} :: {entry['content']}")
    
    Path(filepath).write_text("\n".join(output))
    return True

def import_playbook(filepath):
    ensure_dir()
    data = load_playbook()
    
    content = Path(filepath).read_text()
    lines = content.split("\n")
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("##"):
            continue
        
        if "::" in line:
            try:
                id_part, rest = line.split("]", 1)
                content_part = rest.split("::", 1)[1].strip()
                category = "strategies"
                
                if "errors" in line.lower():
                    category = "errors"
                elif "preferences" in line.lower():
                    category = "preferences"
                elif "commands" in line.lower():
                    category = "commands"
                
                entry_id = id_part.replace("[", "").strip()
                
                if entry_id not in data["entries"]:
                    data["entries"][f"[{entry_id}]"] = {
                        "content": content_part,
                        "category": category,
                        "helpful": 0,
                        "harmful": 0,
                        "created": datetime.now().isoformat(),
                        "updated": datetime.now().isoformat()
                    }
            except:
                pass
    
    save_playbook(data)
    return True

def vote_entry(identifier, vote_type):
    ensure_dir()
    data = load_playbook()
    
    identifier = identifier.strip()
    if not identifier.startswith("["):
        identifier = f"[{identifier}"
    if not identifier.endswith("]"):
        identifier = f"{identifier}]"
    
    for entry_id in list(data["entries"].keys()):
        if entry_id == identifier:
            if vote_type == "helpful":
                data["entries"][entry_id]["helpful"] += 1
            elif vote_type == "harmful":
                data["entries"][entry_id]["harmful"] += 1
            data["entries"][entry_id]["updated"] = datetime.now().isoformat()
            save_playbook(data)
            return True
    return False

def learn_from_error(error_message, context=""):
    """Automatically learn from an error"""
    ensure_dir()
    config = load_config()
    
    if not config.get("learn_from_errors", True):
        return None
    
    error_insight = analyze_error(error_message)
    if error_insight:
        entry_id = add_entry(error_insight, category="errors")
        return entry_id
    return None

def analyze_error(error_message):
    """Convert error message to actionable insight"""
    error_lower = error_message.lower()
    
    patterns = [
        (r"nonetype.*not subscriptable", "Check if object exists before indexing"),
        (r"nonetype.*not iterable", "Check if object is None before iterating"),
        (r"index out of range", "Check list bounds before accessing index"),
        (r"keyerror", "Check if key exists in dictionary"),
        (r"attributeerror.*none", "Check if object is None before accessing attributes"),
        (r"permission denied", "Check file/directory permissions"),
        (r"no such file or directory", "Verify file path exists"),
        (r"module not found", "Install missing module with pip"),
        (r"import error", "Check import path and module installation"),
        (r"timeout", "Increase timeout or check network connection"),
    ]
    
    for pattern, insight in patterns:
        if re.search(pattern, error_lower):
            return insight
    
    return f"Error: {error_message[:100]}"

def learn_from_feedback(feedback):
    """Learn from user feedback/correction"""
    ensure_dir()
    config = load_config()
    
    if not config.get("learn_from_feedback", True):
        return None
    
    feedback_lower = feedback.lower()
    
    if any(word in feedback_lower for word in ["wrong", "incorrect", "not right", "mistake", "error"]):
        entry_id = add_entry(f"Correction noted: {feedback}", category="errors")
        return entry_id
    
    if any(word in feedback_lower for word in ["better", "good", "great", "thanks", "perfect"]):
        return None
    
    entry_id = add_entry(feedback, category="preferences")
    return entry_id

def auto_review():
    """Review playbook and identify low-quality entries"""
    ensure_dir()
    data = load_playbook()
    
    suggestions = []
    for entry_id, entry in data["entries"].items():
        helpful = entry.get("helpful", 0)
        harmful = entry.get("harmful", 0)
        
        if harmful > helpful and harmful > 2:
            suggestions.append(f"Consider removing: {entry['content']}")
        elif helpful > 10:
            suggestions.append(f"High value entry: {entry['content']}")
    
    return suggestions

def get_config():
    """Get current configuration"""
    return load_config()

def set_config(key, value):
    """Update configuration"""
    config = load_config()
    config[key] = value
    save_config(config)
    return config

def get_stats():
    ensure_dir()
    data = load_playbook()
    
    stats = {
        "total": len(data["entries"]),
        "categories": {},
        "last_updated": None
    }
    
    for entry_id, entry in data["entries"].items():
        cat = entry["category"]
        stats["categories"][cat] = stats["categories"].get(cat, 0) + 1
        if not stats["last_updated"] or entry["updated"] > stats["last_updated"]:
            stats["last_updated"] = entry["updated"]
    
    return stats

def main():
    if len(sys.argv) < 2:
        print("Usage: memory.py <command> [args]")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == "add" and len(sys.argv) > 2:
        entry_id = add_entry(" ".join(sys.argv[2:]))
        print(f"Added: {entry_id}")
    
    elif cmd == "search" and len(sys.argv) > 2:
        results = search_playbook(" ".join(sys.argv[2:]))
        for r in results:
            print(f"{r['id']} [{r['category']}] {r['content']}")
    
    elif cmd == "search":
        results = search_playbook()
        for r in results:
            print(f"{r['id']} [{r['category']}] {r['content']}")
    
    elif cmd == "remove" and len(sys.argv) > 2:
        if remove_entry(sys.argv[2]):
            print("Removed")
        else:
            print("Not found")
    
    elif cmd == "export" and len(sys.argv) > 2:
        if export_playbook(sys.argv[2]):
            print(f"Exported to {sys.argv[2]}")
        else:
            print("Export failed")
    
    elif cmd == "import" and len(sys.argv) > 2:
        if import_playbook(sys.argv[2]):
            print(f"Imported from {sys.argv[2]}")
        else:
            print("Import failed")
    
    elif cmd == "vote" and len(sys.argv) > 3:
        if vote_entry(sys.argv[2], sys.argv[3]):
            print("Voted")
        else:
            print("Not found")
    
    elif cmd == "stats":
        stats = get_stats()
        print(f"Total entries: {stats['total']}")
        for cat, count in stats["categories"].items():
            print(f"  {cat}: {count}")
        if stats["last_updated"]:
            print(f"Last updated: {stats['last_updated']}")
    
    elif cmd == "learn" and len(sys.argv) > 2:
        if sys.argv[2] == "error" and len(sys.argv) > 3:
            error_msg = " ".join(sys.argv[3:])
            entry_id = learn_from_error(error_msg)
            if entry_id:
                print(f"Learned from error: {entry_id}")
            else:
                print("Auto-learn disabled or no insight extracted")
        elif sys.argv[2] == "feedback" and len(sys.argv) > 3:
            feedback = " ".join(sys.argv[3:])
            entry_id = learn_from_feedback(feedback)
            if entry_id:
                print(f"Learned from feedback: {entry_id}")
            else:
                print("Feedback noted")
        else:
            print("Usage: memory learn error <message> OR memory learn feedback <text>")
    
    elif cmd == "review":
        suggestions = auto_review()
        if suggestions:
            print("Playbook Review:")
            for s in suggestions:
                print(f"  - {s}")
        else:
            print("No suggestions")
    
    elif cmd == "config":
        if len(sys.argv) > 2:
            if len(sys.argv) > 3:
                key = sys.argv[2]
                value = sys.argv[3].lower() == "true"
                config = set_config(key, value)
                print(f"Updated {key} = {value}")
            else:
                config = get_config()
                print(json.dumps(config, indent=2))
        else:
            config = get_config()
            print(json.dumps(config, indent=2))
    
    else:
        print("Commands: add, search, remove, export, import, vote, stats, learn, review, config")

if __name__ == "__main__":
    main()
