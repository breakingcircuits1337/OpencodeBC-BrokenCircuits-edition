# Memory Skill

Use this skill to remember and recall information across conversations.

## Triggers

- `/remember`
- `/recall`
- `/forget`
- `/memory`
- "remember that"
- "don't forget"
- "I need to remember"

## Usage

### Add to Playbook

```
/remember Use python3 -m venv for virtual environments
```

Categories: strategies, errors, preferences, commands

```
/remember --category errors TypeError means something is None
/remember --category preferences Sarah prefers concise responses
```

### Search Playbook

```
/recall python
/recall azure
/recall
```

### Remove Entry

```
/forget str-00001
/forget python
```

### Vote on Entry

```
/vote str-00001 helpful   # Mark as helpful
/vote str-00001 harmful  # Mark as not helpful
```

### View Stats

```
/memory stats
/memory status
```

### Export/Import

```
/memory export ~/playbook.md
/memory import ~/playbook.md
```

## Files

- Script: `scripts/memory.py`
- Playbook: `~/.config/opencode/memory/playbook.md`
- Data: `~/.config/opencode/memory/playbook.json`

## Examples

```
> /remember Use python3 -m venv for virtual environments
Added: [str-00001]

> /recall azure
[str-00002] [strategies] Azure API key is in ~/.env

> /memory stats
Total entries: 2
  strategies: 2
Last updated: 2026-02-19

> /vote str-00001 helpful
Voted

> /memory export ~/backup.md
Exported to ~/backup.md
```
