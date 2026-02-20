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

## Auto-Learn (Phase 3)

### Learn from Error

Automatically extract insights from error messages:

```
memory learn error "TypeError: 'NoneType' object is not subscriptable"
# Learns: "Check if object exists before indexing"
```

### Learn from Feedback

Learn from user corrections:

```
memory learn feedback "That was wrong, use black instead"
# Learns: "Correction noted: That was wrong, use black instead"
```

### Review Playbook

Get suggestions for improving the playbook:

```
memory review
# Shows entries with low helpful/harmful ratio
```

### Configuration

```
memory config                    # Show all settings
memory config learn_from_errors true   # Enable/disable
memory config learn_from_feedback true
```

## Files

- Script: `scripts/memory.py`
- Playbook: `~/.config/opencode/memory/playbook.md`
- Data: `~/.config/opencode/memory/memory.json`
- Config: `~/.config/opencode/memory/config.json`

## Examples

```
> memory learn error "KeyError: 'foo'"
Learned from error: [err-00001]

> memory search
[str-00001] [strategies] Use python3 -m venv for virtual environments
[err-00001] [errors] Check if key exists in dictionary

> memory review
Playbook Review:
  - Consider removing: <entry with high harmful votes>

> memory config
{"auto_learn": true, "learn_from_errors": true, ...}
```
