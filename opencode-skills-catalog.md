# OpenCode BC Skills Catalog

Skills included in the BrokenCircuits Edition distribution.

---

## BC-Specific Skills (In Repo)

| Skill | Description | Location |
|-------|-------------|----------|
| `memory` | ACE-powered memory system with auto-learning | `skills/memory/` |
| `azure-llm-bridge` | CLI scripts for Mistral & Kimi via Azure | `skills/azure-llm-bridge/` |
| `azure-cli` | Azure resource management | `skills/azure-cli/` |
| `proxmox-manager` | Proxmox VM management | `skills/proxmox-manager/` |
| `magnitude-browser` | Vision-first browser automation | `skills/magnitude-browser/` |

### Superpowers (Process Skills)

| Skill | Description |
|-------|-------------|
| `brainstorming` | Explore requirements before implementation |
| `test-driven-development` | TDD workflow |
| `systematic-debugging` | Debugging methodology |
| `verification-before-completion` | Verify work before claiming completion |
| `writing-plans` | Create implementation plans |
| `executing-plans` | Execute written plans |
| `requesting-code-review` | Code review workflow |
| `receiving-code-review` | Handle review feedback |
| `subagent-driven-development` | Multi-agent implementation |
| `using-git-worktrees` | Isolated workspace workflow |
| `dispatching-parallel-agents` | Run agents in parallel |
| `finishing-a-development-branch` | Complete feature workflow |

---

## Usage

```bash
# Memory commands
memory add "Use black for Python formatting"
memory search python
memory ace run coding "context here"

# Azure
bash scripts/az-login.sh
python scripts/mistral.py "prompt"

# Proxmox
python scripts/list-vms.py
python scripts/node-status.py
```

---

## Memory System Features

The `memory` skill includes:

- **Phase 1**: add, search, remove entries
- **Phase 2**: export, import, vote
- **Phase 3**: auto-learn from errors and feedback
- **Phase 4**: Full ACE framework (Generator/Reflector/Curator)

---

*Generated: 2026-02-20*
*Part of OpenCode BC - BrokenCircuits Edition*
