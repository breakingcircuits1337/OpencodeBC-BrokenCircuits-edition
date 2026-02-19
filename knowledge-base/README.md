# Knowledge Base

Sarah's Memory System - Short-term and Long-term knowledge storage

## Architecture

```
┌─────────────────────────────────────────────┐
│           Knowledge Base                      │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────────┐   ┌────────────────┐ │
│  │   Short-term     │   │   Long-term    │ │
│  │    (Redis)       │   │  (PostgreSQL)  │ │
│  ├──────────────────┤   ├────────────────┤ │
│  │ - Conversation   │   │ - Projects     │ │
│  │ - Recent context │   │ - Research     │ │
│  │ - Temp learnings │   │ - Facts        │ │
│  │ - TTL: 1 hour    │   │ - Preferences  │ │
│  └──────────────────┘   └────────────────┘ │
│            │                    │           │
│            └────────┬───────────┘           │
│                     ▼                       │
│            ┌────────────────┐              │
│            │  Unified API   │              │
│            └────────────────┘              │
└─────────────────────────────────────────────┘
```

## Quick Start

### 1. Install Databases

```bash
# Run setup script (requires root)
sudo bash scripts/setup.sh
```

### 2. Install Node dependencies

```bash
cd ~/knowledge-base
npm install
```

### 3. Test

```bash
node src/cli.js stats
```

## CLI Commands

### Learn something

```bash
# Short-term (Redis) - expires in 1 hour
node src/cli.js learn "current task" "Working on Magnitude"

# Long-term (PostgreSQL) - permanent
node src/cli.js learn "project_magnitude" "LLM self-improvement framework" --permanent --category=projects
```

### Recall something

```bash
node src/cli.js recall "project_magnitude"
```

### Search

```bash
node src/cli.js search "Magnitude"
```

### Projects

```bash
# Create project
node src/cli.js project create "Magnitude" "LLM self-improvement framework"

# Get project
node src/cli.js project get "Magnitude"

# List projects
node src/cli.js project list
```

### Research

```bash
# Store research
node src/cli.js research "AI safety"

# Get research
node src/cli.js getResearch "AI safety"
```

### Interactive Mode

```bash
node src/cli.js interactive
```

## API Usage

```javascript
import KnowledgeBase from './src/index.js';

const kb = new KnowledgeBase();
await kb.initialize();

// Learn
await kb.learn('key', 'value', { permanent: true });

// Recall
const result = await kb.recall('key');

// Search
const results = await kb.search('query');

// Projects
await kb.createProject('name', 'description');

// Research
await kb.storeResearch('topic', 'findings', ['source1']);

// Context (conversation)
await kb.addMessage('session123', { role: 'user', content: 'Hello' });
const history = await kb.getHistory('session123');

await kb.disconnect();
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | localhost | Redis server |
| `REDIS_PORT` | 6379 | Redis port |
| `POSTGRES_HOST` | localhost | PostgreSQL server |
| `POSTGRES_PORT` | 5432 | PostgreSQL port |
| `POSTGRES_USER` | sarah | PostgreSQL user |
| `POSTGRES_PASSWORD` | | PostgreSQL password |
| `DATABASE` | knowledge_base | Database name |

## Integration with OpenCode

Add to your CLAUDE.md:

```markdown
### Knowledge Base
- Location: `/home/sarah/knowledge-base/`
- Use for: Storing project info, remembering research, conversation context
- Commands:
  - `node src/cli.js learn "key" "value" --permanent`
  - `node src/cli.js recall "key"`
  - `node src/cli.js search "query"`
```

## Next Steps

1. Create Proxmox user for database management
2. Add to opencode-bc as a skill
3. Connect to me (Sarah AI) for persistent memory
