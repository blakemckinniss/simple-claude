# Project Memory Isolation Guide

## Overview

The Claude Code memory system uses **project-based isolation** to prevent cross-project contamination. Each project gets its own isolated memory store, identified by a SHA256 hash of the project's absolute path.

## How Project Isolation Works

### 1. Automatic Project Detection

When you work in a project directory, the memory system automatically:
- Computes a unique project hash from the current working directory (CWD)
- Creates an isolated memory store at `.claude/hooks/memory/{project_hash}/`
- Maintains complete separation between different projects

```python
# Project hash generation (automatic)
project_hash = hashlib.sha256(cwd.encode()).hexdigest()[:16]
# Example: /home/user/project-a → c1185c73da7fc6d1
```

### 2. Memory Storage Structure

```
.claude/hooks/memory/
├── c1185c73da7fc6d1/          # Project A memories
│   └── memories.json
├── a9f2b8e4d6c1a3f7/          # Project B memories
│   └── memories.json
└── e5d4c3b2a1f9e8d7/          # Project C memories
    └── memories.json
```

## Adding a New Project

### Step 1: Start Working in the New Project

Simply navigate to your new project directory and start using Claude Code:

```bash
cd /path/to/new-project
claude "Initialize project"
```

The memory system will **automatically**:
- Detect the new project path
- Generate a unique project hash
- Create a new isolated memory store
- Begin storing project-specific memories

### Step 2: Verify Project Isolation

Check that your project has its own memory store:

```bash
# Find your project's hash
python3 -c "import hashlib; print(hashlib.sha256('$(pwd)'.encode()).hexdigest()[:16])"

# Verify memory directory exists
ls -la ~/.claude/hooks/memory/
```

### Step 3: Initial Memory Seeding (Optional)

To pre-populate useful memories for a new project:

```python
from memory_manager import memory_manager, MemoryType

# Add project-specific context
memory_manager.save_memory(
    content="This project uses React 18 with TypeScript",
    memory_type=MemoryType.CRITICAL_CONTEXT,
    session_id="init",
    relevance_score=0.9,
    tags=["project_info", "tech_stack"]
)

# Add architectural decisions
memory_manager.save_memory(
    content="API endpoints follow REST conventions at /api/v1/*",
    memory_type=MemoryType.DECISIONS,
    session_id="init",
    relevance_score=0.8,
    tags=["architecture", "api"]
)
```

## Preventing Cross-Project Contamination

### 1. Project Hash Isolation

**How it works:**
- Each project's CWD creates a unique 16-character hash
- Memories are stored in hash-specific directories
- No shared memory storage between projects
- Hash collision probability: ~1 in 2^64 for reasonable project counts

**Security guarantee:**
```
Project A (/home/user/project-a) → Hash: c1185c73da7fc6d1
Project B (/home/user/project-b) → Hash: a9f2b8e4d6c1a3f7
```
These projects **cannot** access each other's memories.

### 2. Session and Continuation Tracking

Each memory entry includes:
- `session_id`: Unique identifier for the Claude session
- `continuation_id`: Links related conversations
- `project_hash`: Ensures memories stay project-bound

```json
{
  "memory_id": "uuid",
  "content": "Project-specific information",
  "session_id": "current-session",
  "continuation_id": "thread-id",
  "project_hash": "c1185c73da7fc6d1"
}
```

### 3. Preventing Memory Poisoning

**Automatic safeguards:**

1. **Path-based isolation**: Memories cannot be accessed cross-project
2. **Relevance decay**: Old memories automatically lose relevance (0.95 daily decay)
3. **Cleanup thresholds**: Memories with relevance < 0.1 are auto-removed
4. **Type validation**: Only valid MemoryType enums accepted
5. **Content sanitization**: No code execution from memory content

**Manual safeguards:**

```python
# Clean potentially poisoned memories
memory_manager.cleanup_old_memories(
    max_age_days=7,  # Remove memories older than 7 days
    min_relevance=0.3  # Remove low-relevance memories
)

# Reset project memories (nuclear option)
import shutil
project_hash = memory_manager._get_project_hash()
memory_dir = f".claude/hooks/memory/{project_hash}"
shutil.rmtree(memory_dir)  # Completely reset project memories
```

## Best Practices

### 1. Project Initialization

When starting a new project:
- Let the system auto-generate the project hash
- Don't manually copy memory directories between projects
- Seed initial context with high-relevance scores (0.8-0.9)

### 2. Memory Hygiene

- Review memories periodically: `memory_manager.retrieve_memories(limit=10)`
- Remove incorrect memories: `memory_manager.cleanup_old_memories()`
- Monitor memory growth: Check `.claude/hooks/memory/{hash}/memories.json` size

### 3. Project Migration

If moving a project to a new path:
1. The old memories remain in the old hash directory
2. New memories start fresh in the new hash directory
3. To preserve memories, manually copy the JSON file:

```bash
# Get old and new project hashes
OLD_HASH=$(cd /old/path && python3 -c "import hashlib; print(hashlib.sha256('$(pwd)'.encode()).hexdigest()[:16])")
NEW_HASH=$(cd /new/path && python3 -c "import hashlib; print(hashlib.sha256('$(pwd)'.encode()).hexdigest()[:16])")

# Copy memories (if desired)
cp ~/.claude/hooks/memory/$OLD_HASH/memories.json ~/.claude/hooks/memory/$NEW_HASH/
```

## Troubleshooting

### Issue: Memories from wrong project appearing

**Diagnosis:**
```python
# Check current project hash
import os, hashlib
current_hash = hashlib.sha256(os.getcwd().encode()).hexdigest()[:16]
print(f"Current project hash: {current_hash}")

# List all memories and their project hashes
memories = memory_manager.retrieve_memories()
for m in memories:
    print(f"Memory project: {m.get('project_hash')} - {m.get('content')[:50]}")
```

**Solution:**
- Verify you're in the correct directory
- Check for symbolic links that might confuse path detection
- Clear contaminated memories if needed

### Issue: Memory system not initializing for new project

**Solution:**
```python
# Force initialization
memory_manager._ensure_memory_directory()
print(f"Memory directory created: .claude/hooks/memory/{memory_manager._get_project_hash()}")
```

### Issue: Suspected memory poisoning

**Solution:**
1. Review all memories: `memory_manager.retrieve_memories()`
2. Remove suspicious entries by resetting the directory
3. Re-seed with clean, validated memories
4. Increase relevance thresholds for injection

## Security Considerations

1. **Hash Length**: Current 16-character truncation provides adequate separation for typical use. For enterprise deployments with >10,000 projects, consider using 32 characters.

2. **File Permissions**: Ensure `.claude/hooks/memory/` has appropriate permissions:
   ```bash
   chmod 700 ~/.claude/hooks/memory/
   ```

3. **Sensitive Data**: Don't store passwords, API keys, or secrets in memories. The system stores memories in plaintext JSON.

4. **Memory Injection**: Only memories with relevance > 0.5 are injected into context, preventing low-quality contamination.

## Memory Lifecycle

1. **Creation**: Memories created during Claude sessions with project-specific context
2. **Storage**: Saved to isolated project directory with metadata
3. **Retrieval**: Loaded based on relevance and context matching
4. **Decay**: Relevance decreases over time (0.95 factor daily)
5. **Cleanup**: Automatic removal when relevance < 0.1 or age > 30 days
6. **Isolation**: Never shared between different project hashes

## Summary

The memory system provides **automatic project isolation** through:
- SHA256-based directory separation
- No manual configuration required
- Automatic contamination prevention
- Built-in cleanup mechanisms
- Thread-safe operations

Simply work in your project directory, and the system handles isolation automatically. No special steps needed to add a new project - just start working in it!