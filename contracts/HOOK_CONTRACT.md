# Claude Code Hook Handler Contract

## Purpose
This contract establishes the governing rules and principles that Claude Code MUST respect when expanding or editing hook functionality within the `/home/devcontainers/better-claude/.claude/hooks/hook_handlers` directory. This contract is based on the official Claude Code hooks documentation and is designed to prevent destructive misuse.

## Core Principles

### 1. Configuration Structure Rules

#### 1.1 Settings File Hierarchy
- Hooks are configured in settings files with the following precedence:
  - `~/.claude/settings.json` - User settings
  - `.claude/settings.json` - Project settings
  - `.claude/settings.local.json` - Local project settings (not committed)
  - Enterprise managed policy settings

#### 1.2 Hook Configuration Schema
```json
{
  "hooks": {
    "EventName": [
      {
        "matcher": "ToolPattern",  // Only for PreToolUse/PostToolUse
        "hooks": [
          {
            "type": "command",     // Currently only "command" is supported
            "command": "script",   // Bash command to execute
            "timeout": 60000       // Optional timeout in milliseconds
          }
        ]
      }
    ]
  }
}
```

#### 1.3 Matcher Pattern Rules
- **Patterns are case-sensitive**
- Simple strings match exactly: `"Write"` matches only the Write tool
- Regex is supported: `"Edit|Write"` or `"Notebook.*"`
- Use `"*"` or `""` to match all tools
- For events without matchers (UserPromptSubmit, Notification, Stop, SubagentStop), omit the matcher field

### 2. Hook Event Behavior Rules

#### 2.1 Event Types and Their Constraints

| Event | Purpose | Can Block? | Special Behavior |
|-------|---------|------------|------------------|
| PreToolUse | Before tool execution | Yes | Can deny/allow/ask for permission |
| PostToolUse | After tool execution | No* | Can prompt Claude with feedback |
| UserPromptSubmit | Before prompt processing | Yes | Can inject context or block prompts |
| Stop | When Claude finishes | Yes | Can force continuation |
| SubagentStop | When subagent finishes | Yes | Can force continuation |
| Notification | On notifications | No | Logging only |
| PreCompact | Before compaction | No | Cannot block |
| SessionStart | On session start | No | Can inject initial context |

*PostToolUse cannot block the tool (it already ran) but can provide feedback to Claude

#### 2.2 Exit Code Behavior Contract
- **Exit code 0**: Success
  - stdout shown to user (except UserPromptSubmit/SessionStart where it goes to context)
  - Claude does NOT see stdout (except UserPromptSubmit/SessionStart)
- **Exit code 2**: Blocking error
  - stderr is fed to Claude (except UserPromptSubmit/PreCompact/SessionStart)
  - Blocks tool execution (PreToolUse) or prompts Claude (PostToolUse)
- **Other exit codes**: Non-blocking error
  - stderr shown to user
  - Execution continues

### 3. Input/Output Contract

#### 3.1 Hook Input Schema
All hooks receive JSON via stdin with at minimum:
```json
{
  "session_id": "string",
  "transcript_path": "string",
  "cwd": "string",
  "hook_event_name": "string"
}
```

Event-specific fields:
- PreToolUse/PostToolUse: `tool_name`, `tool_input`, (PostToolUse adds `tool_response`)
- UserPromptSubmit: `prompt`
- Notification: `message`
- Stop/SubagentStop: `stop_hook_active`
- PreCompact: `trigger`, `custom_instructions`
- SessionStart: `source`

#### 3.2 JSON Output Control
Hooks can return structured JSON for advanced control:

**Common fields (all events):**
```json
{
  "continue": true,           // Whether Claude should continue
  "stopReason": "string",     // Message when continue is false
  "suppressOutput": true      // Hide from transcript
}
```

**PreToolUse specific:**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow|deny|ask",
    "permissionDecisionReason": "string"
  }
}
```

**PostToolUse specific:**
```json
{
  "decision": "block",  // Prompts Claude with reason
  "reason": "string"
}
```

**UserPromptSubmit specific:**
```json
{
  "decision": "block",  // Prevents prompt processing
  "reason": "string",
  "hookSpecificOutput": {
    "hookEventName": "UserPromptSubmit",
    "additionalContext": "string"  // Added to context if not blocked
  }
}
```

### 4. Security Contract

#### 4.1 CRITICAL WARNING
**USE AT YOUR OWN RISK**: Claude Code hooks execute arbitrary shell commands on your system automatically. By implementing hooks:
- You are solely responsible for the commands you configure
- Hooks can modify, delete, or access any files your user account can access
- Malicious or poorly written hooks can cause data loss or system damage
- Anthropic provides no warranty and assumes no liability for damages
- You must thoroughly test hooks in a safe environment before production use

#### 4.2 Mandatory Security Practices
When creating or modifying hooks, you MUST:

1. **Validate and sanitize ALL inputs** - Never trust input data
2. **Quote shell variables** - Always use `"$VAR"` not `$VAR`
3. **Block path traversal** - Check for `..` in file paths
4. **Use absolute paths** - Specify full paths for scripts
5. **Use `$CLAUDE_PROJECT_DIR`** - For project-relative paths
6. **Skip sensitive files** - Never process `.env`, `.git/`, keys, secrets

#### 4.3 Input Validation Requirements
```python
# REQUIRED: Validate JSON input
try:
    input_data = json.load(sys.stdin)
except json.JSONDecodeError as e:
    print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
    sys.exit(1)

# REQUIRED: Validate expected fields exist
tool_name = input_data.get("tool_name", "")
if not tool_name:
    sys.exit(1)  # Silent failure for non-applicable hooks

# REQUIRED: Sanitize file paths
file_path = input_data.get("tool_input", {}).get("file_path", "")
if ".." in file_path or file_path.startswith("/etc"):
    print("Security: Path traversal blocked", file=sys.stderr)
    sys.exit(2)
```

### 5. Implementation Requirements

#### 5.1 File Organization
- Hook handlers must be placed in `/home/devcontainers/better-claude/.claude/hooks/hook_handlers/`
- Each event type should have its own module or directory
- Common utilities should be factored into shared modules

#### 5.2 Error Handling
- All hooks MUST handle JSON parsing errors gracefully
- Hooks should fail silently (exit 0 or 1) when not applicable
- Only use exit code 2 when intentionally blocking an action
- Always provide clear error messages via stderr

#### 5.3 Performance Constraints
- Default timeout: 60 seconds (configurable per command)
- Hooks run in parallel - must be thread-safe
- Avoid blocking operations that could hang Claude Code

#### 5.4 Testing Requirements
Before deploying any hook:
1. Test the command manually with sample JSON input
2. Verify all exit codes work as expected
3. Test edge cases (empty input, malformed data, missing fields)
4. Ensure no unintended side effects on the file system

### 6. Prohibited Actions

The following actions are STRICTLY PROHIBITED in hook implementations:

1. **Never modify Claude Code's configuration files** during hook execution
2. **Never execute commands without proper input validation**
3. **Never process sensitive files** (passwords, keys, tokens)
4. **Never use unquoted shell variables** in commands
5. **Never trust user input** without sanitization
6. **Never create infinite loops** or recursive hook triggers
7. **Never modify system files** or critical configurations
8. **Never log sensitive information** from hook inputs

### 7. Compliance Verification

Any hook implementation MUST pass these verification steps:

1. **Schema Compliance**: Hook configuration matches the documented JSON schema
2. **Security Audit**: All security practices are implemented
3. **Error Handling**: Graceful handling of all error conditions
4. **Documentation**: Clear comments explaining the hook's purpose and behavior
5. **Testing**: Comprehensive test coverage for all code paths

## Enforcement

This contract is enforced through:
1. Code review of all hook modifications
2. Automated testing of hook behavior
3. Security scanning of hook implementations
4. Runtime validation of hook outputs

By working with hooks in this directory, you acknowledge and agree to follow all rules and principles outlined in this contract.

---
*This contract is based on the official Claude Code hooks documentation and must be updated if the official documentation changes.*