# PreToolUse Hook Exemption Mechanism

## Overview

The PreToolUse hook handler now supports a comprehensive exemption mechanism that allows bypassing anti-pattern checks with proper justification. This provides flexibility for legitimate exceptions while maintaining code quality standards.

## Features

### 1. Inline Exemption Comments

Add exemption comments directly in your code:

```python
# claude-exempt: <pattern-name> - <justification>
```

Example:
```python
# claude-exempt: High_Cyclomatic_Complexity - Complex business logic requires multiple decision paths
def complex_function():
    # Your complex code here
    pass
```

### 2. Environment Variable Support

Set the `CLAUDE_EXEMPT_PATTERNS` environment variable with comma-separated pattern names:

```bash
export CLAUDE_EXEMPT_PATTERNS="God_File,Deep_Nesting,Magic_Numbers"
```

### 3. Project-Level Configuration

Create `.claude/exemptions.json` with structured exemptions:

```json
{
  "global_exemptions": [
    "Deep_Nesting",
    "Todo_Comments"
  ],
  "file_exemptions": {
    "legacy/": ["God_File", "High_Cyclomatic_Complexity"],
    "migrations/": ["SQL_Injection_Risk"],
    "tests/": ["Debug_Code", "Magic_Numbers"]
  },
  "justifications": {
    "Deep_Nesting": "Project structure requires deep nesting",
    "God_File": "Legacy code - scheduled for refactoring"
  }
}
```

### 4. Force Mode

Bypass ALL checks (use with extreme caution):

```bash
export CLAUDE_FORCE_CREATE=true
```

This will show a warning and log the forced creation.

### 5. Exemption Logging

All exemptions are logged to `.claude/logs/exemptions.log` with:
- Timestamp
- File path
- Pattern name
- Justification
- Source (INLINE, ENV, GLOBAL_CONFIG, FILE_CONFIG, FORCE)

Log format (JSON):
```json
{
  "timestamp": "2025-08-05T22:42:19.408907",
  "file": "/path/to/file.py",
  "pattern": "High Cyclomatic Complexity",
  "justification": "Complex business logic",
  "source": "INLINE"
}
```

## Pattern Names

Common anti-patterns that can be exempted:

### Code Quality
- `High_Cyclomatic_Complexity` - Functions with complexity > 10
- `God_Class` - Classes with > 15 methods
- `God_File` - Files with > 500 lines
- `Deep_Inheritance` - Inheritance depth > 3
- `Too_Many_Parameters` - Functions with > 5 parameters
- `Deep_Function_Nesting` - Function nesting depth > 3
- `Complex_Return_Logic` - Multiple/complex return statements

### Security
- `Hardcoded_Credentials` - API keys, passwords in code
- `SQL_Injection_Risk` - Dynamic SQL construction
- `Command_Injection_Risk` - Unsafe command execution
- `Debug_Code` - Debug statements in production code

### Architecture
- `Wrong_Layer_Logic` - Business logic in presentation layer
- `Database_Layer_Violation` - DB access outside data layer
- `Deep_Nesting` - File path > 6 levels deep
- `Circular_Import_Risk` - Complex relative imports

### Code Smells
- `Generic_Utility_File` - utils.py, helpers.py patterns
- `Abandoned_Code` - deprecated, obsolete, backup files
- `Temporary_Code` - temp, wip, experimental files
- `Technical_Debt` - > 5 TODO/FIXME comments
- `Magic_Numbers` - Large numeric literals
- `Unused_Imports` - Imported but unused modules
- `Unused_Variables` - Assigned but unused variables

## Priority Order

Exemptions are checked in this priority order:
1. **Force Mode** (`CLAUDE_FORCE_CREATE=true`)
2. **Inline Comments** (in the file itself)
3. **Environment Variables** (`CLAUDE_EXEMPT_PATTERNS`)
4. **Global Config** (from `exemptions.json`)
5. **File-Specific Config** (from `exemptions.json`)

## Best Practices

1. **Always provide justification** - Explain why the exemption is necessary
2. **Be specific** - Exempt only the patterns you need, not everything
3. **Review regularly** - Check `exemptions.log` to track technical debt
4. **Avoid force mode** - Use specific exemptions instead of bypassing all checks
5. **Document exemptions** - Keep `exemptions.json` updated with clear justifications

## Example Usage

### Creating a Legacy File with Exemptions

```python
# legacy_processor.py

# claude-exempt: God_File - Legacy code, refactoring planned for Q2
# claude-exempt: High_Cyclomatic_Complexity - Complex business rules from old system

def process_legacy_data(data):
    # 600+ lines of complex legacy logic
    pass
```

### Configuring Project-Wide Exemptions

```json
{
  "global_exemptions": ["Deep_Nesting"],
  "file_exemptions": {
    "src/legacy/": ["God_File", "High_Cyclomatic_Complexity"],
    "src/migrations/": ["SQL_Injection_Risk", "Database_Layer_Violation"]
  },
  "justifications": {
    "Deep_Nesting": "Microservices architecture requires deep module structure",
    "God_File": "Legacy monolith being gradually decomposed",
    "SQL_Injection_Risk": "Migration scripts use parameterized queries at runtime"
  }
}
```

### Monitoring Exemptions

Check the exemption log regularly:

```bash
# View recent exemptions
tail -n 20 .claude/logs/exemptions.log

# Count exemptions by pattern
grep -o '"pattern": "[^"]*"' .claude/logs/exemptions.log | sort | uniq -c

# Find files with most exemptions
grep -o '"file": "[^"]*"' .claude/logs/exemptions.log | sort | uniq -c | sort -rn
```

## Troubleshooting

### Exemption Not Working?

1. Check pattern name spelling (case-insensitive, but spaces/underscores matter)
2. Verify exemption source priority (inline > env > config)
3. Check log file for exemption entries
4. Ensure `exemptions.json` is valid JSON

### Too Many Exemptions?

If you find yourself exempting many patterns:
1. Review if the patterns are too strict
2. Consider refactoring the code instead
3. Plan technical debt reduction
4. Use exemptions as temporary measures, not permanent solutions

## Security Considerations

- **Never exempt security patterns in production code** without security review
- **Force mode should require special authorization** in CI/CD pipelines
- **Regularly audit exemption logs** for security-critical patterns
- **Document security exemptions** in your security documentation

## Integration with CI/CD

In CI/CD pipelines:

```yaml
# GitHub Actions example
env:
  CLAUDE_PROJECT_DIR: ${{ github.workspace }}
  CLAUDE_EXEMPT_PATTERNS: "Todo_Comments"  # Allow TODOs in CI
  # Never use CLAUDE_FORCE_CREATE in CI!
```

## Future Enhancements

Potential improvements for the exemption system:
- Exemption expiration dates
- Exemption approval workflow
- Pattern severity customization
- Team-specific exemption policies
- Metrics dashboard for technical debt tracking