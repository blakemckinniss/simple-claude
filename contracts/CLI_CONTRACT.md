# External Tool Integration Contract

## Purpose
This contract establishes standards for integrating and managing external CLI tools within the better-claude system, ensuring reliable tool availability, safe command execution, and consistent error handling patterns. This contract is MEDIUM priority for maintaining robust system functionality.

## Core Principles

### 1. Tool Integration Standards

#### 1.1 Supported Tool Categories
```json
{
  "tools": {
    "search": ["rg", "fd", "fzf"],
    "file_ops": ["bat", "lsd", "exa", "tree"],
    "text_processing": ["sd", "jq", "yq", "mlr"],
    "development": ["ctags", "delta", "tokei", "scc"],
    "system": ["zoxide", "dust", "duf", "procs"],
    "network": ["xh", "dog"],
    "containers": ["podman", "dive", "trivy"],
    "utilities": ["hyperfine", "entr", "tldr"]
  }
}
```

#### 1.2 Tool Availability Requirements
- **Essential tools**: Must be available or system provides fallback
- **Enhanced tools**: Graceful degradation to standard alternatives
- **Optional tools**: Feature disabled if unavailable
- **Version compatibility**: Document minimum required versions

#### 1.3 Installation Validation
- Startup health checks for essential tools
- Version compatibility verification
- Path resolution and execution permission checks
- Fallback mechanism activation when tools missing

### 2. Command Execution Safety

#### 2.1 Command Validation
```bash
# Safe command patterns
rg --line-number 'pattern' file.txt
fd --type f --extension py
git status --porcelain

# Prohibited patterns
rm -rf /
sudo commands (unless explicitly allowed)
Commands with user input injection risks
```

#### 2.2 Execution Environment
- Controlled PATH environment
- Working directory constraints
- Resource limits (timeout, memory)
- Output size limitations

#### 2.3 Input Sanitization
- Shell metacharacter escaping
- Path traversal prevention
- Command injection protection
- User input validation

### 3. Error Handling Patterns

#### 3.1 Error Classification
- **Tool not found**: Missing binary or incorrect PATH
- **Permission denied**: Insufficient execution permissions
- **Command failed**: Tool executed but returned error
- **Timeout**: Tool execution exceeded time limit
- **Resource exhausted**: Out of memory or disk space

#### 3.2 Standardized Error Response
```json
{
  "error": {
    "type": "tool_error",
    "tool": "tool_name",
    "command": "executed_command",
    "exit_code": 1,
    "stderr": "error_message",
    "suggestion": "suggested_action",
    "fallback_available": true|false
  }
}
```

### 4. Performance and Resource Management

#### 4.1 Execution Limits
- **Timeout**: 30s default, 300s maximum
- **Memory**: 500MB per tool execution
- **Output size**: 10MB maximum capture
- **Concurrent executions**: 5 tools maximum

#### 4.2 Resource Optimization
- Command result caching for repeated operations
- Intelligent tool selection based on performance
- Resource usage monitoring and alerts
- Automatic cleanup of temporary files

## Implementation Requirements

### 1. Tool Management System

#### 1.1 Tool Registry
```python
class ToolRegistry:
    def __init__(self):
        self.tools = {
            'rg': {
                'binary': 'rg',
                'fallback': 'grep',
                'required': True,
                'min_version': '12.0.0'
            }
        }
```

#### 1.2 Availability Checking
- Startup validation of all registered tools
- Runtime availability verification before use
- Automatic fallback activation
- User notification of missing tools

### 2. Command Execution Framework

#### 2.1 Safe Execution Wrapper
- Command sanitization and validation
- Environment variable control
- Output capture and size limiting
- Timeout enforcement and cleanup

#### 2.2 Result Processing
- Standard output/error parsing
- Exit code interpretation
- Error message standardization
- Success/failure metric tracking

### 3. Fallback Mechanisms

#### 3.1 Tool Substitution
- Modern tool → standard tool fallbacks (rg → grep)
- Feature-complete alternatives where possible
- Graceful degradation messaging
- Performance impact notifications

#### 3.2 Built-in Alternatives
- Python implementations for critical tools
- Basic functionality when external tools unavailable
- Limited feature sets with clear user communication
- Progressive enhancement when tools become available

## Validation Criteria

### 1. Reliability Metrics

#### 1.1 Tool Availability
- **Essential tools**: 99.9% availability
- **Enhanced tools**: 95% availability with fallbacks
- **Optional tools**: Graceful handling when unavailable
- **Startup validation**: 100% success rate

#### 1.2 Execution Success Rate
- **Command success**: >98% for valid operations
- **Error handling**: 100% for safety violations
- **Timeout handling**: Proper cleanup in 100% of cases
- **Resource limits**: Enforcement in 100% of cases

### 2. Security Validation

#### 2.1 Command Safety
- **Injection prevention**: Zero successful command injections
- **Path traversal**: Zero successful directory escapes
- **Privilege escalation**: Zero unauthorized privilege gains
- **Resource abuse**: Zero resource exhaustion attacks

#### 2.2 Input Validation
- All user inputs properly sanitized
- File paths validated and constrained
- Command arguments escaped appropriately
- Output data validated before processing

### 3. Performance Standards

#### 3.1 Execution Performance
- **Fast tools** (rg, fd): <1s for typical operations
- **Standard tools** (git, ctags): <5s for typical operations
- **Heavy tools** (scc, tokei): <30s for large codebases
- **Fallback performance**: <2x slower than native tool

#### 3.2 Resource Efficiency
- Memory usage tracking and limiting
- CPU usage monitoring for long-running tools
- Disk space management for temporary files
- Network usage monitoring for tools with network access

## Enforcement

### 1. Automated Safety Measures

#### 1.1 Command Validation
- Pre-execution safety checks
- Real-time resource monitoring
- Automatic termination of runaway processes
- Post-execution cleanup verification

#### 1.2 Security Enforcement
- Command whitelist validation
- Path restriction enforcement
- Output sanitization for sensitive data
- Audit logging of all tool executions

### 2. Violation Response

#### 2.1 Safety Violations
- **Critical**: Immediate termination and alert
- **High**: Block execution with user notification
- **Medium**: Execute with warnings and monitoring
- **Low**: Log incident for review

#### 2.2 Performance Violations
- Automatic timeout enforcement
- Resource usage alerts and throttling
- Fallback activation for slow tools
- User notification of performance issues

### 3. Quality Assurance

#### 3.1 Testing Requirements
- Unit tests for all tool integrations
- Integration tests for command execution
- Security testing for input validation
- Performance testing for resource limits

#### 3.2 Monitoring and Metrics
- Tool availability monitoring
- Command execution success rates
- Performance metrics tracking
- Security incident logging

## Emergency Procedures

### 1. Tool Failure Response

#### 1.1 Critical Tool Failure
1. Activate fallback mechanisms immediately
2. Notify user of degraded functionality
3. Log incident for investigation
4. Attempt automatic recovery

#### 1.2 Mass Tool Unavailability
1. Enter safe mode with built-in alternatives
2. Provide user guidance for tool installation
3. Prioritize essential functionality
4. Plan for graceful system recovery

### 2. Security Incident Response

#### 2.1 Command Injection Detection
1. Immediately terminate suspicious processes
2. Block further executions from affected source
3. Review and strengthen input validation
4. Audit recent command history

#### 2.2. Resource Abuse Detection
1. Terminate resource-intensive processes
2. Implement temporary resource restrictions
3. Investigate source of abuse
4. Enhance monitoring and limits

### 3. Performance Emergency

#### 3.1 Tool Performance Degradation
1. Activate faster alternatives or fallbacks
2. Implement temporary timeouts
3. Notify users of performance issues
4. Plan for performance optimization

#### 3.2 System Resource Exhaustion
1. Terminate non-essential tool executions
2. Implement emergency resource limits
3. Clear temporary files and caches
4. Restore normal operations when resources available