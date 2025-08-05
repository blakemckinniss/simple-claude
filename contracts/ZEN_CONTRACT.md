# ZEN MCP (Model Context Protocol) Contract

## Purpose
This contract establishes the governing rules, principles, and usage patterns for ZEN MCP - a multi-model AI orchestration system that enables strategic collaboration between different AI models (Gemini, O3, Claude, Ollama, etc.) within the Better Claude ecosystem. This contract ensures proper usage, integration, and expansion of ZEN's capabilities.

## Core Principles

### 1. ZEN Architecture Overview

#### 1.1 System Components
- **ZEN MCP Server**: Multi-model orchestration platform enabling AI model collaboration
- **ZEN Analyst**: Tools specialist for AI-assisted analysis
- **ZEN Specialist**: First responder and strategic coordinator  
- **Context Management**: Fresh 200k token context for each subagent
- **XML Protocol**: Structured communication format for execution plans

#### 1.2 Available Models
ZEN can orchestrate between:
- Gemini (1206, 2.0 Flash, 1.5 Pro/Flash)
- O3 (High, Medium, Low, Mini)
- Claude (Opus, Sonnet, Haiku)
- Ollama (local models)
- OpenAI models
- Additional models as configured

#### 1.3 MCP Tool Hierarchy
```
mcp__zen__[tool_name]
├── thinkdeep    - Deep investigation and comprehensive analysis
├── debug        - Systematic debugging and issue resolution
├── analyze      - Assessment, review, and evaluation
├── consensus    - Multi-perspective decision making
├── chat         - General consultation and brainstorming
├── refactor     - Code restructuring and improvement
├── secaudit     - Security vulnerability analysis
├── testgen      - Test strategy and generation
├── docgen       - Documentation generation
└── planner      - Strategic planning and architecture
```

### 2. Communication Protocol

#### 2.1 XML Execution Plan Format
```xml
<execution_plan>
  <primary_approach>Main strategy description</primary_approach>
  <delegation_required>true/false</delegation_required>
  <specialists_needed>
    <specialist>
      <type>specialist-type</type>
      <task>Specific task description</task>
      <rationale>Why this specialist is needed</rationale>
    </specialist>
  </specialists_needed>
  <workflow>
    <step number="1">
      <description>Step description</description>
      <specialist>specialist-type or main-thread</specialist>
      <dependencies>Previous step numbers</dependencies>
    </step>
  </workflow>
  <context_requirements>
    <requirement>Required context or files</requirement>
  </context_requirements>
  <success_metrics>
    <metric>Measurable success criteria</metric>
  </success_metrics>
</execution_plan>
```

#### 2.2 Thinking Modes
| Mode | Percentage | Use Case |
|------|------------|----------|
| Minimal | 0.5% | Simple queries, quick lookups |
| Light | 5% | Basic analysis, straightforward problems |
| Standard | 20% | Typical development tasks |
| Deep | 50% | Complex problem solving |
| Maximum | 100% | Critical architectural decisions |

### 3. Integration Patterns

#### 3.1 UserPromptSubmit Hook Integration
ZEN is integrated through the unified_smart_advisor module:
- Pattern matching for ZEN tool selection
- Automatic tool recommendations based on prompt analysis
- Score-based tool prioritization
- Integration with agent recommendations

#### 3.2 Tool Selection Patterns
```python
zen_tool_patterns = {
    "thinkdeep": [
        r"\b(investigate|complex|deep|thorough|comprehensive|analyze deeply)\b"
    ],
    "debug": [
        r"\b(debug|bug|error|issue|problem|broken|failing|fix|troubleshoot)\b"
    ],
    "analyze": [
        r"\b(analyze|assessment|review|evaluate|examine|audit)\b"
    ],
    "consensus": [
        r"\b(should I|which is better|compare|decide|choice|opinion)\b"
    ],
    "chat": [
        r"\b(help|how to|explain|guide|question|brainstorm|discuss)\b"
    ]
}
```

#### 3.3 Priority Scoring
- Keyword matches: +1.0 point per match
- Exact word boundaries: +2.0 points
- Multiple keyword matches: Bonus multiplier (1 + 0.1 × count)
- MCP pattern priority: Base priority × score

### 4. Usage Guidelines

#### 4.1 When to Use ZEN
**ALWAYS use ZEN for:**
- Complex architectural decisions requiring multi-perspective analysis
- Deep debugging of intricate issues
- Security audits and vulnerability assessments
- Consensus building on technical choices
- Breaking down complex problems into manageable subtasks

**PREFER ZEN when:**
- Token conservation is important (per CLAUDE.md guidance)
- Multiple specialist perspectives would be valuable
- The task requires systematic, step-by-step analysis
- You need to maintain context across multiple operations

#### 4.2 Invocation Methods
1. **Direct MCP Tool Call**: `use_mcp_tool` with server_name "zen"
2. **Smart Recommendations**: Automatic suggestions via unified_smart_advisor
3. **Manual Override**: Explicit tool specification in prompts
4. **Agent Integration**: Via agent-specific ZEN tool mappings

#### 4.3 Best Practices
- Use `TASK()` wrapper for structured task definitions
- Specify thinking mode based on complexity
- Provide clear context requirements
- Define measurable success metrics
- Leverage delegation for parallel processing

### 5. Specialist Coordination

#### 5.1 First Responder Pattern
The ZEN Specialist acts as the primary strategic coordinator:
1. Receives and analyzes the request
2. Determines if delegation is needed
3. Creates execution plan with specialist assignments
4. Coordinates workflow and dependencies
5. Synthesizes results from multiple specialists

#### 5.2 Available Specialists
| Specialist | Domain | Primary Tools |
|------------|--------|---------------|
| code-refactorer | Code improvement | refactor, analyze |
| security-auditor | Security analysis | secaudit, analyze |
| test-strategist | Testing strategy | testgen, planner |
| debugger | Issue resolution | debug, analyze |
| performance-optimizer | Performance tuning | analyze, thinkdeep |
| api-architect | API design | thinkdeep, planner |
| code-documenter | Documentation | docgen, analyze |
| database-architect | Database design | analyze, planner |
| devops-engineer | Infrastructure | analyze, planner |
| migration-planner | System migration | thinkdeep, planner |

### 6. Context Management

#### 6.1 Token Allocation
- Each subagent receives fresh 200k token context
- Main thread context is preserved
- Selective context sharing based on requirements
- Automatic context summarization for efficiency

#### 6.2 Context Requirements
When invoking ZEN, specify:
- Relevant files and their paths
- Previous analysis or decisions
- Environmental constraints
- Success criteria and metrics

### 7. Error Handling and Recovery

#### 7.1 Failure Modes
| Error Type | Recovery Strategy |
|------------|-------------------|
| Model unavailable | Fallback to alternative model |
| Context overflow | Automatic summarization |
| Timeout | Graceful degradation with partial results |
| Invalid XML | Schema validation and correction |

#### 7.2 Circuit Breakers
- MCP injection: Controlled by INJECTION_CIRCUIT_BREAKERS
- Timeout limits: Configurable per operation
- Retry logic: Exponential backoff for transient failures

### 8. Security Considerations

#### 8.1 Input Validation
- All prompts sanitized before model submission
- XML schema validation for execution plans
- Path traversal protection for file operations
- Sensitive data filtering

#### 8.2 Access Controls
- Model access governed by API keys
- File system access restricted to project scope
- Network operations require explicit permission
- Audit logging for all operations

### 9. Performance Optimization

#### 9.1 Caching Strategies
- Tool recommendation caching via @lru_cache
- Model response caching for identical queries
- Context summarization caching

#### 9.2 Parallel Execution
- Independent specialist tasks run concurrently
- Async/await patterns for I/O operations
- Thread pooling for CPU-intensive operations

### 10. Monitoring and Observability

#### 10.1 Metrics to Track
- Tool selection accuracy
- Model response times
- Token usage per operation
- Success rate by task type
- Error frequency and types

#### 10.2 Logging Requirements
- All ZEN invocations logged with context
- Performance metrics captured
- Error details with stack traces
- Usage patterns for optimization

## Implementation Requirements

### Required Environment Variables
```bash
# API Keys for model access
GEMINI_API_KEY=your_gemini_key
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key

# ZEN Configuration
ZEN_DEFAULT_MODEL=gemini-1206
ZEN_THINKING_MODE=standard
ZEN_TIMEOUT_SECONDS=300
```

### Integration Checklist
- [ ] API keys configured in .env
- [ ] MCP server connection established
- [ ] Tool patterns updated in unified_smart_advisor
- [ ] Circuit breakers properly configured
- [ ] Logging infrastructure in place
- [ ] Performance monitoring enabled

## Compliance and Validation

### Testing Requirements
1. Unit tests for tool selection logic
2. Integration tests for MCP communication
3. End-to-end tests for specialist coordination
4. Performance benchmarks for response times
5. Security audit for input validation

### Documentation Standards
- All ZEN tools must have clear descriptions
- Execution plans must include rationale
- Success metrics must be measurable
- Error messages must be actionable

## Prohibited Actions

The following actions are STRICTLY PROHIBITED when using ZEN MCP:

1. **Never bypass token limits** by attempting to overflow context windows
2. **Never invoke ZEN recursively** within ZEN operations to prevent infinite loops
3. **Never expose API keys** or credentials in prompts or execution plans
4. **Never modify ZEN's core XML protocol** without updating all consumers
5. **Never skip input validation** when processing user prompts
6. **Never ignore thinking mode limits** - respect model capacity constraints
7. **Never execute untrusted code** suggested by models without review
8. **Never disable security filters** for sensitive data processing
9. **Never cache personal or sensitive data** in recommendation systems
10. **Never allow unrestricted file system access** to delegated specialists

## Evolution and Maintenance

### Adding New Tools
1. Define tool in ZEN MCP server configuration
2. Add pattern matching in unified_smart_advisor
3. Document tool purpose and usage
4. Create integration tests
5. Update this contract

### Model Updates
1. Test compatibility with existing tools
2. Update model-specific optimizations
3. Benchmark performance changes
4. Document new capabilities
5. Update fallback strategies

## Enforcement

This contract is enforced through:

1. **Automated Testing**: All ZEN integrations must pass comprehensive test suites
2. **Code Review**: Multi-model orchestration changes require security review
3. **Runtime Validation**: XML protocol validation and schema enforcement
4. **Audit Logging**: All ZEN operations logged for compliance monitoring
5. **Performance Monitoring**: SLA enforcement for response times
6. **Security Scanning**: Regular vulnerability assessments of model interactions
7. **Usage Analytics**: Pattern analysis to detect anomalous usage
8. **Documentation Review**: Contract compliance verification for all changes

By using ZEN MCP within this system, you acknowledge and agree to follow all rules and principles outlined in this contract. Violations may result in feature restrictions or access revocation.

---

*This contract is authoritative for ZEN MCP usage within Better Claude. Updates require review and testing to ensure system stability. This contract supersedes any conflicting documentation and must be updated when official MCP specifications change.*

## Appendix: Quick Reference

### Common ZEN Invocations

**Deep Analysis:**
```
mcp__zen__thinkdeep - For complex architectural decisions
```

**Debugging:**
```
mcp__zen__debug - For systematic issue resolution
```

**Consensus Building:**
```
mcp__zen__consensus - For multi-perspective decisions
```

**Security Audit:**
```
mcp__zen__secaudit - For vulnerability assessment
```

**Code Refactoring:**
```
mcp__zen__refactor - For code improvement suggestions
```

### Integration Example
```python
# In unified_smart_advisor.py
if "complex architecture" in prompt.lower():
    recommendations.append("mcp__zen__thinkdeep")
    
# Direct invocation
result = use_mcp_tool(
    server_name="zen",
    tool_name="analyze",
    arguments={"query": prompt, "mode": "deep"}
)