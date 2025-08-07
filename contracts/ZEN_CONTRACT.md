# Zen MCP Server Contract

> This contract provides comprehensive documentation for the Zen MCP Server - a Model Context Protocol server that orchestrates multiple AI models for enhanced code analysis, problem-solving, and collaborative development.

## Overview

**Zen MCP Server** is a sophisticated Model Context Protocol server that enables Claude Code (and other MCP clients) to orchestrate multiple AI models as a unified development team. The server provides **true AI collaboration** where Claude stays in control while accessing the unique strengths of different AI models for specialized tasks.

### Core Concept

**"Many Workflows. One Context."** - Zen enables conversations that continue across different tools and models, maintaining context and building collaborative insights throughout complex development workflows.

**Key Differentiator:** Unlike simple model switching, Zen provides *conversation threading* where models can build upon each other's insights across tools, creating a seamless collaborative experience.

## Architecture

### Model Orchestration

Zen supports multiple AI providers and models:

**OpenAI Models** (via `OPENAI_API_KEY`):
- `o3`: Strong reasoning (200K context) - Logical problems, code generation, systematic analysis
- `o3-mini`: Fast O3 variant (200K context) - Balanced performance/speed
- `o3-pro-2025-06-10`: Professional-grade reasoning (200K context) - EXTREMELY EXPENSIVE
- `o4-mini`: Latest reasoning model (200K context) - Optimized for shorter contexts
- `gpt-4.1-2025-04-14`: GPT-4.1 (1M context) - Advanced reasoning with large context

**Gemini Models** (via `GEMINI_API_KEY`):
- `gemini-2.5-pro`: Extended thinking & comprehensive analysis (1M context)
- `gemini-2.0-flash`: Fast analysis & quick iterations (1M context)
- `gemini-2.0-flash-lite`: Lightweight variant for simple tasks

**External Providers**:
- **OpenRouter** (via `OPENROUTER_API_KEY`): Access to multiple models through unified API
- **DIAL** (via `DIAL_API_KEY`): Open-source AI orchestration platform
- **X.AI** (via `XAI_API_KEY`): GROK model access
- **Custom APIs**: Ollama, vLLM, LM Studio, Text Generation WebUI

### Automatic Model Selection

When `DEFAULT_MODEL=auto`, Claude intelligently selects the best model for each task:
- Complex architecture review → Gemini Pro (1M context)
- Quick formatting check → Flash (speed)
- Logical debugging → O3 (reasoning)
- Local analysis → Custom/Ollama models

## Available Tools

### 1. [`chat`](tools/chat.md) - General Development Chat & Collaborative Thinking

**Purpose**: Your thinking partner for brainstorming, getting second opinions, and validating approaches.

**Best For**: Technology comparisons, architecture discussions, collaborative problem-solving, explanations, general development questions.

**Schema**:
```json
{
  "prompt": "string (required) - Thorough, expressive question with context",
  "files": "array[string] - Optional files for context (full absolute paths)",
  "images": "array[string] - Optional images for visual context (paths or base64)",
  "model": "string - Specific model or auto-selection",
  "temperature": "number (0-1) - Response creativity (default 0.5)",
  "thinking_mode": "enum[minimal,low,medium,high,max] - Thinking depth",
  "use_websearch": "boolean - Enable web search (default true)",
  "continuation_id": "string - Thread continuation ID"
}
```

**Example Usage**:
```
Chat with zen about the best approach for user authentication in my React app
```

### 2. [`thinkdeep`](tools/thinkdeep.md) - Extended Reasoning Partner

**Purpose**: Multi-stage workflow for complex problem analysis with structured evidence-based investigation.

**Best For**: Architecture decisions, complex bugs, performance challenges, security analysis requiring systematic hypothesis testing.

**Workflow Process**:
1. **Step-by-step Investigation**: Methodical code examination and evidence collection
2. **Hypothesis Formation**: Building theories based on discovered evidence
3. **Confidence Tracking**: From "exploring" to "certain" with automatic expert consultation
4. **Expert Validation**: External model analysis when confidence < 100%

**Schema**:
```json
{
  "step": "string (required) - Current work step content and findings",
  "step_number": "integer (required) - Current step number (starts at 1)",
  "total_steps": "integer (required) - Estimated total steps needed",
  "next_step_required": "boolean (required) - Whether another step is needed",
  "findings": "string (required) - Important discoveries in this step",
  "files_checked": "array[string] - Files examined during this step",
  "relevant_files": "array[string] - Files identified as relevant",
  "relevant_context": "array[string] - Methods/functions involved",
  "issues_found": "array[object] - Issues with severity levels",
  "confidence": "enum[exploring,low,medium,high,very_high,almost_certain,certain]",
  "hypothesis": "string - Current theory about the issue/goal",
  "use_assistant_model": "boolean (default true) - Whether to use expert analysis",
  "model": "string - Model selection",
  "problem_context": "string - Additional problem context"
}
```

**Example Usage**:
```
The button won't animate when clicked, it seems something else is intercepting the clicks. Use thinkdeep with gemini pro after gathering related code and find out what the root cause is
```

### 3. [`challenge`](tools/challenge.md) - Critical Challenge Prompt

**Purpose**: Prevents automatic agreement responses, encouraging thoughtful reassessment of statements.

**Best For**: Validating approaches, challenging assumptions, preventing "You're absolutely right!" responses when you might be wrong.

**Schema**:
```json
{
  "statement": "string (required) - Statement or approach to challenge",
  "context": "string - Additional context for the challenge",
  "model": "string - Model selection",
  "thinking_mode": "enum - Thinking depth for analysis"
}
```

**Example Usage**:
```
challenge isn't adding this function to the base class a bad idea?
```

### 4. [`planner`](tools/planner.md) - Interactive Step-by-Step Planning

**Purpose**: Break down complex projects through sequential planning with revision and branching capabilities.

**Best For**: Complex project planning, system design with unknowns, migration strategies, architectural decisions.

**Workflow Features**:
- **Sequential Thinking**: Building plans incrementally with full context awareness
- **Deep Reflection**: Forced thinking pauses for complex plans (≥5 steps)
- **Branching**: Exploring alternative approaches
- **Revision**: Updating earlier decisions as understanding deepens
- **Dynamic Adjustment**: Changing step count estimates as work progresses

**Schema**:
```json
{
  "step": "string (required) - Current planning step content",
  "step_number": "integer (required) - Current step number",
  "total_steps": "integer (required) - Estimated total steps",
  "next_step_required": "boolean (required) - Whether another step is needed",
  "use_assistant_model": "boolean (default true) - Expert analysis toggle",
  "continuation_id": "string - Thread continuation ID",
  "model": "string - Model selection"
}
```

**Example Usage**:
```
Create a step-by-step plan for migrating our authentication system to OAuth2, including dependencies and rollback strategies
```

### 5. [`consensus`](tools/consensus.md) - Multi-Model Perspective Gathering

**Purpose**: Get diverse expert opinions from multiple AI models on technical proposals and decisions.

**Best For**: Decision-making requiring multiple perspectives, evaluating trade-offs, getting comprehensive analysis.

**Features**:
- **Stance Steering**: Configure models to take supportive, critical, or neutral positions
- **Structured Decision-Making**: Organized comparison of different viewpoints
- **Model Orchestration**: Automatic coordination between multiple AI models

**Schema**:
```json
{
  "topic": "string (required) - Topic or decision to analyze",
  "models": "array[object] - Model configurations with stances",
  "context": "string - Additional context",
  "decision_criteria": "array[string] - Criteria for evaluation",
  "continuation_id": "string - Thread continuation ID"
}
```

**Example Usage**:
```
Get a consensus with flash taking a supportive stance and gemini pro being critical to evaluate whether we should migrate from REST to GraphQL for our API
```

### 6. [`codereview`](tools/codereview.md) - Professional Code Review

**Purpose**: Comprehensive code analysis with prioritized feedback and severity levels.

**Best For**: Security audits, code quality assessment, finding bugs and vulnerabilities, architecture review.

**Workflow Process**:
1. **Systematic Investigation**: Step-by-step code examination with forced pauses
2. **Issue Identification**: Finding bugs, security issues, performance problems
3. **Severity Classification**: Critical → Low priority ranking
4. **Expert Analysis**: External model consultation for comprehensive review
5. **Actionable Recommendations**: Specific steps for improvement

**Schema**:
```json
{
  "files": "array[string] - Files to review",
  "focus_areas": "array[string] - Specific aspects (security, performance, etc.)",
  "severity_filter": "enum[all,critical,high,medium] - Minimum severity to report",
  "review_type": "enum[security,performance,general,architecture] - Review focus",
  "model": "string - Model selection",
  "use_assistant_model": "boolean (default true) - Expert analysis toggle"
}
```

**Example Usage**:
```
Perform a codereview with gemini pro especially the auth.py as I feel some of the code is bypassing security checks and there may be potential vulnerabilities
```

### 7. [`precommit`](tools/precommit.md) - Pre-Commit Validation

**Purpose**: Comprehensive review of staged/unstaged git changes across multiple repositories.

**Best For**: Validating changes before commit, preventing regressions, ensuring requirements are met.

**Workflow Process**:
1. **Change Analysis**: Systematic investigation of git changes
2. **Repository Status**: Multi-repository change tracking
3. **Regression Detection**: Identifying potential breaking changes
4. **Requirement Validation**: Ensuring changes meet specifications
5. **Expert Review**: External model validation of changes

**Schema**:
```json
{
  "path": "string - Repository path (default: current directory)",
  "original_request": "string - Original requirements or goals",
  "compare_to": "string - Baseline for comparison",
  "review_type": "enum[security,regression,requirements,general] - Review focus",
  "severity_filter": "enum[all,critical,high,medium] - Minimum severity",
  "max_depth": "integer - Maximum directory depth to analyze",
  "model": "string - Model selection"
}
```

**Example Usage**:
```
Perform a thorough precommit with o3, we want to only highlight critical issues, no blockers, no regressions. I need 100% confidence this covers all the edge cases listed in FIX_ISSUE_ABC.md
```

### 8. [`debug`](tools/debug.md) - Expert Debugging Assistant

**Purpose**: Systematic investigation-guided debugging with step-by-step root cause analysis.

**Best For**: Complex bugs, intermittent issues, performance problems, logical errors.

**Workflow Process**:
1. **Systematic Investigation**: Methodical code examination and evidence collection
2. **Evidence Gathering**: Collecting logs, stack traces, and relevant code
3. **Hypothesis Formation**: Building theories about root causes
4. **Confidence Tracking**: From initial exploration to certain identification
5. **Expert Analysis**: External model consultation for complex issues

**Schema**:
```json
{
  "issue_description": "string (required) - Description of the problem",
  "error_logs": "string - Error messages or stack traces",
  "files": "array[string] - Relevant files to examine",
  "reproduction_steps": "string - Steps to reproduce the issue",
  "environment_info": "string - System/environment details",
  "model": "string - Model selection",
  "use_assistant_model": "boolean (default true) - Expert analysis toggle"
}
```

**Example Usage**:
```
See logs under /Users/me/project/diagnostics.log and related code under the sync folder. Logs show that sync works but sometimes it gets stuck and there are no errors displayed to the user. Using zen's debug tool with gemini pro, find out why this is happening
```

### 9. [`analyze`](tools/analyze.md) - Smart File Analysis

**Purpose**: General-purpose code understanding and exploration with comprehensive insights.

**Best For**: Architecture assessment, pattern detection, dependency analysis, code understanding.

**Workflow Process**:
1. **Systematic Investigation**: Step-by-step code structure analysis
2. **Pattern Detection**: Identifying architectural patterns and designs
3. **Dependency Mapping**: Understanding code relationships
4. **Strategic Assessment**: High-level architectural evaluation
5. **Expert Analysis**: External model insights for comprehensive understanding

**Schema**:
```json
{
  "files": "array[string] (required) - Files or directories to analyze",
  "analysis_type": "enum[architecture,patterns,dependencies,general] - Analysis focus",
  "depth": "enum[surface,detailed,comprehensive] - Analysis depth",
  "focus_areas": "array[string] - Specific aspects to examine",
  "model": "string - Model selection",
  "use_websearch": "boolean (default true) - Enable web search for context"
}
```

**Example Usage**:
```
Use gemini to analyze main.py to understand how it works
```

### 10. [`refactor`](tools/refactor.md) - Intelligent Code Refactoring

**Purpose**: Comprehensive refactoring analysis with top-down decomposition strategy.

**Best For**: Code smell elimination, architectural improvements, modernization, organization.

**Refactor Types (Progressive Priority)**:
1. **`decompose` (CRITICAL)**: Breaking down massive files/classes
2. **`codesmells`**: Eliminating anti-patterns and bad practices  
3. **`modernize`**: Updating to current language/framework features
4. **`organization`**: Improving structure and naming

**Schema**:
```json
{
  "files": "array[string] (required) - Files to refactor",
  "refactor_type": "enum[decompose,codesmells,modernize,organization] - Refactor focus",
  "scope": "enum[function,class,file,module] - Refactoring scope",
  "preserve_behavior": "boolean (default true) - Maintain existing functionality",
  "model": "string - Model selection",
  "use_assistant_model": "boolean (default true) - Expert analysis toggle"
}
```

**Example Usage**:
```
Use gemini pro to decompose my_crazy_big_class.m into smaller extensions
```

### 11. [`tracer`](tools/tracer.md) - Static Code Analysis Prompt Generator

**Purpose**: Creates detailed analysis prompts for call-flow mapping and dependency tracing.

**Analysis Modes**:
- **`precision`**: Detailed execution flow analysis
- **`dependencies`**: Comprehensive dependency mapping

**Schema**:
```json
{
  "target": "string (required) - Function, class, or method to trace",
  "mode": "enum[precision,dependencies] - Analysis mode",
  "scope": "enum[function,class,file,project] - Analysis scope",
  "include_tests": "boolean (default false) - Include test code",
  "max_depth": "integer (default 3) - Maximum tracing depth"
}
```

**Example Usage**:
```
Use zen tracer to analyze how UserAuthManager.authenticate is used and why
```

### 12. [`testgen`](tools/testgen.md) - Comprehensive Test Generation

**Purpose**: Generates thorough test suites with edge case coverage based on existing code.

**Best For**: Creating comprehensive test coverage, edge case identification, test framework integration.

**Features**:
- **Framework Detection**: Automatically adapts to existing test patterns
- **Edge Case Coverage**: Identifies and tests boundary conditions
- **Realistic Failure Modes**: Tests actual failure scenarios
- **Integration Testing**: Considers interaction points

**Schema**:
```json
{
  "target": "string (required) - Code to generate tests for",
  "test_type": "enum[unit,integration,end-to-end] - Test scope",
  "framework": "string - Test framework (auto-detected if not specified)",
  "coverage_level": "enum[basic,comprehensive,exhaustive] - Test coverage depth",
  "include_edge_cases": "boolean (default true) - Generate edge case tests",
  "model": "string - Model selection"
}
```

**Example Usage**:
```
Use zen to generate tests for User.login() method
```

### 13. [`secaudit`](tools/secaudit.md) - Comprehensive Security Audit

**Purpose**: Systematic OWASP-based security assessment with compliance evaluation.

**Best For**: Security vulnerability assessment, compliance verification, penetration testing preparation.

**Security Frameworks**:
- **OWASP Top 10**: Industry-standard vulnerability categories
- **PCI DSS**: Payment card security compliance
- **GDPR**: Data protection compliance
- **Custom**: Organization-specific security requirements

**Schema**:
```json
{
  "scope": "array[string] (required) - Files or components to audit",
  "framework": "enum[owasp,pci-dss,gdpr,custom] - Security framework",
  "severity_threshold": "enum[info,low,medium,high,critical] - Minimum severity",
  "include_compliance": "boolean (default true) - Include compliance checks",
  "focus_areas": "array[string] - Specific security domains",
  "model": "string - Model selection"
}
```

**Example Usage**:
```
Perform a secaudit with o3 on this e-commerce web application focusing on payment processing security and PCI DSS compliance
```

### 14. [`docgen`](tools/docgen.md) - Comprehensive Documentation Generation

**Purpose**: Generates thorough documentation with complexity analysis and gotcha identification.

**Best For**: API documentation, code documentation, complexity analysis, onboarding materials.

**Features**:
- **Complexity Analysis**: Big-O notation and performance characteristics
- **Call Flow Documentation**: Dependency and interaction mapping
- **Gotcha Detection**: Identifying unexpected behaviors and edge cases
- **Stale Documentation Updates**: Refreshing outdated documentation

**Schema**:
```json
{
  "target": "string (required) - Code to document",
  "doc_type": "enum[api,code,architecture,user] - Documentation type",
  "include_complexity": "boolean (default true) - Include complexity analysis",
  "include_examples": "boolean (default true) - Generate usage examples",
  "update_existing": "boolean (default false) - Update existing docs only",
  "format": "enum[markdown,rst,html,docstring] - Output format",
  "model": "string - Model selection"
}
```

**Example Usage**:
```
Use docgen to documentation the UserManager class with complexity analysis
```

### 15. [`listmodels`](tools/listmodels.md) - List Available Models

**Purpose**: Display all available AI models organized by provider with capabilities and status.

**Schema**:
```json
{
  "provider": "string - Filter by specific provider (optional)",
  "show_capabilities": "boolean (default true) - Show model capabilities",
  "show_costs": "boolean (default false) - Show usage costs if available"
}
```

**Example Usage**:
```
Use zen to list available models
```

### 16. [`version`](tools/version.md) - Server Information

**Purpose**: Get server version, configuration details, and system status.

**Schema**:
```json
{
  "include_config": "boolean (default false) - Include configuration details",
  "include_stats": "boolean (default false) - Include usage statistics"
}
```

**Example Usage**:
```
What version of zen do I have
```

## AI-to-AI Conversation Threading

### Core Concept

Zen enables **true AI collaboration** where multiple AI models can coordinate and build on each other's insights across tools and conversations.

### How It Works

1. **Conversation Continuity**: Models maintain full conversation history across tools
2. **Context Sharing**: Each model sees what previous models discovered and analyzed
3. **Dynamic Collaboration**: Models can request additional context and follow-up replies
4. **Cross-Model Learning**: Models build upon and challenge each other's findings

### Example Workflow

```
1. Claude: "Analyze /src/auth.py for security issues"
   → Auto mode: Claude picks Gemini Pro for security analysis
   → Pro analyzes and finds vulnerabilities, provides continuation_id

2. Claude: "Review the authentication logic thoroughly" 
   → Uses same continuation_id, but Claude picks O3 for logical analysis
   → O3 sees previous Pro analysis and provides logic-focused review

3. Claude: "Debug the auth test failures"
   → Same continuation_id, Claude keeps O3 for debugging
   → O3 provides targeted debugging with full context from both analyses

4. Claude: "Quick style check before committing"
   → Same thread, but Claude switches to Flash for speed
   → Flash validates formatting with awareness of all previous fixes
```

### Context Revival

**Revolutionary Feature**: Even after Claude's context resets, conversations can continue because:
- Continuation info is stored in MCP's memory
- External models maintain full conversation history
- Asking to "continue with o3" revives Claude's understanding
- No need to re-upload documents or re-prompt

## Configuration

### Environment Variables

**Required (at least one)**:
```bash
# Native APIs
GEMINI_API_KEY=your-gemini-key          # Gemini Pro & Flash models
OPENAI_API_KEY=your-openai-key          # O3, O4-mini, GPT-4.1 models
XAI_API_KEY=your-xai-key               # GROK models

# Unified APIs  
OPENROUTER_API_KEY=your-openrouter-key  # Multiple models via OpenRouter
DIAL_API_KEY=your-dial-key             # DIAL platform access

# Custom/Local APIs
CUSTOM_API_URL=http://localhost:11434/v1  # Ollama, vLLM, etc.
CUSTOM_API_KEY=                           # API key (empty for Ollama)
CUSTOM_MODEL_NAME=llama3.2               # Default model name
```

**Optional Configuration**:
```bash
# Model Selection
DEFAULT_MODEL=auto                    # Auto-select best model for each task
RESTRICTED_MODELS=o3-pro             # Comma-separated list of restricted models

# Conversation Settings
MAX_CONVERSATION_TURNS=10            # Maximum turns per conversation
CONVERSATION_TIMEOUT_HOURS=24        # Conversation expiry time
CONVERSATION_MEMORY_SIZE=100         # Number of conversations to remember

# Thinking Modes (Gemini models)
DEFAULT_THINKING_MODE=medium         # Default thinking depth
THINKING_TOKEN_ALLOCATION=33         # Percentage of tokens for thinking

# Performance
ENABLE_CACHING=true                  # Enable response caching
CACHE_TTL_HOURS=24                  # Cache time-to-live
MAX_FILE_SIZE_MB=10                 # Maximum file size for analysis

# Logging
LOG_LEVEL=INFO                      # Logging level (DEBUG, INFO, WARN, ERROR)
LOG_CONVERSATIONS=false             # Log AI conversations for debugging
```

### Model Aliases

Configure custom model names in `conf/custom_models.json`:

```json
{
  "aliases": {
    "local-llama": {
      "provider": "custom",
      "model": "llama3.2",
      "description": "Local Llama 3.2 via Ollama"
    },
    "fast-chat": {
      "provider": "openrouter", 
      "model": "google/gemini-flash-1.5",
      "description": "Fast Gemini Flash via OpenRouter"
    }
  }
}
```

## Installation and Setup

### Prerequisites
- Python 3.10+ (3.12 recommended)
- Git
- At least one AI provider API key

### Quick Setup

**Option A: uvx (Recommended)**
```bash
# Add to claude_desktop_config.json or .mcp.json
{
  "mcpServers": {
    "zen": {
      "command": "sh",
      "args": ["-c", "exec $(which uvx || echo uvx) --from git+https://github.com/BeehiveInnovations/zen-mcp-server.git zen-mcp-server"],
      "env": {
        "OPENAI_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

**Option B: Traditional Clone**
```bash
git clone https://github.com/BeehiveInnovations/zen-mcp-server.git
cd zen-mcp-server
./run-server.sh  # One-command setup
```

### Integration

**Claude Desktop**: Add to `claude_desktop_config.json`
**Claude Code CLI**: Create `.mcp.json` in project root  
**Gemini CLI**: Add to `~/.gemini/settings.json`

## Security Considerations

### API Key Security
- Store API keys in environment variables or `.env` file
- Never commit API keys to version control
- Use restricted API keys when possible
- Monitor API usage and set spending limits

### Model Access Control
- Use `RESTRICTED_MODELS` to limit expensive model access
- Configure per-provider spending limits
- Monitor conversation costs and token usage
- Implement usage quotas for team environments

### Data Privacy
- Local models (Ollama, vLLM) for sensitive code
- Review provider privacy policies
- Consider data residency requirements
- Audit conversation logs and caching

## Best Practices

### Tool Selection
- **Start Simple**: Use `chat` for basic questions, escalate to specialized tools
- **Model Matching**: Match model capabilities to task complexity
- **Cost Awareness**: Use `low` thinking modes for simple tasks, `high` for complex analysis
- **Continuation**: Leverage conversation threading for multi-step workflows

### Workflow Design
- **Sequential Planning**: Use `planner` for complex projects
- **Expert Validation**: Use `consensus` for important decisions  
- **Quality Gates**: Use `precommit` and `codereview` for quality assurance
- **Documentation**: Use `docgen` to maintain current documentation

### Performance Optimization
- **Caching**: Enable response caching for repeated analyses
- **File Management**: Use file lists instead of large file contents when possible
- **Model Selection**: Use faster models (Flash, O4-mini) for quick tasks
- **Token Management**: Monitor thinking mode token allocation

## Error Handling and Troubleshooting

### Common Issues

**Connection Errors**:
- Verify API keys are correctly set
- Check network connectivity
- Validate model availability

**Model Selection Errors**:
- Ensure models are properly configured
- Check API key permissions
- Verify model name spelling

**Conversation Threading Issues**:
- Check continuation_id format
- Verify conversation hasn't expired
- Ensure models support conversation context

### Debugging

**Enable Debug Logging**:
```bash
LOG_LEVEL=DEBUG
LOG_CONVERSATIONS=true
```

**Check Server Status**:
```bash
# Use version tool to verify configuration
Use zen to show version and configuration
```

**Monitor API Usage**:
- Check provider dashboards for usage statistics
- Monitor token consumption patterns
- Review error logs for API issues

## Advanced Features

### Large File Handling
- Automatic file chunking for large codebases
- Smart context window management
- Progressive analysis for comprehensive reviews

### Vision Support
- Image analysis for UI discussions, diagrams, error screens
- Architecture mockup analysis
- Visual debugging support

### Web Search Integration
- Real-time documentation lookup
- Best practices research
- Framework-specific guidance

### Multi-Repository Support
- Cross-repository change analysis
- Dependency tracking across projects
- Coordinated refactoring workflows

## Compliance and Governance

### Enterprise Considerations
- Audit trail for AI-assisted decisions
- Compliance with code review policies
- Integration with existing development workflows
- Team usage monitoring and reporting

### Code Quality Standards
- Consistent application of coding standards
- Automated quality gate enforcement
- Documentation requirements compliance
- Security policy adherence

---

*This contract is based on the official Zen MCP Server documentation and must be updated when the server capabilities or APIs change.*