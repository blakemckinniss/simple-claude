# PROMPT CONTRACT

## Purpose
This document defines the contract for prompt engineering and context enhancement in the Claude Code system. It ensures consistent, high-quality prompt generation that maximizes Claude's effectiveness while minimizing token usage.

## 1. Core Principles

### 1.1 Context Density
- **Maximum Value, Minimum Tokens**: Every token must carry meaningful information
- **Pre-Processing**: Use smaller models (Gemini) to structure context before Claude
- **Deduplication**: Remove redundant information across context sources
- **Compression**: Use structured formats over verbose descriptions

### 1.2 Prompt Clarity
- **Explicit Instructions**: Clear, actionable directives without ambiguity
- **Structured Format**: Consistent organization across all prompts
- **Context Separation**: Distinguish user request from injected context
- **Metadata Preservation**: Maintain source attribution for context elements

### 1.3 Task Alignment
- **Intent Preservation**: Never alter the user's original request
- **Context Relevance**: Only include context directly related to the task
- **Progressive Enhancement**: Layer context from general to specific
- **Action Orientation**: Focus on what needs to be done, not theory

## 2. Prompt Structure

### 2.1 Required Components
Every enhanced prompt MUST contain:

```
1. USER REQUEST ANALYSIS
   - Original Question: [Exact user input]
   - Task Type Detected: [Category from analysis]

2. CONTEXT SUMMARY
   - Quick overview of available context
   - Key findings from context analysis

3. DETECTED ELEMENTS
   - Specific items found in context
   - Grouped by relevance category

4. ENHANCED REQUEST
   - Primary Task: [User's request]
   - Relevant Context: [Structured context]
   - Recommended Approach: [Based on analysis]

5. CLAUDE CODE META ANALYSIS
   - 20-point questionnaire with context-based answers
```

### 2.2 Context Categories
Context must be categorized and prioritized:

1. **Critical Context** (Always Include)
   - Active errors and warnings
   - Current file/function being modified
   - Direct dependencies

2. **Relevant Context** (Include if Related)
   - Recent changes (git)
   - Test results
   - Related code structures

3. **Supporting Context** (Include if Space)
   - Session history
   - Performance metrics
   - Available tools

## 3. Quality Standards

### 3.1 Questionnaire Requirements
The CLAUDE CODE META ANALYSIS must:
- **Be Specific**: No generic placeholders or default values
- **Be Analytical**: Based on actual context analysis
- **Be Actionable**: Provide clear next steps
- **Be Honest**: Acknowledge uncertainties and risks

### 3.2 Context Processing Rules
- **Extract, Don't Repeat**: Synthesize information from raw context
- **Prioritize Actionable Info**: Errors > Warnings > Suggestions
- **Maintain Traceability**: Include file paths and line numbers
- **Handle Missing Context**: Explicitly note what's unavailable

### 3.3 Enhancement Guidelines
- **Preserve User Intent**: Never change what the user asked for
- **Add, Don't Replace**: Context supplements, never supersedes
- **Structure for Scanning**: Use headers, bullets, and formatting
- **Frontload Critical Info**: Most important context first

## 4. Token Optimization

### 4.1 Compression Techniques
- **Use References**: `src/auth/login.js:45` instead of full paths
- **Aggregate Similar Items**: Group related errors/warnings
- **Truncate Safely**: Show first/last lines with count for long lists
- **Symbolic Representation**: Use symbols (❌ ⚠️ ✅) for status

### 4.2 Context Limits
- **Hard Limit**: 2000 tokens for enhanced context
- **Soft Target**: 1000-1500 tokens optimal
- **Priority Truncation**: Remove supporting before relevant before critical
- **Preserve Coherence**: Never truncate mid-sentence or mid-structure

## 5. Task-Specific Templates

### 5.1 Debugging Template
Focus on:
- Error messages and stack traces
- Recent changes that might have caused issues
- Test failures related to the error
- Previous similar issues from history

### 5.2 Implementation Template
Focus on:
- Existing patterns in codebase
- Available utilities and helpers
- Dependencies and constraints
- Related test coverage

### 5.3 General Template
Balanced approach:
- Overview of current state
- Available resources
- Potential challenges
- Recommended approach

## 6. AI Enhancement Pipeline

### 6.1 Context Gathering Phase
Parallel collection of:
- Git status and recent commits
- Code intelligence (LSP, tree-sitter)
- Test results and coverage
- System state and monitoring
- MCP tools and capabilities

### 6.2 AI Processing Phase
Gemini receives:
- Raw context from all sources
- User's original prompt
- Task-specific template
- System prompt for analysis

### 6.3 Post-Processing Phase
After Gemini response:
- Append static directives
- Add zen-pro orchestration
- Final validation checks
- Token count verification

## 7. Validation Criteria

### 7.1 Completeness Check
✓ All context categories represented
✓ Questionnaire fully populated
✓ No placeholder values
✓ Clear next steps defined

### 7.2 Quality Metrics
- **Specificity Score**: Ratio of specific to generic statements
- **Context Coverage**: Percentage of available context utilized
- **Token Efficiency**: Information density per token
- **Actionability Index**: Number of concrete next steps

### 7.3 Red Flags
❌ Generic questionnaire answers
❌ Missing critical context
❌ Altered user intent
❌ Token limit exceeded
❌ Unstructured content

## 8. Continuous Improvement

### 8.1 Feedback Loop
- Monitor Claude's responses
- Track most useful context types
- Identify missing information patterns
- Refine templates based on outcomes

### 8.2 Template Evolution
- A/B test different structures
- Measure task completion rates
- Optimize for specific task types
- Update based on Claude capabilities

### 8.3 Performance Monitoring
- Token usage statistics
- Response quality metrics
- Task success rates
- Time to completion

## 9. Integration Points

### 9.1 Hook System
- UserPromptSubmit: Primary integration point
- SessionStateManagement: Context persistence
- ErrorRecovery: Fallback mechanisms

### 9.2 Configuration
- `ai_optimizer_config.json`: Templates and patterns
- Environment variables: API keys and flags
- Dynamic adjustments: Based on context size

### 9.3 Extensibility
- New context sources: Plug-in architecture
- Custom templates: Task-specific additions
- Model upgrades: Gemini to other models
- Enhanced analysis: Additional NLP features

## 10. Contract Enforcement

### 10.1 Mandatory Requirements
1. Context enhancement MUST NOT alter user intent
2. Questionnaire MUST be filled with analyzed values
3. Token limits MUST be respected
4. Critical errors MUST be highlighted first

### 10.2 Quality Gates
Before sending to Claude:
1. Validate structure completeness
2. Check token count
3. Verify no placeholders remain
4. Ensure context relevance

### 10.3 Failure Handling
If enhancement fails:
1. Fall back to static enhancement only
2. Log failure for analysis
3. Still process user request
4. Mark degraded enhancement

---

## Summary

This contract ensures that every prompt sent to Claude is:
- **Optimized**: Maximum context in minimum tokens
- **Structured**: Consistent format for reliable parsing
- **Relevant**: Only information that helps the task
- **Actionable**: Clear guidance on what to do
- **Analyzed**: Pre-processed insights from Gemini

By following this contract, we create a prompt enhancement system that amplifies Claude's capabilities while respecting token constraints and maintaining prompt quality.