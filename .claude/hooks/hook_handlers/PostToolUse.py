#!/usr/bin/env python3
"""
PostToolUse hook handler compliant with HOOK_CONTRACT.md.
This hook is called after Claude uses a tool.
Provides CLI recommendations for Bash commands and automatically fixes Python files using python_auto_fixer.py.
"""

import json
import sys
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple

# Import state manager for continuation tracking
sys.path.insert(0, str(Path(__file__).parent.parent))
from hook_tools.state_manager import state_manager


def extract_continuation_id(tool_name: str, tool_input: Dict[str, Any], tool_response: Any) -> str:
    """
    Extract continuation_id from mcp__zen tool responses.
    
    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        tool_response: Response from the tool (can be dict, list, or string)
        
    Returns:
        continuation_id if found, empty string otherwise
    """
    # Only process mcp__zen tools
    if not tool_name.startswith('mcp__zen__'):
        return ""
    
    # Handle different response types
    response_to_check = tool_response
    
    # If response is a list, check the first item
    if isinstance(tool_response, list) and len(tool_response) > 0:
        response_to_check = tool_response[0]
        
        # If the first item is a dict with a 'text' field containing JSON
        if isinstance(response_to_check, dict) and 'text' in response_to_check:
            text_content = response_to_check.get('text', '')
            if isinstance(text_content, str):
                try:
                    response_to_check = json.loads(text_content)
                except (json.JSONDecodeError, ValueError):
                    pass
    
    # If response is a string, try to parse it as JSON
    elif isinstance(response_to_check, str):
        try:
            response_to_check = json.loads(response_to_check)
        except (json.JSONDecodeError, ValueError):
            pass
    
    # Check for continuation_id in the response
    if isinstance(response_to_check, dict):
        # Look for continuation_offer structure
        continuation_offer = response_to_check.get('continuation_offer', {})
        if isinstance(continuation_offer, dict):
            continuation_id = continuation_offer.get('continuation_id', '')
            if continuation_id:
                return continuation_id
        
        # Also check direct continuation_id field
        continuation_id = response_to_check.get('continuation_id', '')
        if continuation_id:
            return continuation_id
    
    return ""


def detect_zen_usage_patterns(tool_name: str, tool_input: Dict[str, Any], session_id: str, cwd: str) -> List[str]:
    """
    Detect patterns that suggest ZEN tools would be beneficial.
    
    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        session_id: Current session identifier
        cwd: Current working directory
        
    Returns:
        List of ZEN tool recommendations
    """
    recommendations = []
    
    # Track multi-file operations
    file_count = 0
    file_paths = []
    
    if tool_name in ['Read', 'Edit', 'MultiEdit', 'Write']:
        # Count files being processed
        for key in ['file_path', 'path', 'filepath']:
            if key in tool_input and tool_input[key]:
                file_paths.append(tool_input[key])
        
        if tool_name == 'MultiEdit' and 'edits' in tool_input:
            file_count = 1  # MultiEdit works on single file
        else:
            file_count = len(file_paths)
    
    # Complex debugging scenarios
    if tool_name == 'Bash' and tool_input.get('command', ''):
        command = tool_input['command'].lower()
        debug_patterns = ['grep', 'rg', 'find', 'fd', 'trace', 'strace', 'gdb', 'debug', 'log', 'error', 'crash', 'fail']
        if any(pattern in command for pattern in debug_patterns):
            recommendations.append("mcp__zen__debug - Systematic debugging with expert analysis for complex issues")
    
    # Security-related operations
    if tool_name in ['Read', 'Grep', 'Bash'] and tool_input:
        content_keys = ['pattern', 'command', 'file_path']
        content = ' '.join(str(tool_input.get(key, '')) for key in content_keys).lower()
        security_patterns = ['auth', 'password', 'token', 'secret', 'key', 'security', 'vuln', 'exploit', 'inject', 'xss', 'sql', 'csrf']
        if any(pattern in content for pattern in security_patterns):
            recommendations.append("mcp__zen__secaudit - Comprehensive security analysis with OWASP compliance")
    
    # Pre-commit validation scenarios
    if tool_name == 'Bash' and tool_input.get('command', ''):
        command = tool_input['command'].lower()
        git_patterns = ['git diff', 'git status', 'git log', 'git add', 'git commit']
        if any(pattern in command for pattern in git_patterns):
            recommendations.append("mcp__zen__precommit - Comprehensive pre-commit validation workflow")
    
    # Code quality and refactoring for Python files
    if tool_name in ['Edit', 'MultiEdit', 'Write'] and file_paths:
        python_files = [fp for fp in file_paths if fp.endswith('.py')]
        if python_files:
            recommendations.append("mcp__zen__refactor - Code improvement and modernization analysis")
            recommendations.append("mcp__zen__codereview - Comprehensive code quality assessment")
    
    # Performance and analysis patterns
    if tool_name == 'Bash' and tool_input.get('command', ''):
        command = tool_input['command'].lower()
        perf_patterns = ['benchmark', 'profile', 'perf', 'time', 'memory', 'cpu', 'optimize', 'performance']
        if any(pattern in command for pattern in perf_patterns):
            recommendations.append("mcp__zen__analyze - Performance analysis and optimization recommendations")
    
    # Test generation patterns
    test_patterns = ['test', 'spec', 'pytest', 'jest', 'unittest', '_test', 'tests/']
    if tool_name in ['Read', 'Write', 'Edit'] and tool_input.get('file_path', ''):
        file_path = tool_input['file_path'].lower()
        if any(pattern in file_path for pattern in test_patterns):
            recommendations.append("mcp__zen__testgen - Comprehensive test suite generation")
    
    # Documentation generation for code files
    if tool_name in ['Read', 'Write'] and tool_input.get('file_path', ''):
        file_path = tool_input['file_path'].lower()
        code_extensions = ('.py', '.js', '.ts', '.java', '.cpp', '.c', '.go', '.rs', '.php', '.rb')
        if file_path.endswith(code_extensions):
            recommendations.append("mcp__zen__docgen - Automated documentation generation")
    
    # Code tracing for complex analysis
    if tool_name in ['Read', 'Grep'] and tool_input:
        content_keys = ['pattern', 'file_path']
        content = ' '.join(str(tool_input.get(key, '')) for key in content_keys).lower()
        trace_patterns = ['function', 'method', 'class', 'import', 'dependency', 'call', 'invoke']
        if any(pattern in content for pattern in trace_patterns):
            recommendations.append("mcp__zen__tracer - Code flow and dependency analysis")
    
    # Consensus building for architectural decisions
    architecture_patterns = ['design', 'architect', 'pattern', 'structure', 'framework', 'library']
    if tool_name in ['Read', 'Write', 'Edit'] and tool_input.get('file_path', ''):
        file_path = tool_input['file_path'].lower()
        if any(pattern in file_path for pattern in architecture_patterns):
            recommendations.append("mcp__zen__consensus - Multi-perspective architectural analysis")
    
    # Multi-step operations (file count threshold)
    if file_count >= 3:
        recommendations.append("mcp__zen__analyze - Multi-file architectural analysis")
        recommendations.append("mcp__zen__planner - Sequential planning for complex operations")
    
    # Planning for complex multi-edit operations
    if tool_name == 'MultiEdit' and tool_input.get('edits', []):
        edit_count = len(tool_input.get('edits', []))
        if edit_count >= 5:
            recommendations.append("mcp__zen__planner - Multi-step editing workflow planning")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_recommendations = []
    for rec in recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recommendations.append(rec)
    
    return unique_recommendations[:3]  # Limit to top 3 recommendations


def generate_zen_prompt_template(tool_name: str, recommendations: List[str], has_continuation: bool, continuation_id: str = "") -> str:
    """
    Generate contextualized prompt templates for ZEN tool usage.
    
    Args:
        tool_name: Name of the tool that was used
        recommendations: List of MUST USE ZEN tools
        has_continuation: Whether session has existing continuation
        continuation_id: Existing continuation ID if available
        
    Returns:
        Formatted prompt template
    """
    if not recommendations:
        return ""
    
    template_parts = []
    
    # Header with context
    if has_continuation and continuation_id:
        template_parts.append(f"🔗 ⚠️⚡💥🚫❌☠️☢️☣️ mcp__zen_* CONTINUATION AVAILABLE!!! YOU PROACTIVELY MUST USE continuation_id='{continuation_id}' FOR CONTEXT CONTINUITY NOW!!! ⚠️⚡💥🚫❌☠️☢️☣️")
    else:
        template_parts.append("🚀 ZEN WORKFLOW MUST USE for enhanced analysis:")
    
    # Add specific recommendations with context
    for i, rec in enumerate(recommendations, 1):
        template_parts.append(f"{i}. {rec}")
    
    # Add usage guidance
    template_parts.append("\n💡 USAGE PATTERN:")
    if has_continuation:
        template_parts.append(f"   Use: mcp__zen__[tool] with continuation_id='{continuation_id}'")
    else:
        template_parts.append("   Use: mcp__zen__[tool] for systematic multi-step analysis")
    
    template_parts.append("   Benefits: 200k token allowance + expert validation + structured workflow")
    
    return "\n".join(template_parts)


def store_continuation_id(session_id: str, continuation_id: str) -> None:
    """
    Store continuation_id for the current session.
    
    Args:
        session_id: Current session identifier
        continuation_id: Continuation ID to store
    """
    if session_id and continuation_id:
        state_manager.set_continuation_id(session_id, continuation_id)


def sanitize_input(input_data: Dict[str, Any]) -> bool:
    """
    Sanitize and validate input data according to security requirements.
    
    Args:
        input_data: Hook event data
        
    Returns:
        True if input is safe, False otherwise
    """
    # Check for required fields
    required_fields = ["session_id", "transcript_path", "cwd", "hook_event_name"]
    for field in required_fields:
        if field not in input_data:
            return False
    
    # Validate paths for traversal attacks
    transcript_path = input_data.get("transcript_path", "")
    cwd = input_data.get("cwd", "")
    
    if ".." in transcript_path or ".." in cwd:
        print("Security: Path traversal blocked", file=sys.stderr)
        return False
    
    # Skip if no tool information
    if not input_data.get("tool_name", ""):
        return False
        
    return True


def should_trigger_python_fixer(tool_name: str, tool_input: Dict[str, Any]) -> bool:
    """
    Determine if python_auto_fixer should be triggered.
    
    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        
    Returns:
        True if python fixer should run, False otherwise
    """
    # Only trigger for file modification tools
    file_tools = ['Write', 'Edit', 'MultiEdit', 'write_to_file', 'apply_diff', 'insert_content']
    if tool_name not in file_tools:
        return False
    
    # Check if any Python files are involved
    file_paths = []
    
    # Extract file paths from various tool input formats
    for key in ['file_path', 'path', 'filepath']:
        if key in tool_input and tool_input[key]:
            file_paths.append(tool_input[key])
    
    # Handle 'args' structure (used by apply_diff and other tools)
    if 'args' in tool_input and isinstance(tool_input['args'], list):
        for item in tool_input['args']:
            if isinstance(item, dict) and 'path' in item:
                file_paths.append(item['path'])
    
    # Check if any path is a Python file
    for file_path in file_paths:
        if isinstance(file_path, str) and file_path.endswith('.py'):
            # Skip hook files and test files to avoid infinite loops
            skip_patterns = ['hook_handlers', 'hook_tools', 'test_', '_test.py', '__pycache__']
            if not any(pattern in file_path.lower() for pattern in skip_patterns):
                return True
    
    return False


def extract_todo_content(tool_input: Dict[str, Any]) -> str:
    """Extract todo content from TodoWrite tool input."""
    todos = tool_input.get("todos", [])
    if not todos:
        return ""
    
    content_parts = []
    for todo in todos:
        if isinstance(todo, dict) and "content" in todo:
            content_parts.append(todo["content"])
    
    return " ".join(content_parts).lower()


def get_agent_info(agents_dir: str) -> List[Tuple[str, str, str]]:
    """Read agent files and extract name, description, and keywords.
    
    Returns:
        List of (filename, description, content) tuples
    """
    agents = []
    if not os.path.exists(agents_dir):
        return agents
    
    for filename in os.listdir(agents_dir):
        if filename.endswith('.md'):
            filepath = os.path.join(agents_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Extract first line as description (usually the title/summary)
                    lines = content.split('\n')
                    description = lines[0] if lines else filename
                    # Clean up markdown title formatting
                    description = re.sub(r'^#+\s*', '', description)
                    agents.append((filename, description, content.lower()))
            except Exception:
                continue
    
    return agents


def analyze_bash_command(command: str) -> List[Tuple[str, str, str]]:
    """Analyze bash command and suggest modern alternatives.
    
    Returns:
        List of (old_tool, modern_tool, reason) tuples
    """
    suggestions = []
    command_lower = command.lower()
    
    # Modern CLI tool mappings from CLAUDE.md CLI_CONTRACT
    replacements = {
        'grep': ('rg', 'ripgrep is 10x faster with better defaults and colored output'),
        'find': ('fd', 'fd is faster with intuitive syntax and respects .gitignore'),
        'ls': ('lsd', 'lsd provides beautiful colored output with icons'),
        'sed': ('sd', 'sd has simpler regex syntax and better error messages'),
        'du': ('dust', 'dust shows disk usage with visual tree and faster scanning'),
        'df': ('duf', 'duf displays disk usage with colors and human-readable format'),
        'ps': ('procs', 'procs shows processes with colors and additional info'),
        'curl': ('xh', 'xh has simpler syntax and JSON support built-in'),
        'dig': ('dog', 'dog provides colored output and modern DNS lookups'),
        'diff': ('delta', 'delta shows beautiful side-by-side diffs with syntax highlighting')
    }
    
    # Check for each old tool in the command
    for old_tool, (new_tool, reason) in replacements.items():
        # Look for the tool as a standalone command (not as part of another word)
        pattern = r'\b' + re.escape(old_tool) + r'\b'
        if re.search(pattern, command_lower):
            suggestions.append((old_tool, new_tool, reason))
    
    return suggestions


def analyze_and_recommend_agents(todo_content: str, cwd: str) -> List[str]:
    """Analyze todo content and recommend relevant agents.
    
    Returns:
        List of agent recommendations with descriptions
    """
    if not todo_content:
        # Fallback to generic project management agents
        return [
            "project-orchestrator.md - Complex multi-phase projects",
            "project-planner.md - Comprehensive project planning", 
            "task-dispatch-director.md - Task coordination"
        ]
    
    agents_dir = os.path.join(cwd, ".claude", "agents")
    agents = get_agent_info(agents_dir)
    
    # Define keyword patterns for different types of work
    patterns = {
        'backend': r'\b(api|server|database|backend|rest|graphql|microservice|endpoint)\b',
        'frontend': r'\b(ui|frontend|react|vue|angular|component|styling|css|tailwind|scss)\b',
        'testing': r'\b(test|testing|unit|integration|e2e|pytest|jest|cypress|spec)\b',
        'devops': r'\b(deploy|docker|kubernetes|ci/cd|pipeline|build|infrastructure)\b',
        'database': r'\b(database|sql|postgres|mysql|mongodb|migration|schema|query)\b',
        'security': r'\b(security|auth|oauth|jwt|encryption|vulnerability|audit)\b',
        'mobile': r'\b(mobile|ios|android|react native|flutter|app)\b',
        'documentation': r'\b(doc|documentation|readme|guide|manual|wiki)\b',
        'performance': r'\b(performance|optimize|speed|benchmark|profiling|memory)\b',
        'refactor': r'\b(refactor|clean|improve|restructure|organize|simplify)\b'
    }
    
    # Score agents based on keyword matches
    scored_agents = []
    for filename, description, content in agents:
        score = 0
        matched_categories = []
        
        # Check if todo content keywords match agent content
        for category, pattern in patterns.items():
            if re.search(pattern, todo_content) and re.search(pattern, content):
                score += 2
                matched_categories.append(category)
        
        # Boost score for exact keyword matches in agent filename/description
        for word in todo_content.split():
            if len(word) > 3:  # Skip short words
                if word in filename.lower() or word in description.lower():
                    score += 1
        
        if score > 0:
            scored_agents.append((score, filename, description, matched_categories))
    
    # Sort by score and return top recommendations
    scored_agents.sort(key=lambda x: x[0], reverse=True)
    
    recommendations = []
    for score, filename, description, categories in scored_agents[:5]:
        cat_hint = f"({', '.join(categories)})" if categories else ""
        recommendations.append(f"{filename} - {description} {cat_hint}")
    
    # If no good matches, fall back to generic agents
    if not recommendations:
        recommendations = [
            "project-orchestrator.md - Complex multi-phase projects",
            "project-planner.md - Comprehensive project planning",
            "workflow-agent.md - Universal workflow orchestration"
        ]
    
    return recommendations[:5]  # Limit to 5 recommendations



def run_python_auto_fixer(tool_name: str, tool_input: Dict[str, Any], cwd: str) -> None:
    """
    Execute the python_auto_fixer.py script.
    
    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        cwd: Current working directory
    """
    try:
        # Import the fixer module using modern importlib approach
        import importlib.util
        import subprocess
        
        fixer_path = os.path.join(os.path.dirname(__file__), "..", "hook_tools", "python_auto_fixer.py")
        
        if os.path.exists(fixer_path):
            try:
                # Load module dynamically using importlib.util
                spec = importlib.util.spec_from_file_location("python_auto_fixer", fixer_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Call the run_auto_fixer function
                    if hasattr(module, 'run_auto_fixer'):
                        module.run_auto_fixer(tool_name, tool_input, cwd)
                    else:
                        raise AttributeError("run_auto_fixer function not found in module")
                else:
                    raise ImportError("Could not create module spec")
                    
            except (ImportError, AttributeError):
                # Fallback to subprocess if import fails
                subprocess.Popen(
                    [sys.executable, fixer_path, tool_name, json.dumps(tool_input), cwd],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                    cwd=cwd
                )
                    
    except Exception:
        # Silent fail - don't block the main workflow
        pass


def handle(input_data: Dict[str, Any]) -> None:
    """Handler function called by hook router."""
    # Validate input data
    if not sanitize_input(input_data):
        sys.exit(1)
    
    try:
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {})
        tool_response = input_data.get("tool_response", {})  # Fixed: PostToolUse receives tool_response, not tool_output
        session_id = input_data.get("session_id", "")
        cwd = input_data.get("cwd", "")
        
        # Debug: Log ALL tools to see what's happening
        with open("/tmp/posttooluse_debug.log", "a") as f:
            f.write(f"\n[{datetime.now().isoformat()}] Tool: {tool_name}\n")
            f.write(f"Session: {session_id}\n")
            f.write(f"Response type: {type(tool_response)}\n")
            if isinstance(tool_response, dict):
                f.write(f"Response keys: {tool_response.keys()}\n")
                if tool_name.startswith('mcp__zen__'):
                    f.write(f"Full response: {tool_response}\n")
            elif isinstance(tool_response, list):
                f.write(f"List length: {len(tool_response)}\n")
                if tool_name.startswith('mcp__zen__') and len(tool_response) > 0:
                    f.write(f"First item type: {type(tool_response[0])}\n")
                    f.write(f"First item: {tool_response[0][:500] if isinstance(tool_response[0], str) else tool_response[0]}\n")
        
        # Extract and store continuation_id from mcp__zen tools
        continuation_id = extract_continuation_id(tool_name, tool_input, tool_response)
        if continuation_id:
            store_continuation_id(session_id, continuation_id)
            # Debug: Log when continuation_id is found and stored
            print(f"DEBUG: Stored continuation_id '{continuation_id}' for session '{session_id}'", file=sys.stderr)
        elif tool_name.startswith('mcp__zen__'):
            # Debug: Log when mcp__zen tool doesn't have continuation_id
            print(f"DEBUG: No continuation_id found in {tool_name} response: {tool_response}", file=sys.stderr)
        
        # Check for Bash commands and provide modern CLI recommendations (non-blocking)
        if tool_name == "Bash":
            command = tool_input.get("command", "")
            if command:
                suggestions = analyze_bash_command(command)
                if suggestions:
                    for old_tool, new_tool, reason in suggestions:
                        print(f"⚡💥 YOU MUST USE {new_tool} INSTEAD OF {old_tool}! 🚫❌", file=sys.stderr)
                    sys.exit(2)
        
        # Check for TodoWrite usage and recommend agents instead
        if tool_name == "TodoWrite":
            print("🔥⚡ VERY IMPORTANT: YOU ABSOLUTELY **MUST** HIRE AN AGENT **OR AGENTS FOR INDEPENDENT PARALLEL/BATCH TASK ITEMS** TO COMPLETE THIS CORRECTLY. PARALLELIZE HIRES (PER CLAUDE.md PATTERN_CONTRACT LAWS D2-D6)!!! 💥🚫", file=sys.stderr)
            sys.exit(2)
        
        # Conditionally output ZEN recommendations based on patterns and frequency
        if not tool_name.startswith('mcp__zen__'):  # Don't suggest ZEN for ZEN tools
            # Check if session has existing continuation
            existing_continuation_id = state_manager.get_continuation_id(session_id) or ""
            has_continuation = bool(existing_continuation_id)
            
            # Detect patterns for enhanced recommendations
            zen_recommendations = detect_zen_usage_patterns(tool_name, tool_input, session_id, cwd)
            
            # Track tool use count for this session (stored in state manager)
            tool_count = state_manager.increment_tool_count(session_id)
            
            # Determine if we should show ZEN recommendations
            should_show_zen = False
            
            # High-priority patterns that ALWAYS trigger recommendations
            high_priority_tools = ['Task', 'Bash', 'Grep', 'Edit', 'MultiEdit', 'TodoWrite']
            if tool_name in high_priority_tools:
                should_show_zen = True
            
            # Pattern-based recommendations (when we detected useful patterns)
            elif zen_recommendations:
                should_show_zen = True
            
            # Continuation available - show every 3rd tool use
            elif has_continuation and tool_count % 3 == 0:
                should_show_zen = True
            
            # General frequency - show every 5th tool use for awareness
            elif tool_count % 5 == 0:
                should_show_zen = True
            
            # Multi-file operations or complex patterns
            if tool_name == 'MultiEdit' and tool_input.get('edits', []):
                if len(tool_input.get('edits', [])) >= 3:
                    should_show_zen = True
            
            if should_show_zen:
                # Generate base continuation message
                if has_continuation:
                    base_message = f"🔗 ZEN CONTINUATION AVAILABLE: Use continuation_id='{existing_continuation_id}' with mcp__zen__* tools for context continuity"
                else:
                    base_message = "🚀 ZEN WORKFLOW MUST USE: Start with mcp__zen__* tools for enhanced analysis (200k token allowance + expert validation)"
                
                # Add pattern-based recommendations if available
                if zen_recommendations:
                    zen_prompt = generate_zen_prompt_template(
                        tool_name, 
                        zen_recommendations, 
                        has_continuation, 
                        existing_continuation_id
                    )
                    if zen_prompt:
                        final_message = f"{base_message}\n\n{zen_prompt}"
                    else:
                        final_message = base_message
                else:
                    final_message = base_message
                
                # Output the message using exit code 2 so Claude sees it
                print(f"\n{final_message}", file=sys.stderr)
                sys.exit(2)
        
        # Check if we should trigger the Python auto-fixer
        if should_trigger_python_fixer(tool_name, tool_input):
            run_python_auto_fixer(tool_name, tool_input, cwd)
        
        # Output according to PostToolUse contract (success, no blocking)
        output: Dict[str, Any] = {
            "continue": True,
            "suppressOutput": False  # Allow ZEN recommendations to be visible
        }
        
        print(json.dumps(output))
        sys.exit(0)
        
    except Exception as e:
        print(f"Error in PostToolUse handler: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point for standalone execution."""
    try:
        # Read and validate JSON input from stdin
        input_data = json.load(sys.stdin)
        handle(input_data)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()