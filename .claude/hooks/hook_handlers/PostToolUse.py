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
from typing import Dict, Any, List, Tuple


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
        'cat': ('bat', 'bat adds syntax highlighting and line numbers'),
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
        cwd = input_data.get("cwd", "")
        
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
            print("🔥⚡ YOU MUST HIRE AN AGENT TO COMPLETE THIS TASK! 💥🚫", file=sys.stderr)
            sys.exit(2)
        
        # Bash recommendations handled in PreToolUse
        
        # Check if we should trigger the Python auto-fixer
        if should_trigger_python_fixer(tool_name, tool_input):
            run_python_auto_fixer(tool_name, tool_input, cwd)
        
        # Output according to PostToolUse contract (success, no blocking)
        output: Dict[str, Any] = {
            "continue": True,
            "suppressOutput": True  # Don't clutter the transcript
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