#!/usr/bin/env python3
# claude-exempt: File Without Context Manager - Existing code pattern from extracted functions
"""
Utility Functions

Contains general utility functions extracted from PostToolUse.py for better organization.
Provides input sanitization, Python fixer logic, TODO extraction, and bash command analysis.
"""

import re
import sys
from typing import Dict, Any, Optional, List, Tuple


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


def should_trigger_python_fixer(
    tool_name: str, tool_input: Dict[str, Any], cwd: str
) -> bool:
    """
    Determine if the Python auto-fixer should be triggered based on tool usage.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        cwd: Current working directory

    Returns:
        True if Python fixer should be triggered, False otherwise
    """
    # Only trigger for file modification operations
    file_modification_tools = ["Edit", "Write", "MultiEdit"]
    if tool_name not in file_modification_tools:
        return False

    # Check if we're dealing with Python files
    python_files = []
    
    if tool_name in ["Edit", "Write"]:
        file_path = tool_input.get("file_path", "")
        if file_path and file_path.endswith(".py"):
            python_files.append(file_path)
    elif tool_name == "MultiEdit":
        file_path = tool_input.get("file_path", "")
        if file_path and file_path.endswith(".py"):
            python_files.append(file_path)

    if not python_files:
        return False

    # Check for syntax error indicators in tool input
    syntax_error_indicators = [
        "syntaxerror",
        "indentationerror",
        "invalid syntax",
        "unexpected indent",
        "expected :",
        "missing parenthesis",
        "unexpected eof",
        "invalid character",
    ]

    # Check file content or tool input for syntax issues
    content_to_check = ""
    
    if tool_name == "Write":
        content_to_check = tool_input.get("content", "")
    elif tool_name in ["Edit", "MultiEdit"]:
        # For edits, check the new_string content
        if tool_name == "Edit":
            content_to_check = tool_input.get("new_string", "")
        elif tool_name == "MultiEdit" and "edits" in tool_input:
            # Check all edit strings
            edit_strings = []
            for edit in tool_input.get("edits", []):
                if "new_string" in edit:
                    edit_strings.append(edit["new_string"])
            content_to_check = " ".join(edit_strings)

    # Check content for potential syntax issues
    content_lower = content_to_check.lower()
    has_syntax_indicators = any(
        indicator in content_lower for indicator in syntax_error_indicators
    )

    # Check for common Python syntax patterns that might need fixing
    syntax_patterns = [
        r'def\s+\w+\([^)]*\)\s*$',  # Function without colon
        r'if\s+.*\s*$',             # If statement without colon
        r'for\s+.*\s*$',            # For loop without colon
        r'while\s+.*\s*$',          # While loop without colon
        r'class\s+\w+.*\s*$',       # Class definition without colon
        r'try\s*$',                 # Try without colon
        r'except.*\s*$',            # Except without colon
        r'else\s*$',                # Else without colon
        r'elif.*\s*$',              # Elif without colon
    ]

    has_syntax_patterns = any(
        re.search(pattern, content_to_check, re.MULTILINE)
        for pattern in syntax_patterns
    )

    # Trigger fixer if we have indicators or patterns
    return has_syntax_indicators or has_syntax_patterns


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


def analyze_bash_command(command: str, modern_cli_replacements: Optional[Dict[str, Dict[str, str]]] = None) -> List[Tuple[str, str, str]]:
    """Analyze bash command and suggest modern alternatives.

    Args:
        command: Bash command to analyze
        modern_cli_replacements: Dictionary of CLI replacements from constants
    
    Returns:
        List of (old_tool, modern_tool, reason) tuples
    """
    suggestions = []
    command_lower = command.lower()

    # Use provided replacements or fallback to hardcoded ones
    if modern_cli_replacements:
        replacements = {}
        for old_tool, config in modern_cli_replacements.items():
            new_tool = config.get("new_tool", old_tool)
            reason = config.get("reason", f"Use {new_tool} instead of {old_tool}")
            replacements[old_tool] = (new_tool, reason)
    else:
        # Fallback Modern CLI tool mappings from CLAUDE.md CLI_CONTRACT
        replacements = {
            "grep": ("rg", "ripgrep is 10x faster with better defaults and colored output"),
            "find": ("fd", "fd is faster with intuitive syntax and respects .gitignore"),
            "ls": ("lsd", "lsd provides beautiful colored output with icons"),
            "sed": ("sd", "sd has simpler regex syntax and better error messages"),
            "du": ("dust", "dust shows disk usage with visual tree and faster scanning"),
            "df": ("duf", "duf displays disk usage with colors and human-readable format"),
            "ps": ("procs", "procs shows processes with colors and additional info"),
            "curl": ("xh", "xh has simpler syntax and JSON support built-in"),
            "dig": ("dog", "dog provides colored output and modern DNS lookups"),
            "diff": (
                "delta",
                "delta shows beautiful side-by-side diffs with syntax highlighting",
            ),
        }

    # Check for each old tool in the command
    for old_tool, (new_tool, reason) in replacements.items():
        # Look for the tool as a standalone command (not as part of another word)
        pattern = r"\b" + re.escape(old_tool) + r"\b"
        if re.search(pattern, command_lower):
            suggestions.append((old_tool, new_tool, reason))

    return suggestions