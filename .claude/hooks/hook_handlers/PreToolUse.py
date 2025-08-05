#!/usr/bin/env python3
"""
PreToolUse hook handler with file creation restrictions.
Blocks .md files outside docs directory and test_*.py files outside tests directory.
"""

import json
import os
import sys
from typing import Dict, Any


def handle(data: Dict[str, Any]) -> None:
    """
    Handle PreToolUse hook events with file creation restrictions.
    
    Args:
        data: Hook event data containing tool information
    """
    try:
        # Extract relevant information - use tool_input per schema
        hook_event_name = data.get("hook_event_name", "")
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        
        
        # Only check file creation tools for restrictions
        file_creation_tools = ["Write", "MultiEdit", "mcp__filesystem__write_file", 
                              "mcp__filesystem__create_directory", "create_or_update_file"]
        
        if tool_name not in file_creation_tools:
            return
            
        # Extract file path from various tool input structures
        file_path = None
        if "file_path" in tool_input:
            file_path = tool_input["file_path"]
        elif "path" in tool_input:
            file_path = tool_input["path"]
        elif "files" in tool_input and isinstance(tool_input["files"], list):
            # Handle MultiEdit with multiple files
            for file_info in tool_input["files"]:
                if isinstance(file_info, dict) and "path" in file_info:
                    check_file_restrictions(file_info["path"])
            return
            
        if not file_path:
            return
            
        check_file_restrictions(file_path)
        
    except Exception as e:
        print(f"Error in PreToolUse handler: {e}", file=sys.stderr)
        sys.exit(1)


def check_file_restrictions(file_path: str) -> None:
    """
    Check if file creation should be blocked based on path restrictions.
    
    Args:
        file_path: Path of file being created
    """
    # Normalize path to absolute
    abs_path = os.path.abspath(file_path)
    project_root = os.environ.get("CLAUDE_PROJECT_DIR", "/home/devcontainers/simple-claude")
    docs_dir = os.path.join(project_root, ".claude", "docs")
    tests_dir = os.path.join(project_root, ".claude", "tests")
    
    # Check .md file restrictions
    if abs_path.endswith('.md'):
        if not abs_path.startswith(docs_dir):
            print(f"Blocked: .md files can only be created in {docs_dir}", file=sys.stderr)
            sys.exit(2)
    
    # Check test_*.py file restrictions
    filename = os.path.basename(abs_path)
    if filename.startswith('test_') and filename.endswith('.py'):
        if not abs_path.startswith(tests_dir):
            print(f"Blocked: test_*.py files can only be created in {tests_dir}", file=sys.stderr)
            sys.exit(2)


if __name__ == "__main__":
    # Read JSON input from stdin
    try:
        input_data = json.load(sys.stdin)
        handle(input_data)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)