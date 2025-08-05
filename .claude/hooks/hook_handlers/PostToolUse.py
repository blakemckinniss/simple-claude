#!/usr/bin/env python3
"""
PostToolUse hook handler compliant with HOOK_CONTRACT.md.
This hook is called after Claude uses a tool.
Automatically fixes Python files using python_auto_fixer.py.
"""

import json
import sys
import os
from typing import Dict, Any


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


def main():
    """Main entry point for PostToolUse hook."""
    try:
        # Read and validate JSON input from stdin
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Validate input data
    if not sanitize_input(input_data):
        sys.exit(1)
    
    try:
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {})
        cwd = input_data.get("cwd", "")
        
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


if __name__ == "__main__":
    main()