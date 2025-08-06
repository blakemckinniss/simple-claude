#!/usr/bin/env python3
"""
File Summarization Module
Provides comprehensive file analysis and summarization functions.
"""

import ast
import json
from pathlib import Path
from typing import Dict, Any

from hook_tools.utilities.path_resolver import PathResolver
from hook_tools.analysis.ast_analyzer import (
    extract_imports,
    extract_todos,
    extract_function_calls,
    extract_type_hints,
    calculate_complexity,
    _extract_call_name
)
from hook_tools.analysis.performance_analyzer import (
    detect_performance_hotspots,
)

# Initialize path resolver for consistent path handling
paths = PathResolver()


def load_constants() -> Dict[str, Any]:
    """Load configuration constants from JSON file using PathResolver."""
    constants_path = paths.hooks_root / "json" / "constants.json"
    try:
        with open(constants_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Constants file not found: {constants_path}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in constants file: {e}")


# Load constants globally with error handling
try:
    CONSTANTS = load_constants()
except RuntimeError as e:
    import sys
    print(f"Error loading constants: {e}", file=sys.stderr)
    sys.exit(2)  # Block execution if constants cannot be loaded


def detect_code_quality_issues(filepath: str, content: str) -> list:
    """Detect anti-patterns and code quality issues."""
    issues = []
    
    try:
        tree = ast.parse(content)
        
        # Check for various anti-patterns
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Long method
                func_lines = content[node.lineno-1:node.end_lineno].count('\n') if hasattr(node, 'end_lineno') else 0
                if func_lines > 50:
                    issues.append({
                        "type": "long_method",
                        "name": node.name,
                        "lines": func_lines,
                        "suggestion": "Consider breaking into smaller functions"
                    })
                
                # Too many parameters
                if len(node.args.args) > 5:
                    issues.append({
                        "type": "too_many_parameters",
                        "name": node.name,
                        "count": len(node.args.args),
                        "suggestion": "Consider using configuration object or builder pattern"
                    })
            
            elif isinstance(node, ast.ClassDef):
                # God class detection
                methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
                if len(methods) > 20:
                    issues.append({
                        "type": "god_class",
                        "name": node.name,
                        "method_count": len(methods),
                        "suggestion": "Consider splitting into smaller, focused classes"
                    })
    except Exception:
        pass
    
    return issues


def calculate_file_metrics(filepath: str, source: str) -> Dict[str, Any]:
    """Calculate code quality metrics for a file.
    
    Args:
        filepath: Path to the file being analyzed
        source: Source code content
        
    Returns:
        Dict with metrics: lines_of_code, comment_ratio, avg_line_length, is_test_file
    """
    try:
        lines = source.splitlines()
        total_lines = len(lines)
        
        if total_lines == 0:
            return {
                "lines_of_code": 0,
                "comment_ratio": 0.0,
                "avg_line_length": 0.0,
                "is_test_file": False
            }
        
        # Count code lines (non-empty, non-comment)
        code_lines = 0
        comment_lines = 0
        total_char_count = 0
        
        for line in lines:
            stripped = line.strip()
            total_char_count += len(line)
            
            if not stripped:  # Empty line
                continue
            elif stripped.startswith('#'):  # Comment line
                comment_lines += 1
            else:  # Code line (may have inline comments)
                code_lines += 1
                # Check for inline comments
                if '#' in line:
                    # Simple heuristic: if # is not in a string literal
                    # This is basic - doesn't handle all edge cases
                    if line.count('"') % 2 == 0 and line.count("'") % 2 == 0:
                        comment_lines += 0.5  # Partial credit for inline comments
        
        # Calculate metrics
        lines_of_code = code_lines
        comment_ratio = comment_lines / total_lines if total_lines > 0 else 0.0
        avg_line_length = total_char_count / total_lines if total_lines > 0 else 0.0
        
        # Detect test files
        filename = Path(filepath).name.lower()
        is_test_file = (
            filename.startswith('test_') or
            filename.endswith('_test.py') or
            'test' in filename or
            '/tests/' in filepath.lower() or
            any(test_import in source.lower() for test_import in [
                'import unittest', 'import pytest', 'from unittest', 'from pytest',
                'import nose', 'from nose', 'import doctest'
            ])
        )
        
        return {
            "lines_of_code": int(lines_of_code),
            "comment_ratio": round(comment_ratio, 3),
            "avg_line_length": round(avg_line_length, 1),
            "is_test_file": is_test_file
        }
        
    except Exception:
        # Return safe defaults on any error
        return {
            "lines_of_code": 0,
            "comment_ratio": 0.0,
            "avg_line_length": 0.0,
            "is_test_file": False
        }


def summarize_python_file(filepath: str) -> Dict[str, Any]:
    """Analyze and summarize a Python file.
    
    Args:
        filepath: Path to the Python file to analyze
        
    Returns:
        Dict containing file summary with functions, classes, imports, etc.
    """
    try:
        with open(filepath, 'r', encoding=CONSTANTS["file_encoding"]["default"], 
                  errors=CONSTANTS["file_encoding"]["error_handling"]) as f:
            source = f.read()
        tree = ast.parse(source)
    except Exception:
        return {"description": CONSTANTS["file_summary"]["unreadable_python"]}

    summary = {
        "functions": [], 
        "classes": [], 
        "docstring": "", 
        "imports": [], 
        "todos": [], 
        "complexity": 0, 
        "function_calls": {}, 
        "type_hints": {}
    }
    
    # Extract functions and classes
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            args = [arg.arg for arg in node.args.args]
            summary["functions"].append(f"{node.name}({', '.join(args)})")
        elif isinstance(node, ast.ClassDef):
            summary["classes"].append(node.name)

    # Extract additional metadata
    summary["docstring"] = ast.get_docstring(tree) or ""
    summary["imports"] = extract_imports(tree)[:5]  # Limit to 5 most important
    summary["todos"] = extract_todos(source)[:3]  # Limit to 3 TODOs
    summary["complexity"] = calculate_complexity(tree)
    
    # Extract function call relationships and type hints
    function_calls = extract_function_calls(tree)
    summary["function_calls"] = dict(list(function_calls.items())[:5])  # Limit to 5 functions
    
    type_hints = extract_type_hints(tree)
    summary["type_hints"] = dict(list(type_hints.items())[:5])  # Limit to 5 functions
    
    # Add performance hotspots
    hotspots = detect_performance_hotspots(tree, source)
    if hotspots:
        summary["performance_hotspots"] = hotspots[:3]  # Limit to top 3 hotspots
    
    # Add code quality issues
    quality_issues = detect_code_quality_issues(filepath, source)
    if quality_issues:
        summary["quality_issues"] = quality_issues[:3]  # Limit to top 3 issues
    
    # Add code quality metrics
    metrics = calculate_file_metrics(filepath, source)
    summary["metrics"] = metrics
    
    if summary["functions"] or summary["classes"]:
        summary["description"] = CONSTANTS["file_summary"]["classes_functions_template"].format(
            classes_count=len(summary['classes']), 
            functions_count=len(summary['functions'])
        )
    else:
        summary["description"] = CONSTANTS["file_summary"]["module_level_fallback"]

    return summary


def summarize_text_file(filepath: str) -> Dict[str, Any]:
    """Analyze and summarize a text file.
    
    Args:
        filepath: Path to the text file to analyze
        
    Returns:
        Dict containing file summary with description and first line
    """
    try:
        with open(filepath, 'r', encoding=CONSTANTS["file_encoding"]["default"], 
                  errors=CONSTANTS["file_encoding"]["error_handling"]) as f:
            for line in f:
                line = line.strip()
                if line:
                    truncate_len = CONSTANTS["text_limits"]["description_truncate_length"]
                    suffix = CONSTANTS["text_limits"]["truncate_suffix"]
                    return {
                        "description": line[:truncate_len] + (suffix if len(line) > truncate_len else ""),
                        "docstring": line
                    }
    except:
        return {"description": CONSTANTS["file_summary"]["unreadable_text"]}
    return {"description": CONSTANTS["file_summary"]["empty_text"]}


def summarize_json_file(filepath: str) -> Dict[str, Any]:
    """Analyze and summarize a JSON file.
    
    Args:
        filepath: Path to the JSON file to analyze
        
    Returns:
        Dict containing file summary with keys if it's a JSON object
    """
    try:
        with open(filepath, 'r', encoding=CONSTANTS["file_encoding"]["default"]) as f:
            data = json.load(f)
        if isinstance(data, dict):
            max_keys = CONSTANTS["text_limits"]["max_json_keys_display"]
            return {
                "description": CONSTANTS["file_summary"]["json_config"], 
                "keys": list(data.keys())[:max_keys]
            }
        return {"description": CONSTANTS["file_summary"]["json_non_dict"]}
    except:
        return {"description": CONSTANTS["file_summary"]["unreadable_json"]}


def summarize_file(filepath: str) -> Dict[str, Any]:
    """Main file summarization function that routes to appropriate analyzer.
    
    Args:
        filepath: Path to the file to analyze
        
    Returns:
        Dict containing file summary based on file type
    """
    # Security: Validate file path
    filepath_obj = Path(filepath)
    
    # Check for path traversal attempts
    if ".." in str(filepath) or filepath_obj.is_absolute():
        return {"description": "Security: Path validation failed"}
    
    # Check if file exists and is within project
    if not filepath_obj.exists() or not filepath_obj.is_file():
        return {"description": "File not found or not a file"}
    
    # Size limit check (5MB)
    if filepath_obj.stat().st_size > 5 * 1024 * 1024:
        return {"description": "File too large (>5MB)"}
    
    ext = filepath_obj.suffix.lower()
    exts = CONSTANTS["file_extensions"]
    if ext == exts["python"]:
        return summarize_python_file(filepath)
    elif ext == exts["json"]:
        return summarize_json_file(filepath)
    elif ext in [exts["markdown"], exts["text"]]:
        return summarize_text_file(filepath)
    else:
        return {"description": CONSTANTS["file_summary"]["skipped_file_prefix"] + filepath}