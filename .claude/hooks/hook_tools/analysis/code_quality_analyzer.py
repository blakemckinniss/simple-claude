#!/usr/bin/env python3
"""
Code Quality Analysis Module
Provides code quality analysis functions for detecting anti-patterns and calculating metrics.
"""

import ast
from pathlib import Path
from typing import Dict, List, Any, Optional

from .ast_analyzer import _extract_call_name


def detect_code_quality_issues(filepath: str, content: str) -> List[Dict[str, Any]]:
    """Detect anti-patterns and code quality issues.
    
    Args:
        filepath: Path to the file being analyzed
        content: Source code content as string
        
    Returns:
        List of code quality issues with type, details, and suggestions
    """
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