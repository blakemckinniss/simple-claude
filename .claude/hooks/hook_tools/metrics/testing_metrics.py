#!/usr/bin/env python3
"""
Testing Metrics Module
Provides functions for extracting test coverage and quality metrics.
"""

import ast
from typing import Dict, List, Any

# Import the _extract_call_name function from ast_analyzer
from ..analysis.ast_analyzer import _extract_call_name


def extract_test_metrics(test_files: List[str]) -> Dict[str, Any]:
    """Extract test coverage and quality metrics.
    
    Args:
        test_files: List of file paths to test files
        
    Returns:
        Dict containing test metrics with keys:
        - test_count: Number of test functions found
        - assertion_density: Average assertions per test function
        - mock_usage: Boolean indicating if mocking is used
        - coverage_estimate: String estimate of coverage level
    """
    metrics = {
        "test_count": 0,
        "assertion_density": 0,
        "mock_usage": False,
        "coverage_estimate": "unknown"
    }
    
    assertion_count = 0
    for filepath in test_files:
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'):
                        metrics['test_count'] += 1
                    
                    if isinstance(node, ast.Call):
                        # Check for assertion calls - handle both attribute and name calls
                        call_name = _extract_call_name(node.func)
                        if call_name and 'assert' in str(call_name).lower():
                            assertion_count += 1
                        if call_name and 'mock' in str(call_name).lower():
                            metrics['mock_usage'] = True
        except Exception:
            pass
    
    if metrics['test_count'] > 0:
        metrics['assertion_density'] = assertion_count / metrics['test_count']
    
    return metrics