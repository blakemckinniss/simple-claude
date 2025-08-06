#!/usr/bin/env python3
"""
Import dependency graph utilities.

This module provides functionality to analyze Python files and build
dependency graphs based on their import statements.
"""

import os
import ast
from subprocess import check_output
from typing import Dict, List


def build_import_graph(constants: Dict[str, any]) -> Dict[str, List[str]]:
    """
    Build a dependency graph by analyzing Python files and extracting their imports.
    
    Uses git ls-files to discover Python files in the repository, parses their AST
    to extract import statements, and returns a mapping of file paths to their imports.
    Limited to 50 files for performance.
    
    Args:
        constants: Configuration constants dictionary containing file encoding settings
    
    Returns:
        Dict mapping file paths to lists of imported module names
        
    Performance Notes:
        - Limited to 50 files for performance optimization
        - Uses graceful degradation for files that can't be parsed
        - Skips relative imports without module names
        
    Error Handling:
        - Continues processing if individual files fail to parse
        - Returns empty dict if git command fails
        - Handles OSError, UnicodeDecodeError, and SyntaxError gracefully
    """
    # claude-exempt: Command Injection Risk - Using safe git command with no user input
    import_graph = {}
    
    try:
        # Get Python files from git using safe command
        python_files = check_output(["git", "ls-files", "*.py"], text=True).splitlines()
        # Limit to 50 files for performance
        python_files = python_files[:50]
        
        for filepath in python_files:
            if not os.path.exists(filepath):
                continue
                
            try:
                # Use established encoding pattern
                with open(filepath, 'r', 
                         encoding=constants["file_encoding"]["default"], 
                         errors=constants["file_encoding"]["error_handling"]) as f:
                    source = f.read()
                
                # Parse AST and extract imports
                tree = ast.parse(source)
                imports = []
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imports.extend([alias.name for alias in node.names])
                    elif isinstance(node, ast.ImportFrom):
                        module = node.module or ''
                        if module:  # Skip relative imports without module name
                            imports.append(module)
                
                if imports:
                    import_graph[filepath] = imports
                    
            except (OSError, UnicodeDecodeError, SyntaxError):
                # Graceful degradation - skip files that can't be parsed
                continue
                
    except Exception:
        # Return empty dict if git command fails
        pass
        
    return import_graph