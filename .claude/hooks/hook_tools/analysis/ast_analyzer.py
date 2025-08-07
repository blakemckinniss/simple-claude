#!/usr/bin/env python3
"""
AST Analysis Module
Provides comprehensive AST analysis functions for Python code inspection.
"""

import ast
import re
from typing import Dict, List, Any, Optional


def extract_imports(tree: ast.AST) -> List[str]:
    """Extract import statements from AST."""
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend([alias.name for alias in node.names])
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ''
            imports.append(module)
    return imports


def extract_todos(source: str) -> List[str]:
    """Extract TODO/FIXME comments from source code."""
    return re.findall(r'#\s*(?:TODO|FIXME|HACK|XXX|NOTE)[:;]?\s*(.+)', source)


def extract_function_calls(tree: ast.AST) -> Dict[str, List[str]]:
    """Extract function call relationships from AST."""
    function_calls = {}
    
    # Find all function definitions first
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            function_name = node.name
            calls = []
            
            # Find all calls within this function
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = _extract_call_name(child.func)
                    if call_name:
                        calls.append(call_name)
            
            function_calls[function_name] = list(set(calls))[:10]  # Limit to 10 unique calls
    
    return function_calls


def _extract_call_name(func_node: ast.AST) -> Optional[str]:
    """Helper to extract function name from call node."""
    try:
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            return func_node.attr
        elif hasattr(func_node, 'id'):
            return getattr(func_node, 'id', None)
    except AttributeError:
        pass
    return None


def extract_type_hints(tree: ast.AST) -> Dict[str, Dict[str, Any]]:
    """Extract type annotations from function signatures."""
    type_hints = {}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            function_name = node.name
            hints = {'args': {}, 'return': None}
            
            # Extract argument type hints
            for arg in node.args.args:
                if arg.annotation:
                    arg_type = _annotation_to_string(arg.annotation)
                    if arg_type:
                        hints['args'][arg.arg] = arg_type
            
            # Extract return type hint
            if node.returns:
                return_type = _annotation_to_string(node.returns)
                if return_type:
                    hints['return'] = return_type
            
            # Only include if there are actual type hints
            if hints['args'] or hints['return']:
                type_hints[function_name] = hints
    
    return type_hints


def _annotation_to_string(annotation: ast.AST) -> Optional[str]:
    """Convert AST annotation node to string representation."""
    try:
        # Try using ast.unparse if available (Python 3.9+)
        if hasattr(ast, 'unparse'):
            return ast.unparse(annotation)
        # Fallback for older Python versions
        elif isinstance(annotation, ast.Name):
            return annotation.id
        elif isinstance(annotation, ast.Constant):
            return str(annotation.value)
        elif isinstance(annotation, ast.Attribute):
            # Safely handle annotation.value which might not have 'id' attribute
            try:
                return f"{annotation.value.id}.{annotation.attr}"  # type: ignore
            except AttributeError:
                # Fallback for complex expressions
                return annotation.attr
    except (AttributeError, TypeError):
        pass
    return None


def calculate_complexity(tree: ast.AST) -> int:
    """Calculate basic cyclomatic complexity."""
    complexity = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
    return complexity


# Additional utility functions for comprehensive AST analysis

def get_function_metrics(tree: ast.AST) -> Dict[str, Dict[str, Any]]:
    """Extract comprehensive metrics for all functions in the AST."""
    metrics = {}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            function_name = node.name
            metrics[function_name] = {
                'complexity': calculate_complexity(node),
                'line_number': node.lineno,
                'parameter_count': len(node.args.args),
                'has_docstring': (
                    isinstance(node.body[0], ast.Expr) and 
                    isinstance(node.body[0].value, ast.Constant) and 
                    isinstance(node.body[0].value.value, str)
                ) if node.body else False,
                'is_async': isinstance(node, ast.AsyncFunctionDef),
                'decorators': [
                    decorator.id if isinstance(decorator, ast.Name) else
                    decorator.attr if isinstance(decorator, ast.Attribute) else
                    getattr(decorator, 'id', str(decorator))
                    for decorator in node.decorator_list
                ]
            }
    
    return metrics


def extract_class_info(tree: ast.AST) -> Dict[str, Dict[str, Any]]:
    """Extract information about classes in the AST."""
    classes = {}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            class_name = node.name
            methods = [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
            
            classes[class_name] = {
                'methods': methods,
                'method_count': len(methods),
                'line_number': node.lineno,
                'base_classes': [
                    base.id if isinstance(base, ast.Name) else
                    getattr(base, 'id', str(base)) for base in node.bases
                ],
                'decorators': [
                    decorator.id if isinstance(decorator, ast.Name) else
                    getattr(decorator, 'id', str(decorator)) for decorator in node.decorator_list
                ]
            }
    
    return classes


def analyze_code_structure(tree: ast.AST, source: str) -> Dict[str, Any]:
    """Perform comprehensive structural analysis of Python code."""
    return {
        'imports': extract_imports(tree),
        'todos': extract_todos(source),
        'function_calls': extract_function_calls(tree),
        'type_hints': extract_type_hints(tree),
        'function_metrics': get_function_metrics(tree),
        'class_info': extract_class_info(tree),
        'total_complexity': sum(
            calculate_complexity(node) for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        )
    }