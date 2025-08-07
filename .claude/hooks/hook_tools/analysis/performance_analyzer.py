#!/usr/bin/env python3
"""
Performance Analysis Module
Provides comprehensive performance analysis functions for Python code inspection.
"""

import ast
import re
from typing import Dict, List, Any, Union

from .ast_analyzer import calculate_complexity, _extract_call_name


# Performance analysis thresholds
COMPLEXITY_THRESHOLD = 10
MIN_NESTED_LOOP_DEPTH = 2
LARGE_RANGE_THRESHOLD = 10000
MAX_FUNCTION_LINES = 50
MAX_PARAMETERS = 5
MAX_CLASS_METHODS = 20


def detect_performance_hotspots(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """Detect performance bottlenecks and complexity issues.
    
    Args:
        tree: AST of the Python source code
        source: Raw source code as string
        
    Returns:
        List of performance hotspots with type, location, and severity info
    """
    hotspots = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            complexity = calculate_complexity(node)
            
            # High complexity function
            if complexity > COMPLEXITY_THRESHOLD:
                hotspots.append({
                    "type": "high_complexity",
                    "function": node.name,
                    "complexity": complexity,
                    "line": getattr(node, 'lineno', 0),
                    "severity": _get_complexity_severity(complexity)
                })
            
            # Nested loops detection (O(n²) or worse)
            loop_depth = _get_loop_depth(node)
            if loop_depth >= MIN_NESTED_LOOP_DEPTH:
                hotspots.append({
                    "type": "nested_loops",
                    "function": node.name,
                    "depth": loop_depth,
                    "line": getattr(node, 'lineno', 0),
                    "complexity_estimate": f"O(n^{loop_depth})",
                    "severity": _get_loop_severity(loop_depth)
                })
    
    # Detect synchronous I/O in async context
    if "async def" in source:
        sync_io_patterns = [r'\bopen\(', r'\brequests\.', r'\btime\.sleep\(']
        for pattern in sync_io_patterns:
            if re.search(pattern, source):
                hotspots.append({
                    "type": "sync_io_in_async",
                    "pattern": pattern,
                    "severity": "high"
                })
    
    return hotspots


def detect_performance_hotspots_comprehensive(filepath: str, tree: ast.AST, source: str) -> Dict[str, Any]:
    """Detect comprehensive performance hotspots in Python code.
    
    Identifies:
    1. O(n²) or worse complexity patterns in loops
    2. Synchronous I/O operations that could be async
    3. Memory-intensive operations (large list comprehensions, unnecessary copies)
    4. Cyclomatic complexity per function
    5. Potential bottlenecks (repeated file I/O, redundant calculations)
    
    Args:
        filepath: Path to the file being analyzed
        tree: AST of the Python source code
        source: Raw source code as string
        
    Returns:
        Dict with performance issues categorized by type
    """
    hotspots = {
        "nested_loops": [],
        "sync_io_operations": [],
        "memory_intensive": [],
        "high_complexity_functions": [],
        "potential_bottlenecks": [],
        "redundant_operations": [],
        "aggregate_risk_score": 0
    }
    
    # Track function definitions for per-function analysis
    function_nodes = {}
    io_operations_by_func = {}
    loop_depth_by_func = {}
    
    # First pass: collect all function definitions
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_nodes[node.name] = node
            io_operations_by_func[node.name] = []
            loop_depth_by_func[node.name] = 0
    
    # Analyze each function
    for func_name, func_node in function_nodes.items():
        _analyze_function_complexity(func_node, func_name, hotspots)
        _analyze_sync_io_operations(func_node, func_name, hotspots)
    
    # Analyze memory-intensive operations
    _analyze_memory_intensive_operations(tree, hotspots)
    
    # Detect potential bottlenecks
    _analyze_potential_bottlenecks(tree, hotspots)
    
    # Calculate aggregate risk score
    hotspots["aggregate_risk_score"] = _calculate_risk_score(hotspots)
    hotspots["risk_level"] = _get_risk_level(hotspots["aggregate_risk_score"])
    
    return hotspots


def _get_loop_depth(node: ast.AST, current_depth: int = 0) -> int:
    """Recursively calculate loop nesting depth.
    
    Args:
        node: AST node to analyze
        current_depth: Current nesting depth
        
    Returns:
        Maximum loop nesting depth found
    """
    max_depth = current_depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.For, ast.While)):
            child_depth = _get_loop_depth(child, current_depth + 1)
            max_depth = max(max_depth, child_depth)
    return max_depth


def _get_complexity_severity(complexity: int) -> str:
    """Get severity level based on cyclomatic complexity."""
    if complexity > 20:
        return "critical"
    elif complexity > 15:
        return "high"
    elif complexity > 10:
        return "medium"
    return "low"


def _get_loop_severity(depth: int) -> str:
    """Get severity level based on loop nesting depth."""
    if depth >= 4:
        return "critical"
    elif depth >= 3:
        return "high"
    elif depth >= 2:
        return "medium"
    return "low"


def _analyze_function_complexity(func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef], func_name: str, hotspots: Dict[str, List]) -> None:
    """Analyze function complexity and nested loops."""
    # Calculate per-function cyclomatic complexity
    func_complexity = 1
    max_loop_depth = 0
    has_nested_loops = False
    
    # Walk through function body
    for node in ast.walk(func_node):
        # Cyclomatic complexity
        if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
            func_complexity += 1
        elif isinstance(node, ast.BoolOp):
            func_complexity += len(node.values) - 1
        
        # Track loop nesting depth
        if isinstance(node, (ast.For, ast.While)):
            # Check if this loop contains another loop
            for child in ast.walk(node):
                if child != node and isinstance(child, (ast.For, ast.While)):
                    has_nested_loops = True
                    max_loop_depth = max(max_loop_depth, 2)
                    
                    # Check for triple nesting (O(n³) or worse)
                    for grandchild in ast.walk(child):
                        if grandchild != child and isinstance(grandchild, (ast.For, ast.While)):
                            max_loop_depth = max(max_loop_depth, 3)
                            hotspots["nested_loops"].append({
                                "function": func_name,
                                "line": node.lineno if hasattr(node, 'lineno') else 0,
                                "complexity": "O(n³) or worse",
                                "severity": "critical",
                                "description": f"Triple-nested loop detected in {func_name}"
                            })
                            break
            
            # Detect if loop contains expensive operations
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = _extract_call_name(child.func)
                    if call_name in ['sorted', 'sort', 'min', 'max', 'sum']:
                        if has_nested_loops:
                            hotspots["nested_loops"].append({
                                "function": func_name,
                                "line": child.lineno if hasattr(child, 'lineno') else 0,
                                "complexity": "O(n² log n) or worse",
                                "severity": "high",
                                "description": f"Sorting/aggregation inside nested loop in {func_name}"
                            })
    
    # Flag high-complexity functions
    if func_complexity > COMPLEXITY_THRESHOLD:
        severity = _get_complexity_severity(func_complexity)
        hotspots["high_complexity_functions"].append({
            "function": func_name,
            "complexity": func_complexity,
            "severity": severity,
            "line": func_node.lineno if hasattr(func_node, 'lineno') else 0,
            "description": f"Function {func_name} has cyclomatic complexity of {func_complexity}"
        })


def _analyze_sync_io_operations(func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef], func_name: str, hotspots: Dict[str, List]) -> None:
    """Analyze synchronous I/O operations that could be async."""
    if isinstance(func_node, ast.AsyncFunctionDef):
        return  # Skip async functions
    
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            call_name = _extract_call_name(node.func)
            
            # Check for sync I/O operations
            sync_io_indicators = [
                'open', 'read', 'write', 'requests.get', 'requests.post',
                'urlopen', 'subprocess.run', 'subprocess.call', 'check_output',
                'os.system', 'input', 'raw_input'
            ]
            
            if any(indicator in str(call_name) for indicator in sync_io_indicators):
                # Check if we're in a loop
                in_loop = _is_node_in_loop(node, func_node)
                
                severity = "high" if in_loop else "medium"
                hotspots["sync_io_operations"].append({
                    "function": func_name,
                    "line": node.lineno if hasattr(node, 'lineno') else 0,
                    "operation": call_name,
                    "severity": severity,
                    "in_loop": in_loop,
                    "description": f"Synchronous I/O '{call_name}' in {func_name}" + 
                                 (" inside loop" if in_loop else "")
                })


def _analyze_memory_intensive_operations(tree: ast.AST, hotspots: Dict[str, List]) -> None:
    """Analyze memory-intensive operations."""
    for node in ast.walk(tree):
        # Large list comprehensions
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            has_large_range = False
            has_nested = False
            
            for generator in node.generators:
                if isinstance(generator.iter, ast.Call):
                    call_name = _extract_call_name(generator.iter.func)
                    if call_name == 'range':
                        # Check if range might be large
                        if len(generator.iter.args) > 0:
                            if isinstance(generator.iter.args[0], ast.Constant):
                                try:
                                    if isinstance(generator.iter.args[0].value, (int, float)) and generator.iter.args[0].value > LARGE_RANGE_THRESHOLD:
                                        has_large_range = True
                                except (TypeError, ValueError):
                                    pass
            
            # Check for nested comprehensions
            for child in ast.walk(node):
                if child != node and isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp)):
                    has_nested = True
                    break
            
            if has_large_range or has_nested:
                severity = "high" if has_nested else "medium"
                hotspots["memory_intensive"].append({
                    "line": node.lineno if hasattr(node, 'lineno') else 0,
                    "type": "list_comprehension",
                    "severity": severity,
                    "nested": has_nested,
                    "description": "Large or nested list comprehension detected"
                })
        
        # Detect unnecessary copies
        if isinstance(node, ast.Call):
            call_name = _extract_call_name(node.func)
            if call_name in ['copy', 'deepcopy', 'list', 'dict', 'set']:
                if _is_node_in_loop(node, tree):
                    hotspots["memory_intensive"].append({
                        "line": node.lineno if hasattr(node, 'lineno') else 0,
                        "type": "copy_in_loop",
                        "operation": call_name,
                        "severity": "high",
                        "description": f"Object copying '{call_name}' inside loop"
                    })
        
        # String concatenation in loops (inefficient in Python)
        if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            if isinstance(node.target, ast.Name):
                if _is_node_in_loop(node, tree):
                    hotspots["memory_intensive"].append({
                        "line": node.lineno if hasattr(node, 'lineno') else 0,
                        "type": "string_concatenation",
                        "severity": "medium",
                        "description": "String concatenation in loop (use list.append + join instead)"
                    })


def _analyze_potential_bottlenecks(tree: ast.AST, hotspots: Dict[str, List]) -> None:
    """Analyze potential bottlenecks."""
    file_operations = {}
    repeated_calculations = {}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _extract_call_name(node.func)
            
            # Track file operations
            if call_name in ['open', 'read', 'write']:
                # Try to extract filename if it's a constant
                if len(node.args) > 0 and isinstance(node.args[0], ast.Constant):
                    filename = node.args[0].value
                    if filename not in file_operations:
                        file_operations[filename] = []
                    file_operations[filename].append(node.lineno if hasattr(node, 'lineno') else 0)
            
            # Track potentially expensive repeated calculations
            expensive_funcs = ['sorted', 'sort', 'sum', 'max', 'min', 'len', 
                             'compile', 'parse', 'load', 'loads', 'dump', 'dumps']
            if call_name in expensive_funcs:
                sig = f"{call_name}"
                if sig not in repeated_calculations:
                    repeated_calculations[sig] = []
                repeated_calculations[sig].append(node.lineno if hasattr(node, 'lineno') else 0)
    
    # Flag repeated file I/O
    for filename, lines in file_operations.items():
        if len(lines) > 2:
            hotspots["potential_bottlenecks"].append({
                "type": "repeated_file_io",
                "filename": filename,
                "occurrences": len(lines),
                "lines": lines[:5],  # Show first 5 occurrences
                "severity": "medium",
                "description": f"File '{filename}' accessed {len(lines)} times"
            })
    
    # Flag redundant calculations
    for calc, lines in repeated_calculations.items():
        if len(lines) > 3:
            hotspots["redundant_operations"].append({
                "type": "repeated_calculation",
                "operation": calc,
                "occurrences": len(lines),
                "lines": lines[:5],
                "severity": "low" if len(lines) < 5 else "medium",
                "description": f"Operation '{calc}' called {len(lines)} times - consider caching"
            })


def _is_node_in_loop(target_node: ast.AST, root_node: ast.AST) -> bool:
    """Check if a node is inside a loop."""
    for parent in ast.walk(root_node):
        if isinstance(parent, (ast.For, ast.While)):
            for child in ast.walk(parent):
                if child == target_node:
                    return True
    return False


def _calculate_risk_score(hotspots: Dict[str, List]) -> int:
    """Calculate aggregate risk score."""
    risk_score = 0
    risk_score += len(hotspots["nested_loops"]) * 10
    risk_score += len(hotspots["sync_io_operations"]) * 5
    risk_score += len(hotspots["memory_intensive"]) * 7
    risk_score += sum(1 for f in hotspots["high_complexity_functions"] if f["severity"] == "critical") * 15
    risk_score += sum(1 for f in hotspots["high_complexity_functions"] if f["severity"] == "high") * 10
    risk_score += sum(1 for f in hotspots["high_complexity_functions"] if f["severity"] == "medium") * 5
    risk_score += len(hotspots["potential_bottlenecks"]) * 3
    risk_score += len(hotspots["redundant_operations"]) * 2
    return risk_score


def _get_risk_level(risk_score: int) -> str:
    """Get risk level classification based on score."""
    if risk_score >= 50:
        return "critical"
    elif risk_score >= 30:
        return "high"
    elif risk_score >= 15:
        return "medium"
    elif risk_score > 0:
        return "low"
    else:
        return "minimal"