#!/usr/bin/env python3
import os
import sys
import ast
import json
import requests
import re
import shutil
from pathlib import Path
from subprocess import check_output
from typing import List, Tuple, Dict, Any, Optional
from collections import defaultdict
import time

# Import the simplified logger, state manager, and memory manager
sys.path.insert(0, str(Path(__file__).parent.parent))
from hook_logger import logger
from hook_tools.state_manager import state_manager
from hook_tools.memory_manager import memory_manager, MemoryType

# Tool output cache for synthesis
TOOL_OUTPUT_CACHE = {}
CACHE_TTL = 300  # 5 minutes

# Load constants from JSON file
def load_constants() -> Dict[str, Any]:
    """Load configuration constants from JSON file."""
    constants_path = Path(__file__).parent.parent.parent / "json" / "constants.json"
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
    print(f"Error loading constants: {e}", file=sys.stderr)
    sys.exit(2)  # Block execution if constants cannot be loaded

# Load environment variables from .env file
def load_env():
    env_path = Path(__file__).parent.parent.parent.parent / CONSTANTS["file_paths"]["env_file_relative_path"]
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value

load_env()

# --- Semantic Summary Logic ---

SUMMARY_OUTPUT = CONSTANTS["file_paths"]["summary_output"]

def extract_imports(tree):
    """Extract import statements from AST."""
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend([alias.name for alias in node.names])
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ''
            imports.append(module)
    return imports

def extract_todos(source):
    """Extract TODO/FIXME comments from source code."""
    return re.findall(r'#\s*(?:TODO|FIXME|HACK|XXX|NOTE)[:;]?\s*(.+)', source)

def extract_function_calls(tree):
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

def _extract_call_name(func_node):
    """Helper to extract function name from call node."""
    try:
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            return func_node.attr
        elif hasattr(func_node, 'id'):
            return func_node.id
    except:
        pass

def detect_performance_hotspots(tree, source):
    """Detect performance bottlenecks and complexity issues."""
    hotspots = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            complexity = calculate_complexity(node)
            
            # High complexity function
            if complexity > 10:
                hotspots.append({
                    "type": "high_complexity",
                    "function": node.name,
                    "complexity": complexity,
                    "line": node.lineno
                })
            
            # Nested loops detection (O(n²) or worse)
            loop_depth = _get_loop_depth(node)
            if loop_depth >= 2:
                hotspots.append({
                    "type": "nested_loops",
                    "function": node.name,
                    "depth": loop_depth,
                    "line": node.lineno,
                    "complexity_estimate": f"O(n^{loop_depth})"
                })
    
    # Detect synchronous I/O in async context
    if "async def" in source:
        sync_io_patterns = [r'\bopen\(', r'\brequests\.', r'\btime\.sleep\(']
        for pattern in sync_io_patterns:
            if re.search(pattern, source):
                hotspots.append({
                    "type": "sync_io_in_async",
                    "pattern": pattern
                })
    
    return hotspots

def _get_loop_depth(node, current_depth=0):
    """Recursively calculate loop nesting depth."""
    max_depth = current_depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.For, ast.While)):
            child_depth = _get_loop_depth(child, current_depth + 1)
            max_depth = max(max_depth, child_depth)
    return max_depth

def calculate_context_depth(prompt):
    """Dynamically calculate context depth based on prompt complexity."""
    prompt_lower = prompt.lower()
    
    # Deep analysis keywords
    if any(word in prompt_lower for word in ['debug', 'deep dive', 'analyze', 'investigate', 'trace', 'why']):
        return {"top_k": 50, "include_body": True, "depth": "deep"}
    
    # Refactoring keywords
    elif any(word in prompt_lower for word in ['refactor', 'improve', 'optimize', 'clean', 'restructure']):
        return {"top_k": 30, "include_body": True, "depth": "refactor", "focus": "complexity"}
    
    # Overview keywords
    elif any(word in prompt_lower for word in ['summary', 'overview', 'quick', 'brief', 'what']):
        return {"top_k": 10, "include_body": False, "depth": "overview"}
    
    # Performance keywords
    elif any(word in prompt_lower for word in ['performance', 'slow', 'bottleneck', 'speed']):
        return {"top_k": 25, "include_body": True, "depth": "performance", "focus": "hotspots"}
    
    # Default moderate depth
    return {"top_k": 20, "include_body": False, "depth": "moderate"}

def detect_code_quality_issues(filepath, content):
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

def aggregate_cross_file_patterns(verbose_outline):
    """Aggregate patterns across multiple files for project-wide insights."""
    patterns = {
        "repeated_patterns": defaultdict(int),
        "naming_inconsistencies": [],
        "architectural_patterns": [],
        "common_issues": defaultdict(list)
    }
    
    # Analyze patterns across files
    for filepath, summary in verbose_outline.items():
        if 'imports' in summary:
            # Track import patterns
            for imp in summary['imports']:
                patterns['repeated_patterns'][imp] += 1
        
        if 'todos' in summary:
            # Aggregate TODOs by category
            for todo in summary['todos']:
                category = 'general'
                if 'refactor' in todo.lower():
                    category = 'refactor'
                elif 'fix' in todo.lower() or 'bug' in todo.lower():
                    category = 'bug'
                elif 'optimize' in todo.lower() or 'performance' in todo.lower():
                    category = 'performance'
                
                patterns['common_issues'][category].append({'file': filepath, 'todo': todo})
    
    # Identify architectural patterns
    import_strs = str(patterns['repeated_patterns'])
    if 'flask' in import_strs.lower():
        patterns['architectural_patterns'].append('Flask Web Framework')
    if 'django' in import_strs.lower():
        patterns['architectural_patterns'].append('Django Web Framework')
    if 'fastapi' in import_strs.lower():
        patterns['architectural_patterns'].append('FastAPI')
    
    return dict(patterns)

def extract_test_metrics(test_files):
    """Extract test coverage and quality metrics."""
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

def synthesize_tool_outputs(cache_key=None, output=None):
    """Cache and synthesize tool outputs to reduce redundancy."""
    global TOOL_OUTPUT_CACHE
    current_time = time.time()
    
    # Clean expired cache entries
    TOOL_OUTPUT_CACHE = {k: v for k, v in TOOL_OUTPUT_CACHE.items() 
                        if current_time - v['timestamp'] < CACHE_TTL}
    
    if cache_key and output:
        # Store output in cache
        TOOL_OUTPUT_CACHE[cache_key] = {
            'output': output,
            'timestamp': current_time
        }
    elif cache_key:
        # Retrieve from cache
        cached = TOOL_OUTPUT_CACHE.get(cache_key)
        if cached:
            return cached['output']
    
    return None

def extract_type_hints(tree):
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

def _annotation_to_string(annotation):
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
    except:
        pass
    return None

def calculate_complexity(tree):
    """Calculate basic cyclomatic complexity."""
    complexity = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
    return complexity

def detect_performance_hotspots_old(filepath: str, tree: ast.AST, source: str) -> Dict[str, Any]:
    """Detect performance hotspots in Python code.
    
    Identifies:
    1. O(n²) or worse complexity patterns in loops
    2. Synchronous I/O operations that could be async
    3. Memory-intensive operations (large list comprehensions, unnecessary copies)
    4. Cyclomatic complexity per function
    5. Potential bottlenecks (repeated file I/O, redundant calculations)
    
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
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            function_nodes[node.name] = node
            io_operations_by_func[node.name] = []
            loop_depth_by_func[node.name] = 0
    
    # Analyze each function
    for func_name, func_node in function_nodes.items():
        # Calculate per-function cyclomatic complexity
        func_complexity = 1
        loop_depth = 0
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
        if func_complexity > 10:
            severity = "critical" if func_complexity > 20 else "high" if func_complexity > 15 else "medium"
            hotspots["high_complexity_functions"].append({
                "function": func_name,
                "complexity": func_complexity,
                "severity": severity,
                "line": func_node.lineno if hasattr(func_node, 'lineno') else 0,
                "description": f"Function {func_name} has cyclomatic complexity of {func_complexity}"
            })
        
        # Detect synchronous I/O that could be async
        if not isinstance(func_node, ast.AsyncFunctionDef):
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
                        in_loop = False
                        for parent in ast.walk(func_node):
                            if isinstance(parent, (ast.For, ast.While)):
                                for child in ast.walk(parent):
                                    if child == node:
                                        in_loop = True
                                        break
                        
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
    
    # Detect memory-intensive operations
    for node in ast.walk(tree):
        # Large list comprehensions
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            # Check if comprehension is over a large range or has nested loops
            has_large_range = False
            has_nested = False
            
            for generator in node.generators:
                if isinstance(generator.iter, ast.Call):
                    call_name = _extract_call_name(generator.iter.func)
                    if call_name == 'range':
                        # Check if range might be large
                        if len(generator.iter.args) > 0:
                            if isinstance(generator.iter.args[0], ast.Constant):
                                # Safely check if the constant is a numeric value > 10000
                                try:
                                    if isinstance(generator.iter.args[0].value, (int, float)) and generator.iter.args[0].value > 10000:
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
                # Check if this is inside a loop
                in_loop = False
                for parent in ast.walk(tree):
                    if isinstance(parent, (ast.For, ast.While)):
                        for child in ast.walk(parent):
                            if child == node:
                                in_loop = True
                                break
                
                if in_loop:
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
                # Check if this is string concatenation in a loop
                for parent in ast.walk(tree):
                    if isinstance(parent, (ast.For, ast.While)):
                        for child in ast.walk(parent):
                            if child == node:
                                hotspots["memory_intensive"].append({
                                    "line": node.lineno if hasattr(node, 'lineno') else 0,
                                    "type": "string_concatenation",
                                    "severity": "medium",
                                    "description": "String concatenation in loop (use list.append + join instead)"
                                })
                                break
    
    # Detect potential bottlenecks
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
                # Create a signature for the call
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
    
    # Calculate aggregate risk score
    risk_score = 0
    risk_score += len(hotspots["nested_loops"]) * 10
    risk_score += len(hotspots["sync_io_operations"]) * 5
    risk_score += len(hotspots["memory_intensive"]) * 7
    risk_score += sum(1 for f in hotspots["high_complexity_functions"] if f["severity"] == "critical") * 15
    risk_score += sum(1 for f in hotspots["high_complexity_functions"] if f["severity"] == "high") * 10
    risk_score += sum(1 for f in hotspots["high_complexity_functions"] if f["severity"] == "medium") * 5
    risk_score += len(hotspots["potential_bottlenecks"]) * 3
    risk_score += len(hotspots["redundant_operations"]) * 2
    
    hotspots["aggregate_risk_score"] = risk_score
    
    # Add risk level classification
    if risk_score >= 50:
        hotspots["risk_level"] = "critical"
    elif risk_score >= 30:
        hotspots["risk_level"] = "high"
    elif risk_score >= 15:
        hotspots["risk_level"] = "medium"
    elif risk_score > 0:
        hotspots["risk_level"] = "low"
    else:
        hotspots["risk_level"] = "minimal"
    
    return hotspots

def summarize_python_file(filepath):
    try:
        with open(filepath, 'r', encoding=CONSTANTS["file_encoding"]["default"], 
                  errors=CONSTANTS["file_encoding"]["error_handling"]) as f:
            source = f.read()
        tree = ast.parse(source)
    except Exception:
        return {"description": CONSTANTS["file_summary"]["unreadable_python"]}

    summary = {"functions": [], "classes": [], "docstring": "", "imports": [], "todos": [], "complexity": 0, "function_calls": {}, "type_hints": {}}
    
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

def summarize_text_file(filepath):
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

def summarize_json_file(filepath):
    try:
        with open(filepath, 'r', encoding=CONSTANTS["file_encoding"]["default"]) as f:
            data = json.load(f)
        if isinstance(data, dict):
            max_keys = CONSTANTS["text_limits"]["max_json_keys_display"]
            return {"description": CONSTANTS["file_summary"]["json_config"], 
                   "keys": list(data.keys())[:max_keys]}
        return {"description": CONSTANTS["file_summary"]["json_non_dict"]}
    except:
        return {"description": CONSTANTS["file_summary"]["unreadable_json"]}

def summarize_file(filepath):
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

def extract_keywords(prompt: str) -> List[str]:
    """Extract meaningful keywords from user prompt."""
    # Remove common words and extract meaningful tokens
    stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 
                  'of', 'with', 'by', 'from', 'up', 'about', 'into', 'through', 'during',
                  'how', 'what', 'where', 'when', 'why', 'can', 'could', 'should', 'would'}
    words = re.findall(r'\b\w+\b', prompt.lower())
    keywords = [w for w in words if w not in stop_words and len(w) > 2]
    return keywords

def score_file_relevance(prompt: str, filepath: str, summary: dict) -> float:
    """Score file relevance to prompt using keyword matching."""
    prompt_tokens = set(extract_keywords(prompt))
    
    # Extract tokens from file path and summary
    file_tokens = set(re.findall(r'\b\w+\b', filepath.lower()))
    file_tokens.update(re.findall(r'\b\w+\b', str(summary).lower()))
    
    # Calculate Jaccard similarity
    intersection = prompt_tokens & file_tokens
    union = prompt_tokens | file_tokens
    return len(intersection) / len(union) if union else 0.0

def filter_relevant_files(prompt: str, outline: dict, top_k: int = 20) -> dict:
    """Filter outline to only include files most relevant to the prompt."""
    scored_files = [(path, summary, score_file_relevance(prompt, path, summary)) 
                    for path, summary in outline.items()]
    scored_files.sort(key=lambda x: x[2], reverse=True)
    return {path: summary for path, summary, _ in scored_files[:top_k]}

def generate_outline(file_list):
    outline = {}
    # Performance: Process files in batches and limit total
    max_files = min(len(file_list), 500)
    
    for path in file_list[:max_files]:
        if os.path.exists(path):
            try:
                outline[path] = summarize_file(path)
            except Exception as e:
                # Log error but continue processing
                outline[path] = {"description": f"Error processing file: {e}"}
    return outline

def get_git_context(keywords: Optional[List[str]] = None) -> dict:
    """Get recent git activity context."""
    try:
        context = {
            "working_on": "",
            "recent_commits": [],
            "recently_changed": [],
            "current_branch": ""
        }
        
        # Get current branch
        try:
            context["current_branch"] = check_output("git branch --show-current", shell=True, text=True).strip()
        except:
            pass
            
        # Get working directory status
        try:
            context["working_on"] = check_output("git status --short", shell=True, text=True).strip()
        except:
            pass
        
        # Get recent commits
        try:
            commits = check_output("git log --oneline -10", shell=True, text=True).splitlines()
            if keywords:
                # Filter commits by keywords
                context["recent_commits"] = [c for c in commits 
                                            if any(kw.lower() in c.lower() for kw in keywords)][:5]
            else:
                context["recent_commits"] = commits[:5]
        except:
            pass
        
        # Get recently changed files
        try:
            changed = check_output("git diff --name-only HEAD~5 2>/dev/null || git ls-files", 
                                 shell=True, text=True).splitlines()
            if keywords:
                context["recently_changed"] = [f for f in changed 
                                              if any(kw.lower() in f.lower() for kw in keywords)][:10]
            else:
                context["recently_changed"] = changed[:10]
        except:
            pass
            
        return context
    except:
        return {"working_on": "", "recent_commits": [], "recently_changed": [], "current_branch": ""}

def get_error_context() -> dict:
    """Extract recent errors from logs and terminal output."""
    context = {"recent_errors": [], "warnings": []}
    
    # Check common log locations
    log_patterns = ['*.log', '*.err', 'error.txt', 'debug.log']
    
    for pattern in log_patterns:
        try:
            # Find recent log files
            files = check_output(f"find . -name '{pattern}' -mtime -1 2>/dev/null | head -5", 
                               shell=True, text=True).splitlines()
            
            for log_file in files:
                if os.path.exists(log_file):
                    try:
                        with open(log_file, 'r', errors='ignore') as f:
                            # Read last 100 lines
                            lines = f.readlines()[-100:]
                            
                            # Extract errors
                            for line in lines:
                                if 'ERROR' in line or 'Exception' in line or 'Traceback' in line:
                                    context["recent_errors"].append(line.strip()[:200])  # Truncate long lines
                                elif 'WARNING' in line or 'WARN' in line:
                                    context["warnings"].append(line.strip()[:200])
                                    
                            # Limit to most recent
                            context["recent_errors"] = context["recent_errors"][-5:]
                            context["warnings"] = context["warnings"][-3:]
                    except:
                        pass
        except:
            pass
    
    return context

def get_project_config() -> dict:
    """Extract project configuration from various config files."""
    context = {
        "dependencies": [],
        "scripts": {},
        "make_targets": [],
        "config_files": []
    }
    
    project_root = Path(os.getcwd())
    
    # Check requirements.txt
    requirements_path = project_root / "requirements.txt"
    if requirements_path.exists():
        try:
            with open(requirements_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:20]  # Limit to first 20 dependencies
                deps = [line.strip().split('==')[0].split('>=')[0].split('~=')[0] 
                       for line in lines if line.strip() and not line.startswith('#')]
                context["dependencies"].extend(deps)
                context["config_files"].append("requirements.txt")
        except Exception:
            pass
    
    # Check package.json
    package_json_path = project_root / "package.json"
    if package_json_path.exists():
        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if "dependencies" in data:
                    context["dependencies"].extend(list(data["dependencies"].keys())[:10])
                if "devDependencies" in data:
                    context["dependencies"].extend(list(data["devDependencies"].keys())[:10])
                if "scripts" in data:
                    context["scripts"].update(data["scripts"])
                context["config_files"].append("package.json")
        except Exception:
            pass
    
    # Check pyproject.toml
    pyproject_path = project_root / "pyproject.toml"
    if pyproject_path.exists():
        try:
            with open(pyproject_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Simple regex-based extraction for dependencies
                deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if deps_match:
                    deps_str = deps_match.group(1)
                    deps = re.findall(r'["\']([^"\'>=<]+)["\']', deps_str)
                    context["dependencies"].extend(deps[:10])
                context["config_files"].append("pyproject.toml")
        except Exception:
            pass
    
    # Check setup.py
    setup_py_path = project_root / "setup.py"
    if setup_py_path.exists():
        try:
            with open(setup_py_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()[:2000]  # Read first 2000 chars to avoid large files
                # Extract install_requires dependencies
                deps_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if deps_match:
                    deps_str = deps_match.group(1)
                    deps = re.findall(r'["\']([^"\'>=<]+)["\']', deps_str)
                    context["dependencies"].extend(deps[:10])
                context["config_files"].append("setup.py")
        except Exception:
            pass
    
    # Check Makefile
    makefile_path = project_root / "Makefile"
    if makefile_path.exists():
        try:
            with open(makefile_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:50]  # Limit to first 50 lines
                targets = []
                for line in lines:
                    # Find make targets (lines that start without whitespace and contain :)
                    if not line.startswith('\t') and ':' in line and not line.startswith('#'):
                        target = line.split(':')[0].strip()
                        if target and not target.startswith('.'):  # Skip special targets
                            targets.append(target)
                context["make_targets"] = targets[:10]  # Limit to 10 targets
                if targets:
                    context["config_files"].append("Makefile")
        except Exception:
            pass
    
    # Remove duplicates and limit total dependencies
    context["dependencies"] = list(dict.fromkeys(context["dependencies"]))[:15]
    
    return context

def get_project_documentation() -> dict:
    """Extract project documentation context."""
    context = {"readme_files": [], "doc_dirs": [], "key_docs": []}
    
    # Look for README files
    readme_patterns = ['README*', 'readme*', 'Readme*']
    for pattern in readme_patterns:
        try:
            files = check_output(f"find . -maxdepth 2 -name '{pattern}' 2>/dev/null | head -3", 
                               shell=True, text=True).splitlines()
            context["readme_files"].extend(files)
        except:
            pass
    
    # Look for documentation directories
    doc_dirs = ['docs', 'doc', 'documentation', 'wiki', 'guides']
    for doc_dir in doc_dirs:
        if os.path.exists(doc_dir) and os.path.isdir(doc_dir):
            context["doc_dirs"].append(doc_dir)
    
    # Look for key documentation files
    key_docs = ['CHANGELOG.md', 'CONTRIBUTING.md', 'LICENSE', 'API.md', 'USAGE.md']
    for doc_file in key_docs:
        if os.path.exists(doc_file):
            context["key_docs"].append(doc_file)
    
    return context

def get_test_context() -> dict:
    """Find test files and identify testing frameworks (pytest, jest)."""
    context = {"test_files": [], "frameworks": [], "coverage_info": {}}
    
    try:
        # Common test patterns
        test_patterns = ['*test*.py', 'test_*.py', '*_test.py', 'tests/*.py', 
                        '*.test.js', 'test/*.js', '*.spec.js', 'spec/*.js']
        
        for pattern in test_patterns:
            try:
                # Find test files
                files = check_output(f"find . -name '{pattern}' -type f 2>/dev/null | head -20", 
                                   shell=True, text=True).splitlines()
                context["test_files"].extend(files)
            except:
                pass
        
        # Remove duplicates and limit
        context["test_files"] = list(set(context["test_files"]))[:15]
        
        # Detect testing frameworks
        framework_indicators = {
            'pytest': ['pytest.ini', 'pyproject.toml', 'conftest.py', 'pytest.cfg'],
            'unittest': ['unittest', 'TestCase'],
            'jest': ['jest.config.js', 'package.json'],
            'mocha': ['mocha.opts', '.mocharc'],
            'vitest': ['vitest.config.js', 'vite.config.js']
        }
        
        for framework, indicators in framework_indicators.items():
            for indicator in indicators:
                if os.path.exists(indicator):
                    context["frameworks"].append(framework)
                    break
                # Also check in test file content
                for test_file in context["test_files"][:5]:  # Check first 5 files only
                    try:
                        if os.path.exists(test_file):
                            with open(test_file, 'r', errors='ignore') as f:
                                content = f.read(1000)  # Read first 1000 chars
                                if indicator in content:
                                    context["frameworks"].append(framework)
                                    break
                    except:
                        pass
        
        # Remove duplicates
        context["frameworks"] = list(set(context["frameworks"]))
        
        # Check for coverage configuration
        coverage_files = ['.coveragerc', 'coverage.xml', '.coverage', 'coverage.json']
        for cov_file in coverage_files:
            if os.path.exists(cov_file):
                context["coverage_info"][cov_file] = "present"
        
        # Get basic test statistics
        context["test_count"] = len(context["test_files"])
        context["framework_count"] = len(context["frameworks"])
        
    except Exception:
        pass
    
    return context

def get_environment_context() -> dict:
    """Get Python version, platform, virtual env, and installed packages."""
    context = {
        "python_version": "",
        "platform": "",
        "virtual_env": "",
        "installed_packages": [],
        "package_managers": []
    }
    
    try:
        # Python version
        context["python_version"] = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        
        # Platform information
        import platform
        context["platform"] = f"{platform.system()} {platform.machine()}"
        
        # Virtual environment detection
        if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
            context["virtual_env"] = "active"
            if 'VIRTUAL_ENV' in os.environ:
                context["virtual_env"] = os.path.basename(os.environ['VIRTUAL_ENV'])
        else:
            context["virtual_env"] = "none"
        
        # Detect package managers
        if os.path.exists('requirements.txt'):
            context["package_managers"].append("pip")
        if os.path.exists('Pipfile'):
            context["package_managers"].append("pipenv")
        if os.path.exists('pyproject.toml'):
            context["package_managers"].append("poetry/pip")
        if os.path.exists('package.json'):
            context["package_managers"].append("npm/yarn")
        if os.path.exists('yarn.lock'):
            context["package_managers"].append("yarn")
        if os.path.exists('package-lock.json'):
            context["package_managers"].append("npm")
        
        # Get key installed packages (limit to avoid overwhelming output)
        try:
            # Try pip list first (most common)
            if shutil.which('pip'):
                pip_output = check_output('pip list --format=freeze 2>/dev/null', 
                                        shell=True, text=True)
                lines = pip_output.splitlines()[:20]  # Limit to 20 packages
                context["installed_packages"] = [line.split('==')[0] if '==' in line else line 
                                               for line in lines if line.strip()]
        except:
            # Fallback to checking common packages
            common_packages = ['flask', 'django', 'fastapi', 'requests', 'numpy', 
                             'pandas', 'pytest', 'black', 'mypy', 'ruff']
            for pkg in common_packages:
                try:
                    __import__(pkg)
                    context["installed_packages"].append(pkg)
                except ImportError:
                    pass
        
        # Limit packages list
        context["installed_packages"] = context["installed_packages"][:15]
        
    except Exception:
        pass
    
    return context

def calculate_file_metrics(filepath: str, source: str) -> dict:
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

def bootstrap_summary(json_path=SUMMARY_OUTPUT):
    import time
    if os.path.exists(json_path):
        try:
            # Check if cache is recent (within 1 hour)
            cache_age = time.time() - os.path.getmtime(json_path)
            if cache_age < 3600:  # 1 hour cache
                with open(json_path, 'r') as f:
                    return json.load(f)
        except:
            pass

    try:
        file_list = check_output(CONSTANTS["git_commands"]["list_files"], text=True).splitlines()
        # Performance: Limit to 500 files max
        file_list = file_list[:500]
    except Exception as e:
        logger.log_error(f"Cannot list files from git: {e}")
        return {}

    outline = generate_outline(file_list)
    try:
        os.makedirs(os.path.dirname(json_path), exist_ok=True)
        with open(json_path, 'w', encoding=CONSTANTS["file_encoding"]["default"]) as f:
            json.dump(outline, f, indent=CONSTANTS["json_formatting"]["indent"])
    except Exception as e:
        logger.log_error(f"Failed to write summary cache: {e}")

    return outline

# --- Agent Information Extraction ---

def get_agent_info(agents_dir: str) -> List[Tuple[str, str, str]]:
    """Read agent files and extract name, description, and model from YAML frontmatter.
    
    Returns:
        List of (name, description, model) tuples
    """
    agents = []
    if not os.path.exists(agents_dir):
        return agents
    
    for filename in os.listdir(agents_dir):
        if filename.endswith(CONSTANTS["file_extensions"]["markdown"]):
            filepath = os.path.join(agents_dir, filename)
            try:
                with open(filepath, 'r', encoding=CONSTANTS["file_encoding"]["default"]) as f:
                    content = f.read()
                    
                # Extract YAML frontmatter
                delimiter = CONSTANTS["yaml_frontmatter"]["delimiter"]
                if content.startswith(delimiter):
                    end_index = content.find(delimiter, 3)
                    if end_index != -1:
                        frontmatter = content[3:end_index].strip()
                        
                        # Parse YAML-like frontmatter manually
                        name = ""
                        description = ""
                        model = ""
                        
                        yaml_keys = CONSTANTS["yaml_frontmatter"]
                        for line in frontmatter.split('\n'):
                            line = line.strip()
                            if line.startswith(yaml_keys["name_key"]):
                                name = line.split(':', 1)[1].strip()
                            elif line.startswith(yaml_keys["description_key"]):
                                description = line.split(':', 1)[1].strip()
                            elif line.startswith(yaml_keys["model_key"]):
                                model = line.split(':', 1)[1].strip()
                        
                        if name and description:
                            agents.append((name, description, model))
            except Exception:
                continue
    
    return agents

# --- Dependency Graph Builder ---

def build_import_graph() -> Dict[str, List[str]]:
    """Build a dependency graph by analyzing Python files and extracting their imports.
    
    Uses git ls-files to discover Python files in the repository, parses their AST
    to extract import statements, and returns a mapping of file paths to their imports.
    Limited to 50 files for performance.
    
    Returns:
        Dict mapping file paths to lists of imported module names
    """
    import_graph = {}
    
    try:
        # Get Python files from git using established pattern
        python_files = check_output("git ls-files *.py", shell=True, text=True).splitlines()
        # Limit to 50 files for performance
        python_files = python_files[:50]
        
        for filepath in python_files:
            if not os.path.exists(filepath):
                continue
                
            try:
                # Use established encoding pattern
                with open(filepath, 'r', 
                         encoding=CONSTANTS["file_encoding"]["default"], 
                         errors=CONSTANTS["file_encoding"]["error_handling"]) as f:
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

# --- Gemini API Integration ---

OPENROUTER_API_KEY = os.getenv(CONSTANTS["environment_variables"]["openrouter_api_key"])
GEMINI_MODEL = CONSTANTS["api"]["gemini_model"]
ENDPOINT = CONSTANTS["api"]["endpoint"]

def format_outline(outline):
    lines = []
    for file, info in outline.items():
        lines.append(f"## {file}")
        for key, value in info.items():
            if isinstance(value, list):
                lines.append(f"- {key}:")
                lines.extend([f"  - {v}" for v in value])
            else:
                lines.append(f"- {key}: {value}")
        lines.append("")
    return "\n".join(lines)

def call_gemini(user_prompt, verbose_outline, mcp_servers=None, agents=None, session_id=None, git_context=None, error_context=None, project_config=None, project_docs=None, test_context=None, env_context=None, import_graph=None, cross_file_patterns=None, test_metrics=None, context_depth=None, memory_context=None):
    if not OPENROUTER_API_KEY:
        logger.log_error(f"Missing {CONSTANTS['environment_variables']['openrouter_api_key']}")
        return "Error: API key not configured"

    outline_text = format_outline(verbose_outline)
    
    # Add performance and quality insights
    quality_insights = ""
    if cross_file_patterns:
        quality_insights += "\n\n## Project-Wide Patterns:\n"
        if cross_file_patterns.get('architectural_patterns'):
            quality_insights += f"Architecture: {', '.join(cross_file_patterns['architectural_patterns'])}\n"
        if cross_file_patterns.get('common_issues'):
            quality_insights += f"Common Issues: {list(cross_file_patterns['common_issues'].keys())}\n"
        if cross_file_patterns.get('repeated_patterns'):
            # Show top 5 most imported modules
            top_imports = sorted(cross_file_patterns['repeated_patterns'].items(), key=lambda x: x[1], reverse=True)[:5]
            quality_insights += f"Top Imports: {', '.join([f'{imp}({count})' for imp, count in top_imports])}\n"
    
    if test_metrics:
        quality_insights += f"\n## Test Metrics:\n"
        quality_insights += f"Test Count: {test_metrics['test_count']}\n"
        quality_insights += f"Assertion Density: {test_metrics['assertion_density']:.2f}\n"
        quality_insights += f"Mock Usage: {test_metrics['mock_usage']}\n"
    
    if context_depth:
        quality_insights += f"\n## Context Configuration:\n"
        quality_insights += f"Depth: {context_depth['depth']}\n"
        quality_insights += f"Files Analyzed: {context_depth['top_k']}\n"
        if context_depth.get('focus'):
            quality_insights += f"Focus: {context_depth['focus']}\n"
    
    # Format git context if provided
    git_text = ""
    if git_context:
        git_text = f"""\n## Git Context
- Current Branch: {git_context.get('current_branch', 'unknown')}
- Working On: {git_context.get('working_on', 'No changes') or 'No changes'}
- Recent Commits: {'; '.join(git_context.get('recent_commits', [])[:3]) or 'None'}
- Recently Changed: {', '.join(git_context.get('recently_changed', [])[:5]) or 'None'}\n"""
    
    # Format error context if provided
    error_text = ""
    if error_context and (error_context.get('recent_errors') or error_context.get('warnings')):
        error_text = f"""\n## Runtime Context
- Recent Errors: {'; '.join(error_context.get('recent_errors', [])[:3]) or 'None'}
- Warnings: {'; '.join(error_context.get('warnings', [])[:2]) or 'None'}\n"""
    
    # Format project config context
    config_text = ""
    if project_config and project_config.get('config_files'):
        config_text = f"""\n## Project Configuration
- Config Files: {', '.join(project_config.get('config_files', [])[:5])}
- Dependencies: {', '.join(project_config.get('dependencies', [])[:5]) or 'None'}\n"""
    
    # Format documentation context
    docs_text = ""
    if project_docs and (project_docs.get('readme_files') or project_docs.get('doc_dirs')):
        docs_text = f"""\n## Project Documentation
- README Files: {', '.join(project_docs.get('readme_files', [])[:3]) or 'None'}
- Doc Directories: {', '.join(project_docs.get('doc_dirs', [])[:3]) or 'None'}
- Key Docs: {', '.join(project_docs.get('key_docs', [])[:3]) or 'None'}\n"""
    
    # Format test context
    test_text = ""
    if test_context and (test_context.get('test_dirs') or test_context.get('test_files')):
        test_text = f"""\n## Testing Context
- Test Directories: {', '.join(test_context.get('test_dirs', [])[:3]) or 'None'}
- Test Files: {', '.join([os.path.basename(f) for f in test_context.get('test_files', [])][:3]) or 'None'}
- Frameworks: {', '.join(test_context.get('test_frameworks', [])[:3]) or 'None'}\n"""
    
    # Format environment context
    env_text = ""
    if env_context and (env_context.get('env_files') or env_context.get('containers') or env_context.get('ci_cd')):
        env_text = f"""\n## Environment & Deployment
- Environment Files: {', '.join(env_context.get('env_files', [])[:3]) or 'None'}
- Containers: {', '.join(env_context.get('containers', [])[:3]) or 'None'}
- CI/CD: {', '.join([os.path.basename(f) for f in env_context.get('ci_cd', [])][:3]) or 'None'}\n"""
    
    # Format import graph context (only for smaller projects)
    import_text = ""
    if import_graph and import_graph.get('import_map'):
        external_deps = ', '.join(import_graph.get('external_deps', [])[:5]) or 'None'
        import_text = f"""\n## Import Dependencies
- External Dependencies: {external_deps}
- Local Modules: {len(import_graph.get('import_map', {}))} files analyzed\n"""
    
    # Format MCP server information if provided
    mcp_text = ""
    if mcp_servers:
        mcp_text = CONSTANTS["gemini_prompt_template"]["mcp_tools_header"]
        for server in mcp_servers:
            mcp_text += f"- {server['name']}: {server['description']}\n"
        mcp_text += "\n"
    
    # Format agent information if provided
    agent_text = ""
    if agents:
        agent_text = CONSTANTS["gemini_prompt_template"]["agents_header"]
        for name, description, model in agents:
            agent_text += f"- {name} ({model}): {description}\n"
        agent_text += "\n"
    
    # Add ZEN continuation prompt based on session state
    zen_prompt = ""
    if session_id:
        current_continuation = get_current_continuation_id(session_id)
        if current_continuation:
            # Active continuation - remind to use existing thread
            zen_prompt = f"\n\n**CRITICAL CONTEXT - ACTIVE ZEN THREAD**: {current_continuation}\nThe user has an active ZEN conversation thread. When using mcp__zen tools, ALWAYS include continuation_id: '{current_continuation}' to maintain conversation continuity and context across tool calls.\n"
        else:
            # No continuation - strong initiation for first message
            zen_prompt = "\n\n**CRITICAL: Start with ZEN Analysis**\nFor complex tasks, ALWAYS begin by using mcp__zen tools (thinkdeep, debug, analyze, etc.) for systematic investigation. These tools provide enhanced reasoning capabilities and should be your first choice for any non-trivial work. The continuation_id from the first ZEN call will be tracked for this session.\n"
    
    # Format memory context if provided
    memory_text = ""
    if memory_context:
        memory_text = f"\n{memory_context}"
    
    template = CONSTANTS["gemini_prompt_template"]
    full_text = f"""{template["user_prompt_header"]}
{user_prompt}
{zen_prompt}
{template["outline_header"]}
{outline_text}{quality_insights}{git_text}{error_text}{config_text}{docs_text}{test_text}{env_text}{import_text}{memory_text}
{mcp_text}{agent_text}{template["analysis_request"]}

{template["relevant_files_section"]}

{template["mcp_tools_section"]}

{template["agents_section"]}

{template["format_header"]}
{template["relevant_files_format"]}

{template["mcp_tools_format"]}

{template["agents_format"]}
"""

    payload = {
        "model": GEMINI_MODEL,
        "messages": [{
            "role": "user",
            "content": [{"type": "text", "text": full_text}]
        }]
    }

    headers = {
        "Content-Type": CONSTANTS["http_headers"]["content_type"],
        "Authorization": f"{CONSTANTS['http_headers']['authorization_prefix']}{OPENROUTER_API_KEY}"
    }

    # Log the Gemini API request
    logger.log_gemini_request(user_prompt, payload)

    try:
        # Add timeout for API calls
        response = requests.post(ENDPOINT, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        response_data = response.json()
        
        # Validate response structure
        if "choices" not in response_data or not response_data["choices"]:
            raise ValueError("Invalid API response structure")
        
        content = response_data["choices"][0]["message"]["content"].strip()
        
        # Log successful response
        logger.log_gemini_response(response_data, success=True)
        return content
        
    except requests.exceptions.Timeout:
        logger.log_gemini_response({"error": "Request timeout"}, success=False)
        raise
    except Exception as e:
        # Log failed response
        logger.log_gemini_response({"error": str(e)}, success=False)
        raise

# --- Continuation Management Helpers ---

def get_current_continuation_id(session_id: str) -> str:
    """Get current continuation_id for session, or empty string if none."""
    continuation_id = state_manager.get_continuation_id(session_id)
    return continuation_id or ""

def set_continuation_id(session_id: str, continuation_id: str) -> None:
    """Set continuation_id for current session."""
    state_manager.set_continuation_id(session_id, continuation_id)

def has_active_continuation(session_id: str) -> bool:
    """Check if session has an active continuation."""
    return state_manager.has_continuation(session_id)

def get_relevant_memories_context(user_prompt: str, session_id: str = "") -> str:
    """
    Retrieve relevant memories and format as concise context hints.
    Only inject highly relevant memories (score > 0.5).
    
    Args:
        user_prompt: User's current prompt
        session_id: Current session identifier
        
    Returns:
        Formatted memory context string or empty string
    """
    try:
        # Get relevant memories with high threshold
        memories = memory_manager.get_relevant_memories(
            context=user_prompt,
            session_id=session_id,
            limit=5,
            min_relevance=0.5
        )
        
        if not memories:
            return ""
        
        # Format as concise context hints
        memory_hints = []
        for memory in memories:
            content = memory.get('content', '')[:150]  # Truncate long content
            memory_type = memory.get('memory_type', 'context')
            relevance = memory.get('combined_relevance', 0)
            
            hint = f"[{memory_type.upper()}] {content} (relevance: {relevance:.2f})"
            memory_hints.append(hint)
        
        if memory_hints:
            return f"\n## Relevant Context from Memory:\n" + "\n".join(f"- {hint}" for hint in memory_hints) + "\n"
        
        return ""
        
    except Exception:
        # Silent fail - don't break context injection if memory retrieval fails
        return ""

# --- Claude Code Hook Entry Point ---

def handle(data):
    # HOOK_CONTRACT: Validate JSON input per security requirements
    try:
        if not isinstance(data, dict):
            print("Error: Invalid input format", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Error: Input validation failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # HOOK_CONTRACT: Validate expected fields exist
    user_prompt = data.get("prompt", "").strip()
    session_id = data.get("session_id", "")
    hook_event_name = data.get("hook_event_name", "")
    
    # Silent failure for non-applicable hooks
    if hook_event_name != "UserPromptSubmit":
        sys.exit(0)
    
    if not user_prompt:
        logger.log_context_injection(success=False, context=None)
        sys.exit(0)  # Do nothing
    
    # Initialize session if not already done
    if session_id:
        state_manager.initialize_session(session_id)

    verbose_outline = bootstrap_summary()
    if not verbose_outline:
        logger.log_error("No semantic outline available")
        sys.exit(0)
    
    # Get agent information
    project_root = Path(os.getcwd())
    agents_dir = project_root / CONSTANTS["file_paths"]["agents_dir_relative_path"]
    agents = get_agent_info(str(agents_dir))

    # Define MCP server information
    mcp_servers = CONSTANTS["mcp_servers"]

    try:
        # Extract keywords from prompt for better context filtering
        keywords = extract_keywords(user_prompt)
        
        # Filter outline to most relevant files
        relevant_outline = filter_relevant_files(user_prompt, verbose_outline, top_k=25)
        
        # Get git context relevant to prompt
        git_context = get_git_context(keywords)
        
        # Get error context if troubleshooting
        error_context = get_error_context() if any(word in user_prompt.lower() 
                                                   for word in ['error', 'bug', 'fix', 'issue', 'problem']) else None
        
        # Get additional context types
        project_config = get_project_config()
        project_docs = get_project_documentation()
        test_context = get_test_context()
        env_context = get_environment_context()
        
        # Get relevant memories for context injection
        memory_context = get_relevant_memories_context(user_prompt, session_id)
        
        # Add cross-file pattern analysis
        cross_file_patterns = aggregate_cross_file_patterns(verbose_outline)
        
        # Extract test metrics if test files found
        test_files = [f for f in verbose_outline.keys() if 'test' in f.lower()]
        test_metrics = extract_test_metrics(test_files) if test_files else None
        
        # Get context configuration for prompt
        context_config = calculate_context_depth(user_prompt)
        
        # Build import graph for smaller projects (optional - only if project seems small)
        import_graph = None
        try:
            file_count = len(check_output("find . -name '*.py' | wc -l", shell=True, text=True).strip())
            if int(file_count) < 50:  # Only for smaller projects
                import_graph = build_import_graph()
        except:
            pass
        
        # Pass enhanced context to Gemini with error handling
        try:
            gemini_response = call_gemini(user_prompt, relevant_outline, mcp_servers, agents, session_id, 
                                        git_context=git_context, error_context=error_context,
                                        project_config=project_config, project_docs=project_docs,
                                        test_context=test_context, env_context=env_context, 
                                        import_graph=import_graph, cross_file_patterns=cross_file_patterns,
                                        test_metrics=test_metrics, context_depth=context_config,
                                        memory_context=memory_context)
        except requests.exceptions.Timeout:
            logger.log_error("Gemini API timeout")
            sys.exit(0)  # Silent failure
        except requests.exceptions.RequestException as e:
            logger.log_error(f"Gemini API request failed: {e}")
            sys.exit(0)  # Silent failure
        
        # Add continuation tracking information to context (now redundant but kept for backward compatibility)
        continuation_info = ""
        if session_id:
            current_continuation = get_current_continuation_id(session_id)
            if current_continuation:
                continuation_info = f"\n\nCONTINUATION_ID: {current_continuation} (Use this in mcp__zen tools for conversation continuity)"
            else:
                continuation_info = "\n\nNO_CONTINUATION: This is a new conversation thread"
        
        # Output properly structured JSON for UserPromptSubmit context injection
        json_keys = CONSTANTS["json_structure"]
        output = {
            json_keys["hook_specific_output_key"]: {
                "hookEventName": json_keys["hook_event_name"],
                json_keys["additional_context_key"]: f"{CONSTANTS['response_template']['context_prefix']}{gemini_response}{continuation_info}"
            }
        }
        
        # Log successful context injection
        logger.log_context_injection(success=True, context=gemini_response)
        
        print(json.dumps(output))
        sys.exit(0)
        
    except Exception as e:
        # Log the error
        logger.log_error(f"Gemini request failed: {e}", {"exception_type": type(e).__name__})
        
        # Block with error message
        json_keys = CONSTANTS["json_structure"]
        output = {
            json_keys["decision_key"]: json_keys["block_decision"],
            json_keys["reason_key"]: f"{CONSTANTS['response_template']['gemini_failure_prefix']}{e}"
        }
        print(json.dumps(output))
        sys.exit(0)
