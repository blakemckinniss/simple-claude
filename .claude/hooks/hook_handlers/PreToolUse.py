#!/usr/bin/env python3
# claude-exempt: hook_handlers_py_protection - Expanding fragile pattern detection with 8 comprehensive anti-pattern categories
"""
PreToolUse hook handler with comprehensive anti-pattern detection.
Blocks file creation that would lead to technical debt or dangerous patterns.
Supports exemption mechanisms for legitimate exceptions with proper justification.

EXPANDED ANTI-PATTERN DETECTION CATEGORIES:
1. Global State Anti-patterns: Mutable defaults, unsafe singletons, global modifications
2. Import Anti-patterns: Star imports, circular imports, function-level imports, dynamic imports
3. File/Resource Management: Context manager violations, unsafe file operations
4. Exception Handling: Silent exceptions, exception control flow, poor error handling
5. Type System Abuse: type() vs isinstance(), monkey patching, dynamic attributes
6. Memory/Performance Landmines: Unbounded reads, recursion, string concatenation loops
7. Security Issues: Command injection, pickle risks, SQL injection, code execution
8. Async/Threading Issues: Blocking calls in async, shared state without locks
"""

import ast
import json
import os
import re
import sys
import logging
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path

# Add hook_tools to Python path if not already there
hook_tools_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hook_tools")
if hook_tools_path not in sys.path:
    sys.path.insert(0, hook_tools_path)

# Import file blocker functionality
try:
    from hook_tools.utilities.path_resolver import PathResolver
    paths = PathResolver()
except ImportError:
    # Fallback for when PathResolver is not available
    paths = None

try:
    import file_blocker  # type: ignore
    block_file_creation_if_restricted = file_blocker.block_file_creation_if_restricted
    FileBlocker = file_blocker.FileBlocker
except ImportError as e:
    print(f"Warning: Could not import file_blocker from {hook_tools_path}: {e}", file=sys.stderr)
    print(f"Available files in hook_tools: {os.listdir(hook_tools_path) if os.path.exists(hook_tools_path) else 'Directory not found'}", file=sys.stderr)
    
    # Fallback: define minimal stubs to prevent crashes
    def block_file_creation_if_restricted(file_path: str) -> None:
        pass
    
    class FileBlocker:
        def __init__(self):
            # Create a proper config object with the required method
            class Config:
                def is_master_block_enabled(self) -> bool:
                    return False
            self.config = Config()
        
        def _is_claude_directory_operation(self, path: str) -> bool:
            return False


def handle(data: Dict[str, Any]) -> None:
    """
    Handle PreToolUse hook events with comprehensive anti-pattern detection.
    
    Args:
        data: Hook event data containing tool information
    """
    try:
        # Extract relevant information - use tool_input per schema
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        
        # Check master block for ALL .claude directory operations
        blocker = FileBlocker()
        if blocker.config.is_master_block_enabled():
            # List of ALL file operation tools (read, write, edit, delete)
            all_file_tools = [
                "Read", "Write", "Edit", "MultiEdit", 
                "mcp__filesystem__read_file", "mcp__filesystem__read_text_file",
                "mcp__filesystem__write_file", "mcp__filesystem__edit_file",
                "mcp__filesystem__create_directory", "mcp__filesystem__move_file",
                "mcp__filesystem__list_directory", "mcp__filesystem__get_file_info",
                "create_or_update_file", "delete_file", "LS", "Grep", "Glob"
            ]
            
            if tool_name in all_file_tools:
                # Extract path from tool input
                path = (tool_input.get("file_path") or 
                       tool_input.get("path") or
                       tool_input.get("directory") or
                       tool_input.get("source") or
                       tool_input.get("destination") or "")
                
                if path and blocker._is_claude_directory_operation(path):
                    print("\n❌ [CRITICAL] MASTER BLOCK ACTIVE:", file=sys.stderr)
                    print("   ALL operations in .claude directory are FROZEN", file=sys.stderr)
                    print(f"   Attempted: {tool_name} on {path}", file=sys.stderr)
                    print("   To disable: export CLAUDE_MASTER_BLOCK=false", file=sys.stderr)
                    sys.exit(2)
        
        # Only check file creation tools for other restrictions
        file_creation_tools = ["Write", "MultiEdit", "mcp__filesystem__write_file", 
                              "mcp__filesystem__create_directory", "create_or_update_file"]
        
        if tool_name not in file_creation_tools:
            return
            
        # Extract file path and content from various tool input structures
        file_path = None
        content = None
        
        if "file_path" in tool_input:
            file_path = tool_input["file_path"]
            content = tool_input.get("content", "")
        elif "path" in tool_input:
            file_path = tool_input["path"]
            content = tool_input.get("content", "")
        elif "files" in tool_input and isinstance(tool_input["files"], list):
            # Handle MultiEdit with multiple files
            for file_info in tool_input["files"]:
                if isinstance(file_info, dict) and "path" in file_info:
                    check_file_restrictions(file_info["path"], file_info.get("content", ""))
            return
        elif "edits" in tool_input and isinstance(tool_input["edits"], list):
            # Handle MultiEdit edits
            file_path = tool_input.get("file_path")
            if file_path:
                # For edits, we check the path but don't have full content
                check_file_restrictions(file_path, "")
            return
            
        if not file_path:
            return
            
        check_file_restrictions(file_path, content or "")
        
    except Exception as e:
        print(f"Error in PreToolUse handler: {e}", file=sys.stderr)
        sys.exit(1)


class ExemptionManager:
    """Manages exemptions for anti-pattern checks."""
    
    def __init__(self):
        self.project_root = os.environ.get("CLAUDE_PROJECT_DIR", "/home/devcontainers/simple-claude")
        self.exemption_config_path = os.path.join(self.project_root, ".claude", "exemptions.json")
        self.log_dir = os.path.join(self.project_root, ".claude", "logs")
        self.exemption_log_path = os.path.join(self.log_dir, "exemptions.log")
        self.exemptions = self._load_exemptions()
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Setup exemption logging."""
        os.makedirs(self.log_dir, exist_ok=True)
        self.logger = logging.getLogger('exemptions')
        self.logger.setLevel(logging.INFO)
        
        # File handler for exemption log
        fh = logging.FileHandler(self.exemption_log_path)
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        
        # Clear existing handlers to avoid duplicates
        self.logger.handlers.clear()
        self.logger.addHandler(fh)
    
    def _load_exemptions(self) -> Dict[str, Any]:
        """Load exemption configuration from file."""
        default_config = {
            "global_exemptions": [],
            "file_exemptions": {},
            "justifications": {}
        }
        
        if os.path.exists(self.exemption_config_path):
            try:
                with open(self.exemption_config_path, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    for key in default_config:
                        if key not in config:
                            config[key] = default_config[key]
                    return config
            except (json.JSONDecodeError, IOError) as e:
                print(f"⚠️  Warning: Failed to load exemption config: {e}", file=sys.stderr)
        
        return default_config
    
    def _get_env_exemptions(self) -> List[str]:
        """Get exemptions from environment variable."""
        env_exemptions = os.environ.get("CLAUDE_EXEMPT_PATTERNS", "")
        if env_exemptions:
            return [e.strip() for e in env_exemptions.split(',') if e.strip()]
        return []
    
    def _parse_inline_exemptions(self, content: str) -> Dict[str, str]:
        """Parse inline exemption comments from file content."""
        exemptions = {}
        if not content:
            return exemptions
        
        # Pattern to match: # claude-exempt: <pattern-name> - <justification>
        pattern = r'#\s*claude-exempt:\s*([\w\s-]+?)\s*-\s*(.+?)$'
        
        for line in content.splitlines():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                pattern_name = match.group(1).strip()
                justification = match.group(2).strip()
                exemptions[pattern_name] = justification
        
        return exemptions
    
    def is_pattern_exempt(self, file_path: str, pattern_name: str, content: str = "") -> Tuple[bool, Optional[str]]:
        """Check if a pattern is exempt for a given file.
        
        Returns:
            Tuple of (is_exempt, justification)
        """
        # Check for force flag first
        if os.environ.get("CLAUDE_FORCE_CREATE", "").lower() == "true":
            justification = "Forced creation via CLAUDE_FORCE_CREATE=true"
            self.log_exemption(file_path, pattern_name, justification, "FORCE")
            return True, justification
        
        # Normalize pattern name for comparison
        pattern_key = pattern_name.lower().replace(' ', '_').replace('-', '_')
        
        # Check inline exemptions
        inline_exemptions = self._parse_inline_exemptions(content)
        for exempt_pattern, justification in inline_exemptions.items():
            if pattern_key in exempt_pattern.lower().replace(' ', '_').replace('-', '_'):
                self.log_exemption(file_path, pattern_name, justification, "INLINE")
                return True, justification
        
        # Check environment variable exemptions
        env_exemptions = self._get_env_exemptions()
        for exempt_pattern in env_exemptions:
            if pattern_key in exempt_pattern.lower().replace(' ', '_').replace('-', '_'):
                justification = f"Exempted via environment variable: {exempt_pattern}"
                self.log_exemption(file_path, pattern_name, justification, "ENV")
                return True, justification
        
        # Check global exemptions from config
        for exempt_pattern in self.exemptions.get("global_exemptions", []):
            if pattern_key in exempt_pattern.lower().replace(' ', '_').replace('-', '_'):
                justification = self.exemptions.get("justifications", {}).get(
                    exempt_pattern, f"Global exemption: {exempt_pattern}"
                )
                self.log_exemption(file_path, pattern_name, justification, "GLOBAL_CONFIG")
                return True, justification
        
        # Check file-specific exemptions from config
        file_exemptions = self.exemptions.get("file_exemptions", {})
        
        # Check both absolute and relative paths
        abs_path = os.path.abspath(file_path)
        rel_path = os.path.relpath(abs_path, self.project_root)
        
        for path_pattern, patterns in file_exemptions.items():
            # Check if file matches the path pattern
            if (path_pattern in abs_path or 
                path_pattern in rel_path or 
                abs_path.endswith(path_pattern) or
                rel_path.endswith(path_pattern)):
                
                for exempt_pattern in patterns:
                    if pattern_key in exempt_pattern.lower().replace(' ', '_').replace('-', '_'):
                        justification = self.exemptions.get("justifications", {}).get(
                            exempt_pattern, f"File-specific exemption: {exempt_pattern}"
                        )
                        self.log_exemption(file_path, pattern_name, justification, "FILE_CONFIG")
                        return True, justification
        
        return False, None
    
    def log_exemption(self, file_path: str, pattern: str, justification: str, source: str) -> None:
        """Log an exemption usage."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "file": file_path,
            "pattern": pattern,
            "justification": justification,
            "source": source
        }
        
        self.logger.info(json.dumps(log_entry))
        
        # Also print to stderr for visibility
        if source == "FORCE":
            print(f"⚠️  FORCE MODE: Bypassing all checks for {file_path}", file=sys.stderr)
        else:
            print(f"ℹ️  Exemption applied: {pattern} for {file_path} ({source}): {justification}", file=sys.stderr)


def check_file_restrictions(file_path: str, content: str = "") -> None:
    """
    Check if file creation should be blocked based on anti-patterns and technical debt indicators.
    
    Args:
        file_path: Path of file being created
        content: Content of the file (if available)
    """
    # Initialize exemption manager
    exemption_manager = ExemptionManager()
    
    # Check for force flag
    if os.environ.get("CLAUDE_FORCE_CREATE", "").lower() == "true":
        print("\n⚠️  WARNING: CLAUDE_FORCE_CREATE=true - Bypassing ALL anti-pattern checks!\n", file=sys.stderr)
        print("   This should only be used when absolutely necessary.", file=sys.stderr)
        print("   Consider using specific exemptions instead.\n", file=sys.stderr)
        exemption_manager.log_exemption(file_path, "ALL_PATTERNS", "Force mode enabled", "FORCE")
        return
    
    # Normalize path to absolute
    abs_path = os.path.abspath(file_path)
    project_root = os.environ.get("CLAUDE_PROJECT_DIR", "/home/devcontainers/simple-claude")
    docs_dir = os.path.join(project_root, ".claude", "docs")
    tests_dir = os.path.join(project_root, ".claude", "tests")
    
    # Original restrictions
    if abs_path.endswith('.md'):
        if not abs_path.startswith(docs_dir):
            print(f"❌ BLOCKED: .md files can only be created in {docs_dir}", file=sys.stderr)
            sys.exit(2)
    
    filename = os.path.basename(abs_path)
    if filename.startswith('test_') and filename.endswith('.py'):
        if not abs_path.startswith(tests_dir):
            print(f"❌ BLOCKED: test_*.py files can only be created in {tests_dir}", file=sys.stderr)
            sys.exit(2)
    
    # Check file blocker restrictions before anti-pattern analysis
    try:
        block_file_creation_if_restricted(abs_path)
    except SystemExit as e:
        # File blocker already printed error message and set exit code
        raise e
    
    # Check for anti-patterns
    violations = detect_anti_patterns(abs_path, content)
    
    # Filter out exempt patterns
    non_exempt_violations = []
    exempted_patterns = []
    
    for severity, pattern, details in violations:
        is_exempt, justification = exemption_manager.is_pattern_exempt(abs_path, pattern, content)
        if is_exempt:
            exempted_patterns.append((severity, pattern, details, justification))
        else:
            non_exempt_violations.append((severity, pattern, details))
    
    # Show exempted patterns if any
    if exempted_patterns:
        print("\nℹ️  EXEMPTED PATTERNS:\n", file=sys.stderr)
        for severity, pattern, details, justification in exempted_patterns:
            emoji = "🚫" if severity == "CRITICAL" else "⚠️" if severity == "HIGH" else "ℹ️"
            print(f"  {emoji} {pattern}: {details}", file=sys.stderr)
            print(f"     ✓ Exempted: {justification}", file=sys.stderr)
    
    # Block on non-exempt critical violations
    critical_violations = [v for v in non_exempt_violations if v[0] == "CRITICAL"]
    if critical_violations:
        print("\n❌ CRITICAL ANTI-PATTERNS DETECTED - FILE CREATION BLOCKED:\n", file=sys.stderr)
        for severity, pattern, details in critical_violations:
            print(f"  🚫 {pattern}: {details}", file=sys.stderr)
        print("\n💡 Fix these issues or add exemptions before creating the file.", file=sys.stderr)
        print("   To exempt: Add '# claude-exempt: <pattern> - <justification>' to the file", file=sys.stderr)
        print("   Or configure in .claude/exemptions.json", file=sys.stderr)
        sys.exit(2)
    
    # Warn on non-exempt high-severity violations
    high_violations = [v for v in non_exempt_violations if v[0] == "HIGH"]
    if high_violations:
        print("\n⚠️  HIGH-RISK PATTERNS DETECTED:\n", file=sys.stderr)
        for severity, pattern, details in high_violations:
            print(f"  ⚠️  {pattern}: {details}", file=sys.stderr)
        print("\n💡 Consider addressing these issues to prevent technical debt.", file=sys.stderr)


def analyze_ast_patterns(file_path: str, content: str) -> List[Tuple[str, str, str]]:
    """
    Analyze AST patterns for deeper code structure validation.
    
    Args:
        file_path: Path to the file being analyzed
        content: Source code content
        
    Returns:
        List of (severity, pattern_name, details) tuples
    """
    violations = []
    
    # Only analyze Python files
    if not file_path.endswith('.py') or not content.strip():
        return violations
    
    try:
        tree = ast.parse(content)
    except SyntaxError:
        # Skip files with syntax errors
        return violations
    except Exception:
        # Skip any other parsing issues
        return violations
    
    # 1. CYCLOMATIC COMPLEXITY ANALYSIS
    function_complexities = _calculate_function_complexities(tree)
    for func_name, complexity in function_complexities.items():
        if complexity > 10:
            violations.append(("HIGH", "High Cyclomatic Complexity", 
                             f"Function '{func_name}' has complexity {complexity} (max: 10)"))
    
    # 2. CLASS METHOD COUNT ANALYSIS (God Class Detection)
    class_methods = _count_class_methods(tree)
    for class_name, method_count in class_methods.items():
        if method_count > 15:
            violations.append(("HIGH", "God Class", 
                             f"Class '{class_name}' has {method_count} methods (max: 15)"))
    
    # 3. INHERITANCE DEPTH ANALYSIS
    inheritance_depths = _analyze_inheritance_depth(tree)
    for class_name, depth in inheritance_depths.items():
        if depth > 3:
            violations.append(("MEDIUM", "Deep Inheritance", 
                             f"Class '{class_name}' has inheritance depth {depth} (max: 3)"))
    
    # 4. UNUSED IMPORTS AND VARIABLES
    unused_imports = _find_unused_imports(tree, content)
    if unused_imports:
        violations.append(("MEDIUM", "Unused Imports", 
                         f"Unused imports: {', '.join(unused_imports[:5])}"))
    
    unused_vars = _find_unused_variables(tree)
    if unused_vars:
        violations.append(("LOW", "Unused Variables", 
                         f"Unused variables: {', '.join(unused_vars[:5])}"))
    
    # 5. FUNCTION PARAMETER COUNT
    param_counts = _analyze_parameter_counts(tree)
    for func_name, param_count in param_counts.items():
        if param_count > 5:
            violations.append(("MEDIUM", "Too Many Parameters", 
                             f"Function '{func_name}' has {param_count} parameters (max: 5)"))
    
    # 6. NESTED FUNCTION DEPTH
    nested_depths = _analyze_nested_function_depth(tree)
    for func_name, depth in nested_depths.items():
        if depth > 3:
            violations.append(("MEDIUM", "Deep Function Nesting", 
                             f"Function '{func_name}' has nesting depth {depth} (max: 3)"))
    
    # 7. RETURN STATEMENT COMPLEXITY
    complex_returns = _analyze_return_complexity(tree)
    for func_name, complexity in complex_returns.items():
        if complexity > 5:
            violations.append(("MEDIUM", "Complex Return Logic", 
                             f"Function '{func_name}' has complex return patterns"))
    
    return violations


def _calculate_function_complexities(tree: ast.AST) -> Dict[str, int]:
    """Calculate cyclomatic complexity for each function."""
    complexities = {}
    
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = 1  # Base complexity
            
            for child in ast.walk(node):
                # Decision points that increase complexity
                if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                    complexity += 1
                elif isinstance(child, ast.ExceptHandler):
                    complexity += 1
                elif isinstance(child, ast.BoolOp):
                    complexity += len(child.values) - 1
                elif isinstance(child, ast.comprehension):
                    complexity += 1
                elif isinstance(child, ast.Lambda):
                    complexity += 1
            
            complexities[node.name] = complexity
    
    return complexities


def _count_class_methods(tree: ast.AST) -> Dict[str, int]:
    """Count methods per class."""
    class_methods = {}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            method_count = 0
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_count += 1
            class_methods[node.name] = method_count
    
    return class_methods


def _analyze_inheritance_depth(tree: ast.AST) -> Dict[str, int]:
    """Analyze inheritance depth for classes."""
    inheritance_depths = {}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            depth = len(node.bases)  # Simple approximation
            if depth > 0:
                inheritance_depths[node.name] = depth
    
    return inheritance_depths


def _find_unused_imports(tree: ast.AST, content: str) -> List[str]:
    """Find unused import statements."""
    imported_names = set()
    used_names = set()
    
    # Collect imported names
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                imported_names.add(name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                imported_names.add(name)
    
    # Collect used names (simplified analysis)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used_names.add(node.id)
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                used_names.add(node.value.id)
    
    return list(imported_names - used_names)


def _find_unused_variables(tree: ast.AST) -> List[str]:
    """Find unused variable assignments."""
    assigned_vars = set()
    used_vars = set()
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned_vars.add(target.id)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            used_vars.add(node.id)
    
    # Filter out common patterns that shouldn't be flagged
    unused = assigned_vars - used_vars
    return [var for var in unused if not var.startswith('_')]


def _analyze_parameter_counts(tree: ast.AST) -> Dict[str, int]:
    """Analyze parameter counts for functions."""
    param_counts = {}
    
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            param_count = len(node.args.args)
            if node.args.vararg:
                param_count += 1
            if node.args.kwarg:
                param_count += 1
            param_counts[node.name] = param_count
    
    return param_counts


def _analyze_nested_function_depth(tree: ast.AST) -> Dict[str, int]:
    """Analyze nesting depth of functions."""
    nested_depths = {}
    
    def _get_nesting_depth(node: ast.AST, current_depth: int = 0) -> int:
        max_depth = current_depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                depth = _get_nesting_depth(child, current_depth + 1)
                max_depth = max(max_depth, depth)
                if current_depth > 0:  # Only record nested functions
                    nested_depths[child.name] = current_depth + 1
            else:
                depth = _get_nesting_depth(child, current_depth)
                max_depth = max(max_depth, depth)
        return max_depth
    
    _get_nesting_depth(tree)
    return nested_depths


def _analyze_return_complexity(tree: ast.AST) -> Dict[str, int]:
    """Analyze complexity of return statements."""
    return_complexities = {}
    
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return_count = 0
            complex_returns = 0
            
            for child in ast.walk(node):
                if isinstance(child, ast.Return):
                    return_count += 1
                    if child.value:
                        # Check if return value is complex
                        if isinstance(child.value, (ast.BoolOp, ast.Compare, ast.IfExp)):
                            complex_returns += 1
                        elif isinstance(child.value, ast.Call):
                            complex_returns += 1
            
            if return_count > 1 or complex_returns > 0:
                return_complexities[node.name] = return_count + complex_returns
    
    return return_complexities


def _detect_global_state_patterns(tree: ast.AST, content: str) -> List[Tuple[str, str, str]]:
    """Detect global state anti-patterns."""
    violations = []
    
    # 1. Mutable default arguments
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for default in node.args.defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    violations.append(("CRITICAL", "Mutable Default Argument",
                        f"Function '{node.name}' has mutable default argument - use None and create inside function"))
                elif isinstance(default, ast.Call) and isinstance(default.func, ast.Name):
                    if default.func.id in ['list', 'dict', 'set']:
                        violations.append(("CRITICAL", "Mutable Default Argument",
                            f"Function '{node.name}' calls {default.func.id}() as default - use None and create inside function"))
    
    # 2. Global variable modifications outside module initialization
    global_assigns = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            for name in node.names:
                global_assigns.append(name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Check for global modifications inside functions/classes
            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name) and target.id in global_assigns:
                            violations.append(("HIGH", "Global State Modification",
                                f"Global variable '{target.id}' modified in {node.name} - consider dependency injection"))
    
    # 3. Singleton patterns without thread safety
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            has_new = any(isinstance(child, ast.FunctionDef) and child.name == '__new__' 
                         for child in node.body)
            has_instance = any(isinstance(child, ast.Assign) and 
                             any(isinstance(target, ast.Name) and target.id == '_instance' 
                                 for target in child.targets)
                             for child in ast.walk(node))
            
            if has_new and has_instance:
                # Check for thread safety (threading.Lock, threading.RLock)
                has_lock = 'threading' in content and ('Lock' in content or 'RLock' in content)
                if not has_lock:
                    violations.append(("HIGH", "Unsafe Singleton Pattern",
                        f"Class '{node.name}' implements singleton without thread safety - use threading.Lock"))
    
    return violations


def _detect_import_patterns(tree: ast.AST, content: str) -> List[Tuple[str, str, str]]:
    """Detect import anti-patterns."""
    violations = []
    
    # 1. Star imports (namespace pollution)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == '*':
                    module = node.module or 'unknown'
                    violations.append(("HIGH", "Star Import",
                        f"'from {module} import *' pollutes namespace - use specific imports"))
    
    # 2. Imports inside functions (except legitimate lazy loading)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    # Check if it's a legitimate lazy import pattern
                    is_lazy = (
                        'import' in node.name.lower() or 
                        'lazy' in node.name.lower() or
                        node.name.startswith('_') or
                        any(isinstance(parent, ast.Try) for parent in ast.walk(node))
                    )
                    if not is_lazy:
                        violations.append(("MEDIUM", "Import Inside Function",
                            f"Import in function '{node.name}' - move to module level unless for lazy loading"))
    
    # 3. exec()/eval() with dynamic imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ['exec', 'eval']:
                for arg in node.args:
                    if ((isinstance(arg, ast.Str) and 'import' in arg.s) or 
                    (isinstance(arg, ast.Constant) and isinstance(arg.value, str) and 'import' in arg.value)):
                        violations.append(("CRITICAL", "Dynamic Import Execution",
                            f"Using {node.func.id}() for dynamic imports - use importlib instead"))
    
    return violations


def _detect_exception_patterns(tree: ast.AST, content: str) -> List[Tuple[str, str, str]]:
    """Detect exception handling anti-patterns."""
    violations = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                # 1. except Exception: without logging
                if (isinstance(handler.type, ast.Name) and 
                    handler.type.id == 'Exception' and 
                    handler.body):
                    
                    has_logging = any(
                        isinstance(child, ast.Call) and
                        isinstance(child.func, ast.Attribute) and
                        child.func.attr in ['error', 'warning', 'exception', 'log', 'debug', 'info']
                        for child in ast.walk(handler)
                    )
                    
                    has_print = any(
                        isinstance(child, ast.Call) and
                        isinstance(child.func, ast.Name) and
                        child.func.id == 'print'
                        for child in ast.walk(handler)
                    )
                    
                    if not has_logging and not has_print:
                        violations.append(("HIGH", "Silent Exception Handling",
                            "except Exception: without logging - errors should be logged or handled"))
                
                # 2. Empty except blocks (swallowing exceptions)
                if (handler.body and len(handler.body) == 1 and 
                    isinstance(handler.body[0], ast.Pass)):
                    violations.append(("HIGH", "Exception Swallowing",
                        "Empty except block swallows exceptions - at minimum log the error"))
                
                # 3. Using exceptions for control flow
                if (isinstance(handler.type, ast.Name) and 
                    handler.type.id in ['KeyError', 'IndexError', 'AttributeError'] and
                    not any(isinstance(child, ast.Raise) for child in ast.walk(handler))):
                    
                    # Check if this might be control flow
                    has_return_or_continue = any(
                        isinstance(child, (ast.Return, ast.Continue, ast.Break))
                        for child in ast.walk(handler)
                    )
                    
                    if has_return_or_continue:
                        violations.append(("MEDIUM", "Exception Control Flow",
                            f"Using {handler.type.id} for control flow - consider explicit checks instead"))
    
    return violations


def _detect_type_system_patterns(tree: ast.AST, content: str) -> List[Tuple[str, str, str]]:
    """Detect type system abuse patterns."""
    violations = []
    
    for node in ast.walk(tree):
        # 1. type() for type checking instead of isinstance()
        if (isinstance(node, ast.Call) and 
            isinstance(node.func, ast.Name) and 
            node.func.id == 'type'):
            
            # Look for type() == comparisons
            parent_nodes = []
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    if child is node:
                        parent_nodes.append(parent)
            
            for parent in parent_nodes:
                if isinstance(parent, ast.Compare):
                    violations.append(("MEDIUM", "Type Checking Anti-pattern",
                        "Use isinstance() instead of type() for type checking"))
        
        # 2. Dynamic attribute assignment to classes (monkey patching)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute):
                    if isinstance(target.value, ast.Name):
                        # Check if assigning to what might be a class
                        if target.value.id.isupper() or target.value.id[0].isupper():
                            violations.append(("HIGH", "Dynamic Class Modification",
                                f"Dynamic attribute assignment to '{target.value.id}' - avoid monkey patching"))
    
    return violations


def _detect_async_threading_patterns(tree: ast.AST, content: str) -> List[Tuple[str, str, str]]:
    """Detect async/threading anti-patterns."""
    violations = []
    
    for node in ast.walk(tree):
        # 1. time.sleep() in async functions
        if isinstance(node, ast.AsyncFunctionDef):
            for child in ast.walk(node):
                if (isinstance(child, ast.Call) and 
                    isinstance(child.func, ast.Attribute) and
                    isinstance(child.func.value, ast.Name) and
                    child.func.value.id == 'time' and
                    child.func.attr == 'sleep'):
                    violations.append(("CRITICAL", "Blocking Call In Async Function",
                        f"time.sleep() in async function '{node.name}' - use asyncio.sleep() instead"))
        
        # 2. Blocking I/O in async functions
        if isinstance(node, ast.AsyncFunctionDef):
            blocking_calls = [
                ('open', 'Use aiofiles for async file I/O'),
                ('requests', 'Use aiohttp or httpx for async HTTP requests'),
                ('urllib', 'Use aiohttp for async HTTP requests'),
                ('socket.socket', 'Use asyncio sockets'),
            ]
            
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = None
                    if isinstance(child.func, ast.Name):
                        call_name = child.func.id
                    elif isinstance(child.func, ast.Attribute):
                        if isinstance(child.func.value, ast.Name):
                            call_name = f"{child.func.value.id}.{child.func.attr}"
                    
                    if call_name:
                        for blocking_call, suggestion in blocking_calls:
                            if blocking_call in call_name:
                                violations.append(("HIGH", "Blocking I/O In Async Function",
                                    f"Blocking call '{call_name}' in async function '{node.name}' - {suggestion}"))
    
    # 3. Shared mutable state without locks (basic detection)
    if 'threading' in content and 'global' in content:
        has_lock = any(lock_type in content for lock_type in ['Lock', 'RLock', 'Semaphore', 'Condition'])
        if not has_lock:
            violations.append(("HIGH", "Shared State Without Synchronization",
                "Threading usage detected with global variables but no locking mechanisms"))
    
    return violations


def detect_anti_patterns(file_path: str, content: str) -> List[Tuple[str, str, str]]:
    """
    Detect anti-patterns and technical debt indicators.
    
    Returns:
        List of (severity, pattern_name, details) tuples
    """
    violations = []
    path_obj = Path(file_path)
    filename = path_obj.name
    
    # AST-based analysis for Python files
    if content and filename.endswith('.py'):
        ast_violations = analyze_ast_patterns(file_path, content)
        violations.extend(ast_violations)
        
        # Advanced AST-based pattern detection
        try:
            tree = ast.parse(content)
            violations.extend(_detect_global_state_patterns(tree, content))
            violations.extend(_detect_import_patterns(tree, content))
            violations.extend(_detect_exception_patterns(tree, content))
            violations.extend(_detect_type_system_patterns(tree, content))
            violations.extend(_detect_async_threading_patterns(tree, content))
        except (SyntaxError, Exception):
            # Skip AST analysis if parsing fails
            pass
    
    # 1. FILE STRUCTURE ANTI-PATTERNS
    
    # Deep nesting (>6 levels)
    if len(path_obj.parts) > 6:
        violations.append(("HIGH", "Deep Nesting", f"File is {len(path_obj.parts)} levels deep (max: 6)"))
    
    # God files (>500 lines)
    if content:
        line_count = len(content.splitlines())
        if line_count > 500:
            violations.append(("HIGH", "God File", f"File has {line_count} lines (max: 500)"))
    
    # Duplicate/utility anti-pattern
    if re.match(r"(utils?|helpers?|common|shared|misc|stuff|temp|old|backup|copy\d*)\.(py|js|ts)$", filename, re.I):
        violations.append(("HIGH", "Generic Utility File", "Indicates lack of proper domain modeling"))
    
    # Abandoned code patterns
    if re.search(r"(deprecated|obsolete|do_not_use|legacy|old_|_old|_bak|\.bak$|~$|\.swp$)", filename, re.I):
        violations.append(("CRITICAL", "Abandoned Code", "File appears to be deprecated or backup"))
    
    # 2. SECURITY ANTI-PATTERNS
    
    if content:
        # Hardcoded credentials
        cred_patterns = [
            (r'(api[_\-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9\-_]{20,}["\']', "API Key"),
            (r'(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']', "Password"),
            (r'aws[_\-]?access[_\-]?key[_\-]?id\s*[:=]\s*["\']AK[A-Z0-9]{16,}["\']', "AWS Key"),
            (r'(secret|token)\s*[:=]\s*["\'][^"\']{16,}["\']', "Secret/Token"),
            (r'(private[_\-]?key)\s*[:=]\s*["\']-----BEGIN', "Private Key")
        ]
        
        for pattern, cred_type in cred_patterns:
            if re.search(pattern, content, re.I):
                violations.append(("CRITICAL", "Hardcoded Credentials", f"{cred_type} detected in code"))
        
        # SQL Injection risks
        if re.search(r'f["\'].*SELECT.*WHERE.*\{|%\s*%|format\(.*SELECT', content):
            violations.append(("CRITICAL", "SQL Injection Risk", "Dynamic SQL query construction detected"))
        
        # Command injection
        if re.search(r'os\.system\s*\(|shell\s*=\s*True|eval\s*\(|exec\s*\(', content):
            violations.append(("CRITICAL", "Command Injection Risk", "Unsafe command execution detected"))
        
        # Debug code in production
        if re.search(r'(debugger|console\.log|print\(.*debug|pdb\.set_trace|import pdb)', content, re.I):
            if 'debug' not in filename.lower() and 'test' not in filename.lower():
                violations.append(("HIGH", "Debug Code", "Debug statements in non-debug file"))
    
    # 3. ARCHITECTURE ANTI-PATTERNS
    
    # Business logic in wrong layer
    if '/controllers/' in file_path or '/views/' in file_path:
        if content and re.search(r'\b(calculate|compute|process|validate|transform)\w*\s*\(', content):
            violations.append(("HIGH", "Wrong Layer Logic", "Business logic in presentation layer"))
    
    # Database access outside data layer
    if content and not any(x in file_path for x in ['/models/', '/repositories/', '/dal/', '/data/']):
        if re.search(r'(SELECT\s+.*FROM|session\.(query|add)|db\.(insert|update|delete))', content):
            violations.append(("HIGH", "Database Layer Violation", "Direct DB access outside data layer"))
    
    # 4. CODE QUALITY ANTI-PATTERNS
    
    # Temporary/experimental code
    if re.search(r'\b(temp|tmp|test|experiment|poc|prototype|draft|wip)\b', filename, re.I):
        if 'test' not in file_path.lower() or not filename.startswith('test_'):
            violations.append(("HIGH", "Temporary Code", "File appears to be temporary/experimental"))
    
    # TODO/FIXME accumulation
    if content:
        todo_count = len(re.findall(r'(TODO|FIXME|HACK|XXX):', content, re.I))
        if todo_count > 5:
            violations.append(("MEDIUM", "Technical Debt", f"Contains {todo_count} TODO/FIXME comments"))
    
    # Magic numbers
    if content and re.search(r'(?<!\w\.)\b\d{3,}\b(?!\s*[)\],;])', content):
        violations.append(("MEDIUM", "Magic Numbers", "Large numeric literals should be constants"))
    
    # Circular import risk
    if content and re.search(r'from\s+\.\.\.\.\s+import|import\s+\.\.\.\.', content):
        violations.append(("HIGH", "Circular Import Risk", "Complex relative imports detected"))
    
    # 5. FILE/RESOURCE MANAGEMENT ANTI-PATTERNS
    
    if content:
        # open() without context manager
        if re.search(r'\bopen\s*\([^)]*\)(?!\s*\.__enter__|(?:\s*as\s+\w+)?(?:\s*\):|\s*,))', content):
            violations.append(("CRITICAL", "File Without Context Manager", 
                             "Use 'with open()' instead of bare open() to ensure proper file closure"))
        
        # Manual file closing without try/finally
        if re.search(r'\.close\(\)(?!.*finally)', content) and not re.search(r'with\s+open', content):
            violations.append(("HIGH", "Manual File Closing", 
                             "Manual file.close() without try/finally can leak resources on exceptions"))
        
        # Hardcoded file paths
        hardcoded_paths = [
            (r'["\'][C-Z]:[\\][^"\'\\n]+["\']', "Windows absolute path"),
            (r'["\'][/][^"\'\\n]+["\']', "Unix absolute path"),
            (r'["\'][.][.][/\\][^"\'\\n]+["\']', "Relative path with ..")
        ]
        for pattern, path_type in hardcoded_paths:
            if re.search(pattern, content):
                violations.append(("HIGH", "Hardcoded File Path", 
                                 f"{path_type} detected - use configuration or Path objects"))
        
        # Direct os.remove() without existence checks
        if re.search(r'os\.remove\s*\([^)]*\)(?!.*(?:exists|isfile))', content):
            violations.append(("HIGH", "Unsafe File Deletion", 
                             "Use os.path.exists() check before os.remove() to avoid FileNotFoundError"))
    
    # 6. MEMORY/PERFORMANCE LANDMINES
    
    if content:
        # Loading entire files without size checks
        if re.search(r'\.(read|readlines)\(\)(?!.*\bsize|.*\blimit)', content):
            violations.append(("HIGH", "Unbounded File Read", 
                             "Reading entire file without size limits can cause memory exhaustion"))
        
        # Unbounded recursion (basic detection)
        if content and filename.endswith('.py'):
            # Look for recursive function calls without obvious depth limits
            func_names = re.findall(r'def\s+(\w+)\s*\(', content)
            for func_name in func_names:
                # Check if function calls itself
                if re.search(rf'{func_name}\s*\([^)]*\)', content):
                    # Check if there's a depth limit or counter
                    if not re.search(r'\bdepth\b|\bcount\b|\blimit\b|\bmax_\w+', content):
                        violations.append(("HIGH", "Potential Unbounded Recursion", 
                                         f"Function '{func_name}' appears recursive without depth limit"))
                        break  # Only report once per file
        
        # String concatenation in loops
        concat_patterns = [
            r'for\s+\w+\s+in\s+[^:]+:\s*[^\\n]*\+=\s*[^\\n]*str',
            r'while\s+[^:]+:\s*[^\\n]*\+=\s*[^\\n]*["\']'
        ]
        for pattern in concat_patterns:
            if re.search(pattern, content, re.MULTILINE):
                violations.append(("MEDIUM", "String Concatenation In Loop", 
                                 "Use list.append() + ''.join() or io.StringIO for better performance"))
                break  # Only report once
        
        # Large list comprehensions that should be generators
        if re.search(r'\[[^\\n]*for\s+\w+\s+in\s+[^\\]]{50,}', content):
            violations.append(("MEDIUM", "Large List Comprehension", 
                             "Consider using generator expression for large data sets"))
    
    # 7. ENHANCED SECURITY ISSUES
    
    if content:
        # subprocess with shell=True (command injection)
        if re.search(r'subprocess\.[^(]*\([^)]*shell\s*=\s*True', content):
            violations.append(("CRITICAL", "Command Injection Risk", 
                             "subprocess with shell=True allows command injection - use shell=False and list arguments"))
        
        # pickle for potentially untrusted data
        if re.search(r'pickle\.(load|loads)\s*\(', content):
            violations.append(("CRITICAL", "Pickle Security Risk", 
                             "pickle.load() can execute arbitrary code - use json or safer serialization"))
        
        # SQL string formatting
        sql_patterns = [
            r'["\'].*SELECT.*%s.*["\']\\s*%',
            r'["\'].*INSERT.*\{.*\}.*["\']\\s*\.format',
            r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{[^}]*\}'
        ]
        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                violations.append(("CRITICAL", "SQL Injection via String Formatting", 
                                 "Use parameterized queries instead of string formatting for SQL"))
                break  # Only report once
        
        # eval() and exec() usage (general security risk)
        if re.search(r'\b(eval|exec)\s*\(', content):
            violations.append(("CRITICAL", "Code Execution Risk", 
                             "eval() and exec() can execute arbitrary code - avoid or sanitize input thoroughly"))
    
    # 8. ENHANCED IMPORT ANTI-PATTERNS (regex-based)
    
    if content:
        # Wildcard imports (already covered in AST but adding regex backup)
        if re.search(r'from\s+[\w.]+\s+import\s+\*', content):
            violations.append(("HIGH", "Wildcard Import", 
                             "from module import * pollutes namespace - use specific imports"))
    
    # 9. FRAGILE PATH PATTERNS
    
    if content and filename.endswith('.py'):
        fragile_path_patterns = [
            # Direct parent navigation patterns
            (r'Path\s*\(\s*__file__\s*\)\s*\.parent(?:\.parent)*', 
             "Fragile path pattern: Path(__file__).parent chains are brittle and break when files move"),
            
            # sys.path manipulation patterns
            (r'sys\.path\.(?:insert|append)\s*\(', 
             "Fragile path pattern: Direct sys.path manipulation creates import dependencies on file location"),
            
            # os.path.dirname chains
            (r'os\.path\.dirname\s*\(\s*os\.path\.dirname\s*\(.*__file__', 
             "Fragile path pattern: Nested os.path.dirname(__file__) calls are location-dependent"),
            
            # Direct path joins with __file__ dirname
            (r'os\.path\.join\s*\(\s*os\.path\.dirname\s*\(\s*__file__\s*\)', 
             "Fragile path pattern: Manual path construction with os.path.dirname(__file__) is brittle"),
            
            # sys.path reassignment patterns
            (r'sys\.path\[0:0\]\s*=|sys\.path\s*=\s*\[.*\]\s*\+\s*sys\.path', 
             "Fragile path pattern: sys.path reassignment creates location dependencies"),
            
            # Common alternative patterns
            (r'os\.getcwd\(\)\s*\+|os\.path\.abspath\s*\(\s*[\'\"]\.\.[/\\]', 
             "Fragile path pattern: Relative path construction from current directory is unreliable")
        ]
        
        for pattern, message in fragile_path_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                violations.append(("CRITICAL", "Fragile Path Pattern", 
                                 f"{message}\n\nUse PathResolver instead:\n"
                                 "from hook_tools.utilities.path_resolver import PathResolver\n"
                                 "paths = PathResolver()\n"
                                 "# Then use paths.project_root, paths.claude_dir, etc."))
    
    return violations


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