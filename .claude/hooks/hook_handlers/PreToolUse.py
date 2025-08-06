#!/usr/bin/env python3
"""
PreToolUse hook handler with comprehensive anti-pattern detection.
Blocks file creation that would lead to technical debt or dangerous patterns.
Supports exemption mechanisms for legitimate exceptions with proper justification.
"""

import ast
import json
import os
import re
import sys
import logging
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional, Set
from pathlib import Path

# Import file blocker functionality
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hook_tools'))
from file_blocker import block_file_creation_if_restricted, FileBlocker


def handle(data: Dict[str, Any]) -> None:
    """
    Handle PreToolUse hook events with comprehensive anti-pattern detection.
    
    Args:
        data: Hook event data containing tool information
    """
    try:
        # Extract relevant information - use tool_input per schema
        hook_event_name = data.get("hook_event_name", "")
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
                    print(f"\n❌ [CRITICAL] MASTER BLOCK ACTIVE:", file=sys.stderr)
                    print(f"   ALL operations in .claude directory are FROZEN", file=sys.stderr)
                    print(f"   Attempted: {tool_name} on {path}", file=sys.stderr)
                    print(f"   To disable: export CLAUDE_MASTER_BLOCK=false", file=sys.stderr)
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