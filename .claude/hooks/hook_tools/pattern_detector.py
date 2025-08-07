#!/usr/bin/env python3
# claude-exempt: File Without Context Manager - Existing code pattern from extracted functions
"""
Pattern Detection Module

Contains pattern detection functions extracted from PostToolUse.py for better organization.
Handles ZEN usage patterns, anti-patterns, and performance hotspot detection.
"""

import ast
import os
import re
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional

# Import dependencies from existing modules
from .analysis.performance_analyzer import detect_performance_hotspots_comprehensive
from .anti_patterns_detector import AntiPatternDetector, Severity
from .context.project_context import (
    get_error_context,
    get_project_config,
    get_project_documentation,
    get_test_context,
    get_environment_context,
)
from .security_validator import check_rate_limit, RateLimitExceeded


def collect_project_context_cached(session_id: str, cwd: str) -> Dict[str, Any]:
    """
    Collect comprehensive project context.

    Args:
        session_id: Current session identifier (for future use)
        cwd: Current working directory

    Returns:
        Dictionary containing project context information
    """
    # Note: session_id and cwd are part of the API but not used in current implementation
    try:
        # Collect all context information
        error_context = get_error_context()
        project_config = get_project_config()
        documentation = get_project_documentation()
        test_context = get_test_context()
        environment = get_environment_context()

        context = {
            "errors": error_context,
            "config": project_config,
            "docs": documentation,
            "tests": test_context,
            "environment": environment,
            "collected_at": datetime.now().isoformat(),
        }

        return context

    except Exception as e:
        # Return minimal context if collection fails
        return {
            "errors": {"recent_errors": [], "warnings": []},
            "config": {"dependencies": [], "scripts": {}, "config_files": []},
            "docs": {"readme_files": [], "doc_dirs": []},
            "tests": {"frameworks": [], "test_files": []},
            "environment": {"python_version": "", "platform": ""},
            "collection_error": str(e),
        }


def detect_zen_usage_patterns(
    tool_name: str,
    tool_input: Dict[str, Any],
    session_id: str,
    cwd: str,
    project_context: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Detect patterns that suggest ZEN tools would be beneficial with project context awareness.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        session_id: Current session identifier
        cwd: Current working directory
        project_context: Project context information for enhanced recommendations

    Returns:
        List of ZEN tool recommendations
    """
    if project_context is None:
        project_context = collect_project_context_cached(session_id, cwd)
    recommendations = []

    # Extract context information for enhanced recommendations
    recent_errors = project_context.get("errors", {}).get("recent_errors", [])
    dependencies = project_context.get("config", {}).get("dependencies", [])
    test_frameworks = project_context.get("tests", {}).get("frameworks", [])
    environment = project_context.get("environment", {})
    # config_files available but not used in current implementation

    # Track multi-file operations
    file_count = 0
    file_paths = []

    if tool_name in ["Read", "Edit", "MultiEdit", "Write"]:
        # Count files being processed
        for key in ["file_path", "path", "filepath"]:
            if key in tool_input and tool_input[key]:
                file_paths.append(tool_input[key])

        if tool_name == "MultiEdit" and "edits" in tool_input:
            file_count = 1  # MultiEdit works on single file
        else:
            file_count = len(file_paths)

    # ERROR-AWARE: Prioritize debug tools if recent errors detected
    if recent_errors:
        error_count = len(recent_errors)
        if error_count >= 3:
            recommendations.insert(
                0,
                f"mcp__zen__debug - CRITICAL: {error_count} recent errors detected, systematic root cause analysis needed",
            )
        elif tool_name in ["Bash", "Read", "Grep"] and any(
            "error" in cmd.lower()
            for cmd in [tool_input.get("command", ""), tool_input.get("pattern", "")]
        ):
            recommendations.append(
                f"mcp__zen__debug - {error_count} recent errors in context, structured debugging recommended"
            )

    # Complex debugging scenarios with context awareness
    if tool_name == "Bash" and tool_input.get("command", ""):
        command = tool_input["command"].lower()
        debug_patterns = [
            "grep",
            "rg",
            "find",
            "fd",
            "trace",
            "strace",
            "gdb",
            "debug",
            "log",
            "error",
            "crash",
            "fail",
        ]
        if any(pattern in command for pattern in debug_patterns):
            context_info = (
                f" (Python {environment.get('python_version', 'unknown')})"
                if environment.get("python_version")
                else ""
            )
            recommendations.append(
                f"mcp__zen__debug - Systematic debugging with expert analysis{context_info}"
            )

    # DEPENDENCY-AWARE: Security-related operations with framework context
    if tool_name in ["Read", "Grep", "Bash"] and tool_input:
        content_keys = ["pattern", "command", "file_path"]
        content = " ".join(str(tool_input.get(key, "")) for key in content_keys).lower()
        security_patterns = [
            "auth",
            "password",
            "token",
            "secret",
            "key",
            "security",
            "vuln",
            "exploit",
            "inject",
            "xss",
            "sql",
            "csrf",
        ]

        if any(pattern in content for pattern in security_patterns):
            # Enhanced security recommendations based on detected frameworks
            web_frameworks = [
                dep
                for dep in dependencies
                if dep.lower()
                in ["flask", "django", "fastapi", "express", "react", "vue", "angular"]
            ]
            if web_frameworks:
                recommendations.append(
                    f"mcp__zen__secaudit - CRITICAL: Security analysis for web frameworks ({', '.join(web_frameworks[:3])})"
                )
            else:
                recommendations.append(
                    "mcp__zen__secaudit - Comprehensive security analysis with OWASP compliance"
                )

    # Pre-commit validation scenarios
    if tool_name == "Bash" and tool_input.get("command", ""):
        command = tool_input["command"].lower()
        git_patterns = ["git diff", "git status", "git log", "git add", "git commit"]
        if any(pattern in command for pattern in git_patterns):
            recommendations.append(
                "mcp__zen__precommit - Comprehensive pre-commit validation workflow"
            )

    # CONTEXT-AWARE: Code quality and refactoring for Python files with environment info
    if tool_name in ["Edit", "MultiEdit", "Write"] and file_paths:
        python_files = [fp for fp in file_paths if fp.endswith(".py")]
        if python_files:
            python_version = environment.get("python_version", "")
            venv_status = environment.get("virtual_env", "none")

            # Enhanced recommendations with environment context
            if (
                python_version
                and python_version.startswith("3.12")
                or python_version.startswith("3.11")
            ):
                recommendations.append(
                    f"mcp__zen__refactor - Modern Python {python_version} optimization and pattern modernization"
                )
            else:
                recommendations.append(
                    "mcp__zen__refactor - Code improvement and modernization analysis"
                )

            if venv_status == "none":
                recommendations.append(
                    "mcp__zen__codereview - CRITICAL: No virtual environment detected, dependency isolation review needed"
                )
            else:
                recommendations.append(
                    "mcp__zen__codereview - Comprehensive code quality assessment"
                )

            # Add performance-specific recommendations for Python files
            performance_recs = detect_performance_hotspots_for_file_operation(
                tool_name, tool_input, cwd
            )
            for perf_rec in performance_recs:
                if perf_rec not in recommendations:
                    recommendations.append(perf_rec)

    # Performance and analysis patterns
    if tool_name == "Bash" and tool_input.get("command", ""):
        command = tool_input["command"].lower()
        perf_patterns = [
            "benchmark",
            "profile",
            "perf",
            "time",
            "memory",
            "cpu",
            "optimize",
            "performance",
        ]
        if any(pattern in command for pattern in perf_patterns):
            recommendations.append(
                "mcp__zen__analyze - Performance analysis and optimization recommendations"
            )

    # FRAMEWORK-AWARE: Test generation patterns with detected framework context
    test_patterns = ["test", "spec", "pytest", "jest", "unittest", "_test", "tests/"]
    if tool_name in ["Read", "Write", "Edit"] and tool_input.get("file_path", ""):
        file_path = tool_input["file_path"].lower()
        if any(pattern in file_path for pattern in test_patterns):
            if test_frameworks:
                primary_framework = test_frameworks[0]
                recommendations.append(
                    f"mcp__zen__testgen - {primary_framework.upper()} test suite generation and coverage analysis"
                )
            else:
                recommendations.append(
                    "mcp__zen__testgen - Comprehensive test suite generation"
                )

    # Test coverage enhancement based on detected frameworks and missing tests
    elif test_frameworks and tool_name in ["Edit", "Write"] and file_paths:
        code_files = [fp for fp in file_paths if fp.endswith((".py", ".js", ".ts"))]
        if (
            code_files
            and len(project_context.get("tests", {}).get("test_files", []))
            < len(code_files) * 0.3
        ):
            recommendations.append(
                f"mcp__zen__testgen - LOW TEST COVERAGE: Generate {test_frameworks[0]} tests for recent changes"
            )

    # Documentation generation for code files
    if tool_name in ["Read", "Write"] and tool_input.get("file_path", ""):
        file_path = tool_input["file_path"].lower()
        code_extensions = (
            ".py",
            ".js",
            ".ts",
            ".java",
            ".cpp",
            ".c",
            ".go",
            ".rs",
            ".php",
            ".rb",
        )
        if file_path.endswith(code_extensions):
            recommendations.append(
                "mcp__zen__docgen - Automated documentation generation"
            )

    # Code tracing for complex analysis
    if tool_name in ["Read", "Grep"] and tool_input:
        content_keys = ["pattern", "file_path"]
        content = " ".join(str(tool_input.get(key, "")) for key in content_keys).lower()
        trace_patterns = [
            "function",
            "method",
            "class",
            "import",
            "dependency",
            "call",
            "invoke",
        ]
        if any(pattern in content for pattern in trace_patterns):
            recommendations.append(
                "mcp__zen__tracer - Code flow and dependency analysis"
            )

    # Consensus building for architectural decisions
    architecture_patterns = [
        "design",
        "architect",
        "pattern",
        "structure",
        "framework",
        "library",
    ]
    if tool_name in ["Read", "Write", "Edit"] and tool_input.get("file_path", ""):
        file_path = tool_input["file_path"].lower()
        if any(pattern in file_path for pattern in architecture_patterns):
            recommendations.append(
                "mcp__zen__consensus - Multi-perspective architectural analysis"
            )

    # Multi-step operations (file count threshold)
    if file_count >= 3:
        recommendations.append("mcp__zen__analyze - Multi-file architectural analysis")
        recommendations.append(
            "mcp__zen__planner - Sequential planning for complex operations"
        )

    # Planning for complex multi-edit operations
    if tool_name == "MultiEdit" and tool_input.get("edits", []):
        edit_count = len(tool_input.get("edits", []))
        if edit_count >= 5:
            recommendations.append(
                "mcp__zen__planner - Multi-step editing workflow planning"
            )

    # Remove duplicates while preserving order
    seen = set()
    unique_recommendations = []
    for rec in recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recommendations.append(rec)

    return unique_recommendations[:3]  # Limit to top 3 recommendations


def detect_anti_patterns_for_file_operation(
    tool_name: str, tool_input: Dict[str, Any], cwd: str
) -> None:
    """
    Detect anti-patterns in Python files during Edit/Write/MultiEdit operations.
    Triggers exit code 2 for critical security/architecture violations.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        cwd: Current working directory
    """
    # Only check file modification tools
    file_tools = ["Edit", "Write", "MultiEdit"]
    if tool_name not in file_tools:
        return

    # Extract file paths from tool input
    file_paths = []
    if tool_name in ["Edit", "Write"]:
        file_path = tool_input.get("file_path", "")
        if file_path and file_path.endswith(".py"):
            file_paths.append(file_path)
    elif tool_name == "MultiEdit":
        file_path = tool_input.get("file_path", "")
        if file_path and file_path.endswith(".py"):
            file_paths.append(file_path)

    # Skip if no Python files to check
    if not file_paths:
        return

    try:
        detector = AntiPatternDetector()

        for file_path in file_paths:
            # Read file content if it exists, or extract from tool input
            file_content = None

            if tool_name == "Write":
                # For Write operations, get content from tool input
                file_content = tool_input.get("content", "")
            elif tool_name == "Edit":
                # For Edit operations, read the current file content
                if os.path.exists(file_path):
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            file_content = f.read()
                    except Exception:
                        continue  # Skip if can't read file
            elif tool_name == "MultiEdit":
                # For MultiEdit operations, read the current file content
                if os.path.exists(file_path):
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            file_content = f.read()
                    except Exception:
                        continue  # Skip if can't read file

            if not file_content:
                continue

            # Detect anti-patterns
            should_block, critical_patterns = detector.should_block_file_creation(
                file_path, file_content
            )

            if should_block and critical_patterns:
                # Format critical violations for output
                error_details = []
                for pattern in critical_patterns:
                    detail = f"❌ {pattern.pattern_name}: {pattern.description}"
                    if pattern.line_number:
                        detail += f" (line {pattern.line_number})"
                    if pattern.suggestion:
                        detail += f"\n   💡 {pattern.suggestion}"
                    error_details.append(detail)

                error_msg = (
                    f"🚨 CRITICAL ANTI-PATTERNS DETECTED in {file_path}:\n\n"
                    + "\n\n".join(error_details)
                    + f"\n\n🚫 File operation blocked due to {len(critical_patterns)} critical security/architecture violations."
                    "\nReview and fix these issues before proceeding."
                )

                # Apply rate limiting to prevent spam
                try:
                    check_rate_limit(f"ANTI_PATTERN_CRITICAL_{file_path}", max_requests=1, window_seconds=30)
                    should_show_anti_pattern = True
                except RateLimitExceeded:
                    should_show_anti_pattern = False
                
                if should_show_anti_pattern:
                    print(error_msg, file=sys.stderr)
                    sys.exit(2)

    except Exception as e:
        # Don't block operation if detector fails, but log the error
        print(f"Warning: Anti-pattern detection failed: {e}", file=sys.stderr)


def detect_performance_hotspots_for_file_operation(
    tool_name: str, tool_input: Dict[str, Any], cwd: str
) -> List[str]:
    """
    Detect performance hotspots in Python files during Edit/Write/MultiEdit operations.
    Returns ZEN tool recommendations for high-risk performance issues.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        cwd: Current working directory

    Returns:
        List of ZEN tool recommendations for performance issues
    """
    # Only check file modification tools
    file_tools = ["Edit", "Write", "MultiEdit"]
    if tool_name not in file_tools:
        return []

    # Extract file paths from tool input
    file_paths = []
    if tool_name in ["Edit", "Write"]:
        file_path = tool_input.get("file_path", "")
        if file_path and file_path.endswith(".py"):
            file_paths.append(file_path)
    elif tool_name == "MultiEdit":
        file_path = tool_input.get("file_path", "")
        if file_path and file_path.endswith(".py"):
            file_paths.append(file_path)

    # Skip if no Python files to check
    if not file_paths:
        return []

    zen_recommendations = []

    try:
        import ast

        for file_path in file_paths:
            # Read file content if it exists, or extract from tool input
            file_content = None

            if tool_name == "Write":
                # For Write operations, get content from tool input
                file_content = tool_input.get("content", "")
            elif tool_name in ["Edit", "MultiEdit"]:
                # For Edit/MultiEdit operations, read the current file content
                if os.path.exists(file_path):
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            file_content = f.read()
                    except Exception:
                        continue  # Skip if can't read file

            if not file_content:
                continue

            try:
                # Parse the Python code to AST
                tree = ast.parse(file_content)

                # Run comprehensive performance analysis
                hotspots = detect_performance_hotspots_comprehensive(
                    file_path, tree, file_content
                )

                # Calculate risk level and determine if ZEN tools are needed
                risk_score = hotspots.get("aggregate_risk_score", 0)
                risk_level = hotspots.get("risk_level", "minimal")

                # Generate specific feedback and recommendations based on risk level
                if risk_score >= 30 or risk_level in ["high", "critical"]:
                    performance_issues = []

                    # Critical nested loops (O(n²) or worse)
                    nested_loops = hotspots.get("nested_loops", [])
                    critical_loops = [
                        loop
                        for loop in nested_loops
                        if loop.get("severity") in ["high", "critical"]
                    ]
                    if critical_loops:
                        performance_issues.append(
                            f"{len(critical_loops)} critical nested loop patterns (O(n²+) complexity)"
                        )

                    # Sync I/O in wrong contexts
                    sync_io = hotspots.get("sync_io_operations", [])
                    critical_io = [io for io in sync_io if io.get("severity") == "high"]
                    if critical_io:
                        performance_issues.append(
                            f"{len(critical_io)} synchronous I/O operations in performance-critical contexts"
                        )

                    # Memory-intensive operations
                    memory_ops = hotspots.get("memory_intensive", [])
                    critical_memory = [
                        mem
                        for mem in memory_ops
                        if mem.get("severity") in ["high", "critical"]
                    ]
                    if critical_memory:
                        performance_issues.append(
                            f"{len(critical_memory)} memory-intensive operations"
                        )

                    # High complexity functions
                    complex_funcs = hotspots.get("high_complexity_functions", [])
                    critical_funcs = [
                        func
                        for func in complex_funcs
                        if func.get("severity") in ["high", "critical"]
                    ]
                    if critical_funcs:
                        performance_issues.append(
                            f"{len(critical_funcs)} high-complexity functions"
                        )

                    # Apply rate limiting for performance feedback
                    try:
                        check_rate_limit(f"PERFORMANCE_HOTSPOT_{file_path}", max_requests=2, window_seconds=60)
                        should_show_performance = True
                    except RateLimitExceeded:
                        should_show_performance = False
                        
                    if should_show_performance:
                        perf_msg = (
                            f"⚡ PERFORMANCE HOTSPOTS DETECTED in {file_path}:\n"
                            f"📊 Risk Score: {risk_score} ({risk_level.upper()})\n"
                            f"🔥 Issues: {'; '.join(performance_issues)}\n"
                            f"💡 Consider using mcp__zen__analyze for optimization recommendations"
                        )
                        print(perf_msg, file=sys.stderr)

                    # Add specific ZEN tool recommendations based on hotspot types
                    if nested_loops or critical_memory:
                        zen_recommendations.append(
                            "mcp__zen__analyze - Performance optimization and algorithmic complexity analysis"
                        )

                    if sync_io:
                        zen_recommendations.append(
                            "mcp__zen__refactor - Async/await pattern implementation"
                        )

                    if complex_funcs:
                        zen_recommendations.append(
                            "mcp__zen__codereview - Function decomposition and complexity reduction"
                        )

                # Medium risk issues get basic recommendation
                elif risk_score >= 15 or risk_level == "medium":
                    zen_recommendations.append(
                        "mcp__zen__analyze - Code optimization analysis"
                    )

                # Add recommendations based on specific hotspot categories regardless of risk level
                nested_loops = hotspots.get("nested_loops", [])
                sync_io = hotspots.get("sync_io_operations", [])
                memory_ops = hotspots.get("memory_intensive", [])
                complex_funcs = hotspots.get("high_complexity_functions", [])

                if nested_loops and "mcp__zen__analyze" not in " ".join(
                    zen_recommendations
                ):
                    zen_recommendations.append(
                        "mcp__zen__analyze - Performance optimization and algorithmic complexity analysis"
                    )

                if sync_io and "mcp__zen__refactor" not in " ".join(
                    zen_recommendations
                ):
                    zen_recommendations.append(
                        "mcp__zen__refactor - Async/await pattern implementation"
                    )

                if complex_funcs and "mcp__zen__codereview" not in " ".join(
                    zen_recommendations
                ):
                    zen_recommendations.append(
                        "mcp__zen__codereview - Function decomposition and complexity reduction"
                    )

            except SyntaxError:
                # Skip files with syntax errors
                continue

    except Exception as e:
        # Don't block operation if performance analysis fails
        print(f"Warning: Performance analysis failed: {e}", file=sys.stderr)

    return zen_recommendations