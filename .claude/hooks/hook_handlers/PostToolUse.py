#!/usr/bin/env python3
# claude-exempt: hook_handlers_py_protection - Enhancing ZEN triggering logic with severity-weighted system
"""
PostToolUse hook handler compliant with HOOK_CONTRACT.md.
This hook is called after Claude uses a tool.
Provides CLI recommendations for Bash commands and automatically fixes Python files using python_auto_fixer.py.
"""

import json
import sys
import os
import re
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

# Import state manager for continuation tracking, logger for rate limiting, and memory manager
from hook_tools.utilities.path_resolver import PathResolver
from hook_tools.utilities.smart_truncate import truncate_for_preview
from hook_tools.state_manager import state_manager
from hook_logger import logger
from hook_tools.memory_manager import memory_manager, MemoryType
from hook_tools.anti_patterns_detector import AntiPatternDetector
from hook_tools.analysis.performance_analyzer import (
    detect_performance_hotspots_comprehensive,
)
from hook_tools.context.project_context import (
    get_error_context,
    get_project_config,
    get_project_documentation,
    get_test_context,
    get_environment_context,
)

paths = PathResolver()

# Configurable severity-weighted triggering thresholds
SEVERITY_CONFIG = {
    "critical": {
        "frequency": 1,  # Always trigger (every tool use)
        "bypass_rate_limit": True,
    },
    "high": {"frequency": 2, "bypass_rate_limit": False},  # Every 2nd tool use
    "medium": {
        "frequency_with_continuation": 3,  # Every 3rd tool use
        "frequency_without_continuation": 5,  # Every 5th tool use
        "bypass_rate_limit": False,
    },
    "low": {"frequency": 7, "bypass_rate_limit": False},  # Every 7th tool use
}


def extract_continuation_id(
    tool_name: str, tool_input: Dict[str, Any], tool_response: Any
) -> str:
    """
    Extract continuation_id from mcp__zen tool responses.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        tool_response: Response from the tool (can be dict, list, or string)

    Returns:
        continuation_id if found, empty string otherwise
    """
    # Only process mcp__zen tools
    if not tool_name.startswith("mcp__zen__"):
        return ""

    # Handle different response types
    response_to_check = tool_response

    # If response is a list, check the first item
    if isinstance(tool_response, list) and len(tool_response) > 0:
        response_to_check = tool_response[0]

        # If the first item is a dict with a 'text' field containing JSON
        if isinstance(response_to_check, dict) and "text" in response_to_check:
            text_content = response_to_check.get("text", "")
            if isinstance(text_content, str):
                try:
                    response_to_check = json.loads(text_content)
                except (json.JSONDecodeError, ValueError):
                    pass

    # If response is a string, try to parse it as JSON
    elif isinstance(response_to_check, str):
        try:
            response_to_check = json.loads(response_to_check)
        except (json.JSONDecodeError, ValueError):
            pass

    # Check for continuation_id in the response
    if isinstance(response_to_check, dict):
        # Look for continuation_offer structure
        continuation_offer = response_to_check.get("continuation_offer", {})
        if isinstance(continuation_offer, dict):
            continuation_id = continuation_offer.get("continuation_id", "")
            if continuation_id:
                return continuation_id

        # Also check direct continuation_id field
        continuation_id = response_to_check.get("continuation_id", "")
        if continuation_id:
            return continuation_id

    return ""


def collect_project_context_cached(session_id: str, cwd: str) -> Dict[str, Any]:
    """
    Collect comprehensive project context.

    Args:
        session_id: Current session identifier (for future use)
        cwd: Current working directory

    Returns:
        Dictionary containing project context information
    """
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
    config_files = project_context.get("config", {}).get("config_files", [])

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


def generate_zen_prompt_template(
    tool_name: str,
    recommendations: List[str],
    has_continuation: bool,
    continuation_id: str = "",
    project_context: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate contextualized prompt templates for ZEN tool usage with project context.

    Args:
        tool_name: Name of the tool that was used
        recommendations: List of MUST USE ZEN tools
        has_continuation: Whether session has existing continuation
        continuation_id: Existing continuation ID if available
        project_context: Project context for enhanced prompts

    Returns:
        Formatted prompt template with project context
    """
    if not recommendations:
        return ""

    template_parts = []

    # Header with context
    if has_continuation and continuation_id:
        template_parts.append(
            f"🔗 ⚠️⚡💥🚫❌☠️☢️☣️ mcp__zen_* CONTINUATION AVAILABLE!!! YOU PROACTIVELY MUST USE continuation_id='{continuation_id}' FOR CONTEXT CONTINUITY NOW!!! ⚠️⚡💥🚫❌☠️☢️☣️"
        )
    else:
        template_parts.append("🚀 ZEN WORKFLOW MUST USE for enhanced analysis:")

    # Add specific recommendations with context
    for i, rec in enumerate(recommendations, 1):
        template_parts.append(f"{i}. {rec}")

    # Add usage guidance
    template_parts.append("\n💡 USAGE PATTERN:")
    if has_continuation:
        template_parts.append(
            f"   Use: mcp__zen__[tool] with continuation_id='{continuation_id}'"
        )
    else:
        template_parts.append(
            "   Use: mcp__zen__[tool] for systematic multi-step analysis"
        )

    template_parts.append(
        "   Benefits: 200k token allowance + expert validation + structured workflow"
    )

    # Add project context insights to the template
    if project_context:
        context_insights = []

        # Add error context if present
        recent_errors = project_context.get("errors", {}).get("recent_errors", [])
        if recent_errors:
            context_insights.append(f"⚠️ {len(recent_errors)} recent errors detected")

        # Add framework context
        test_frameworks = project_context.get("tests", {}).get("frameworks", [])
        if test_frameworks:
            context_insights.append(f"🧪 Testing: {', '.join(test_frameworks[:2])}")

        # Add environment context
        python_version = project_context.get("environment", {}).get(
            "python_version", ""
        )
        venv_status = project_context.get("environment", {}).get("virtual_env", "")
        if python_version:
            env_info = f"🐍 Python {python_version}"
            if venv_status and venv_status != "none":
                env_info += f" ({venv_status})"
            elif venv_status == "none":
                env_info += " (⚠️ no venv)"
            context_insights.append(env_info)

        # Add dependency context
        dependencies = project_context.get("config", {}).get("dependencies", [])
        if dependencies:
            key_deps = [
                dep
                for dep in dependencies[:5]
                if dep.lower()
                in [
                    "flask",
                    "django",
                    "fastapi",
                    "requests",
                    "pandas",
                    "numpy",
                    "react",
                    "vue",
                    "angular",
                    "express",
                    "pytest",
                    "jest",
                ]
            ]
            if key_deps:
                context_insights.append(f"📦 Key deps: {', '.join(key_deps[:3])}")

        if context_insights:
            template_parts.append("\n🔍 PROJECT CONTEXT:")
            for insight in context_insights[:4]:  # Limit to 4 insights
                template_parts.append(f"   {insight}")

    return "\n".join(template_parts)


def store_continuation_id(session_id: str, continuation_id: str) -> None:
    """
    Store continuation_id for the current session.

    Args:
        session_id: Current session identifier
        continuation_id: Continuation ID to store
    """
    if session_id and continuation_id:
        state_manager.set_continuation_id(session_id, continuation_id)


def collect_comprehensive_analysis_data(
    tool_name: str,
    tool_input: Dict[str, Any],
    project_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Collect comprehensive analysis data for enhanced memory storage.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        project_context: Project context information

    Returns:
        Dictionary containing comprehensive analysis results
    """
    analysis_results = {}

    # Anti-pattern analysis for Python files
    if tool_name in ["Edit", "Write", "MultiEdit"]:
        file_paths = []
        if "file_path" in tool_input and tool_input["file_path"]:
            file_paths.append(tool_input["file_path"])

        python_files = [fp for fp in file_paths if fp.endswith(".py")]
        if python_files:
            try:
                detector = AntiPatternDetector()
                all_patterns = []

                for file_path in python_files:
                    # Get file content
                    file_content = None
                    if tool_name == "Write":
                        file_content = tool_input.get("content", "")
                    elif os.path.exists(file_path):
                        try:
                            with open(file_path, "r", encoding="utf-8") as f:
                                file_content = f.read()
                        except Exception:
                            continue

                    if file_content:
                        patterns = detector.detect_anti_patterns(
                            file_path, file_content
                        )
                        serialized_patterns = [
                            {
                                "pattern_name": p.pattern_name,
                                "description": p.description,
                                "severity": p.severity.name,
                                "line_number": p.line_number,
                                "suggestion": p.suggestion,
                                "file_path": p.file_path,
                            }
                            for p in patterns
                        ]
                        all_patterns.extend(serialized_patterns)

                analysis_results["anti_patterns"] = all_patterns

            except Exception:
                analysis_results["anti_patterns"] = []

    # Performance analysis for Python files
    if tool_name in ["Edit", "Write", "MultiEdit"]:
        try:
            import ast

            file_paths = []
            if "file_path" in tool_input and tool_input["file_path"]:
                file_paths.append(tool_input["file_path"])

            python_files = [fp for fp in file_paths if fp.endswith(".py")]
            if python_files:
                for file_path in python_files:
                    file_content = None
                    if tool_name == "Write":
                        file_content = tool_input.get("content", "")
                    elif os.path.exists(file_path):
                        try:
                            with open(file_path, "r", encoding="utf-8") as f:
                                file_content = f.read()
                        except Exception:
                            continue

                    if file_content:
                        try:
                            tree = ast.parse(file_content)
                            hotspots = detect_performance_hotspots_comprehensive(
                                file_path, tree, file_content
                            )
                            analysis_results["performance_metrics"] = hotspots
                            break  # Only analyze first file for now
                        except SyntaxError:
                            pass
        except Exception:
            pass

    # Project context integration
    if project_context:
        analysis_results["project_context"] = project_context

    # Tool context
    analysis_results["tool_context"] = {
        "tool_name": tool_name,
        "input_summary": create_tool_input_summary(tool_name, tool_input),
    }

    return analysis_results


# Alias for test compatibility
def collect_comprehensive_analysis(
    tool_name: str,
    tool_input: Dict[str, Any],
    project_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Alias for collect_comprehensive_analysis_data for test compatibility."""
    return collect_comprehensive_analysis_data(tool_name, tool_input, project_context)


def create_tool_input_summary(tool_name: str, tool_input: Dict[str, Any]) -> str:
    """Create concise summary of tool input for memory storage."""
    if tool_name == "Bash":
        return truncate_for_preview(tool_input.get("command", ""), 100)
    elif tool_name in ["Edit", "MultiEdit", "Write"]:
        file_path = tool_input.get("file_path", "")
        if file_path:
            return f"File: {file_path}"
    elif tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        if file_path:
            return f"Read: {file_path}"

    return f"{tool_name} operation"


def calculate_composite_risk_score(analysis_results: Dict[str, Any]) -> float:
    """Calculate composite risk score from analysis results."""
    risk_score = 0.0

    # Anti-pattern risk scoring
    anti_patterns = analysis_results.get("anti_patterns", [])
    for pattern in anti_patterns:
        severity = pattern.get("severity", "LOW")
        if severity == "CRITICAL":
            risk_score += 0.3
        elif severity == "HIGH":
            risk_score += 0.2
        elif severity == "MEDIUM":
            risk_score += 0.1
        elif severity == "LOW":
            risk_score += 0.05

    # Performance risk scoring
    performance_metrics = analysis_results.get("performance_metrics", {})
    perf_risk_level = performance_metrics.get("risk_level", "minimal")
    if perf_risk_level == "critical":
        risk_score += 0.4
    elif perf_risk_level == "high":
        risk_score += 0.3
    elif perf_risk_level == "medium":
        risk_score += 0.2
    elif perf_risk_level == "low":
        risk_score += 0.1

    # Project context risk factors
    project_context = analysis_results.get("project_context", {})
    recent_errors = project_context.get("errors", {}).get("recent_errors", [])
    if len(recent_errors) >= 3:
        risk_score += 0.2

    # Virtual environment risk
    venv_status = project_context.get("environment", {}).get("virtual_env", "")
    if venv_status == "none":
        risk_score += 0.1

    # Cap at 1.0
    return min(risk_score, 1.0)


def classify_memory_type_from_analysis(analysis_results: Dict[str, Any]) -> MemoryType:
    """Determine appropriate memory type based on analysis findings."""
    # Check for critical anti-patterns first
    anti_patterns = analysis_results.get("anti_patterns", [])
    for pattern in anti_patterns:
        if pattern.get("severity") == "CRITICAL":
            category = pattern.get("pattern_name", "").lower()
            if (
                "security" in category
                or "credential" in category
                or "injection" in category
            ):
                return MemoryType.SECURITY_ANALYSIS
            else:
                return MemoryType.ANTI_PATTERNS

    # Check for performance issues
    performance_metrics = analysis_results.get("performance_metrics", {})
    if performance_metrics.get("risk_level") in ["critical", "high"]:
        return MemoryType.PERFORMANCE_ANALYSIS

    # Check for high-risk anti-patterns
    high_risk_patterns = [p for p in anti_patterns if p.get("severity") == "HIGH"]
    if high_risk_patterns:
        return MemoryType.ANTI_PATTERNS

    # Check for architecture/code quality issues
    if any("architecture" in p.get("pattern_name", "").lower() for p in anti_patterns):
        return MemoryType.ARCHITECTURE_PATTERNS

    if any("quality" in p.get("pattern_name", "").lower() for p in anti_patterns):
        return MemoryType.CODE_QUALITY

    # Project context classification
    project_context = analysis_results.get("project_context", {})
    recent_errors = project_context.get("errors", {}).get("recent_errors", [])
    if len(recent_errors) >= 2:
        return MemoryType.ERRORS

    # Default to tool patterns
    return MemoryType.TOOL_PATTERNS


def create_enhanced_tags(
    project_context: Optional[Dict[str, Any]],
    analysis_results: Dict[str, Any],
    tool_name: str,
) -> List[str]:
    """Create enhanced tags based on context and analysis."""
    tags = [tool_name]  # Keep original case for tool name

    # Add anti-pattern tags
    anti_patterns = analysis_results.get("anti_patterns", [])
    if anti_patterns:
        tags.append("anti_patterns_detected")
    for pattern in anti_patterns:
        severity = pattern.get("severity", "LOW")
        pattern_name = pattern.get("pattern_name", "").lower()
        tags.extend([f"antipattern_{pattern_name}", f"severity_{severity.lower()}"])

    # Add performance tags
    performance_metrics = analysis_results.get("performance_metrics", {})
    risk_level = performance_metrics.get("risk_level", "minimal")
    if risk_level != "minimal":
        tags.append(f"performance_{risk_level}")

    # Add nested loop tags
    nested_loops = performance_metrics.get("nested_loops", [])
    if nested_loops:
        tags.append("nested_loops")
        for loop in nested_loops:
            if loop.get("severity") in ["high", "critical"]:
                tags.append("complexity_critical")
                break

    # Add framework tags from project context
    if project_context:
        dependencies = project_context.get("config", {}).get("dependencies", [])
        test_frameworks = project_context.get("tests", {}).get("frameworks", [])

        # Add key framework tags
        key_frameworks = [
            "flask",
            "django",
            "fastapi",
            "pytest",
            "jest",
            "react",
            "vue",
        ]
        for framework in key_frameworks:
            if framework in dependencies or framework in test_frameworks:
                tags.append(f"framework_{framework}")
                # Also add plain framework name for compatibility
                tags.append(framework)

        # Add dependency tags directly for more comprehensive tagging
        for dep in dependencies:
            tags.append(dep.lower())

        # Add Python version tag (more specific for better matching)
        python_version = project_context.get("environment", {}).get(
            "python_version", ""
        )
        if python_version:
            # Use full major.minor version for better specificity
            if "." in python_version:
                major_minor = ".".join(python_version.split(".")[:2])
                tags.append(f"python{major_minor}")
            else:
                tags.append(f"python{python_version}")

        # Add error context tags
        recent_errors = project_context.get("errors", {}).get("recent_errors", [])
        if recent_errors:
            tags.append(f"errors_{len(recent_errors)}")
            if len(recent_errors) >= 3:
                tags.append("error_critical")

    # Remove duplicates and limit to most relevant
    unique_tags = list(dict.fromkeys(tags))  # Preserves order
    return unique_tags[:15]  # Limit to prevent tag explosion


def calculate_enhanced_relevance_score(
    analysis_results: Dict[str, Any], context_tags: List[str]
) -> float:
    """Calculate enhanced relevance score based on analysis findings."""
    # Start with a lower base relevance to allow differentiation
    base_relevance = 0.3

    # Check if context tags indicate high-impact or low-impact scenarios
    high_impact_tags = {
        "security",
        "performance",
        "critical",
        "error",
        "vulnerability",
        "injection",
    }
    low_impact_tags = {"documentation", "formatting", "style", "comment", "whitespace"}

    context_tag_set = set(tag.lower() for tag in context_tags)
    has_high_impact = bool(context_tag_set.intersection(high_impact_tags))
    has_low_impact = (
        bool(context_tag_set.intersection(low_impact_tags)) and not has_high_impact
    )

    # Adjust base score based on tag types
    if has_low_impact:
        base_relevance = 0.2  # Start lower for low-impact scenarios
    elif has_high_impact:
        base_relevance = 0.4  # Start higher for high-impact scenarios

    # Boost for critical issues (reduced for low-impact scenarios)
    anti_patterns = analysis_results.get("anti_patterns", [])
    critical_patterns = [p for p in anti_patterns if p.get("severity") == "CRITICAL"]
    high_patterns = [p for p in anti_patterns if p.get("severity") == "HIGH"]

    # Apply impact multiplier to anti-pattern scoring
    impact_multiplier = 0.3 if has_low_impact else 1.0

    if critical_patterns:
        base_relevance += 0.4 * impact_multiplier
    elif high_patterns:
        base_relevance += 0.3 * impact_multiplier
    elif anti_patterns:
        base_relevance += 0.15 * impact_multiplier

    # Performance relevance boost (reduced for low-impact scenarios)
    performance_metrics = analysis_results.get("performance_metrics", {})
    risk_level = performance_metrics.get("risk_level", "minimal")
    if risk_level == "critical":
        base_relevance += 0.3 * impact_multiplier
    elif risk_level == "high":
        base_relevance += 0.25 * impact_multiplier
    elif risk_level == "medium":
        base_relevance += 0.1 * impact_multiplier

    # Context richness boost (smaller for low-impact tags)
    richness_multiplier = 0.5 if has_low_impact else 1.0
    if len(context_tags) > 10:
        base_relevance += 0.1 * richness_multiplier
    elif len(context_tags) > 5:
        base_relevance += 0.05 * richness_multiplier

    # Project context boost
    project_context = analysis_results.get("project_context", {})
    if project_context and project_context.get("errors", {}).get("recent_errors", []):
        base_relevance += 0.1

    return min(base_relevance, 1.0)


def extract_file_paths(tool_input: Dict[str, Any]) -> List[str]:
    """Extract file paths from tool input."""
    file_paths = []

    # Common file path keys
    for key in ["file_path", "path", "filepath"]:
        if key in tool_input and tool_input[key]:
            file_paths.append(str(tool_input[key]))

    # Handle additional_paths for test compatibility
    if "additional_paths" in tool_input and isinstance(
        tool_input["additional_paths"], list
    ):
        for path in tool_input["additional_paths"]:
            if path:
                file_paths.append(str(path))

    # Handle 'args' structure for some tools
    if "args" in tool_input and isinstance(tool_input["args"], list):
        for item in tool_input["args"]:
            if isinstance(item, dict) and "path" in item:
                file_paths.append(str(item["path"]))

    return file_paths


def classify_operation_type(tool_name: str, tool_input: Dict[str, Any]) -> str:
    """Classify the type of operation based on tool and input."""
    if tool_name == "Bash":
        command = tool_input.get("command", "").lower()
        if any(cmd in command for cmd in ["git", "commit", "push", "pull"]):
            return "version_control"
        elif any(cmd in command for cmd in ["test", "pytest", "jest"]):
            return "testing"
        elif any(cmd in command for cmd in ["build", "compile", "deploy"]):
            return "build_deploy"
        else:
            return "system_command"
    elif tool_name in ["Edit", "MultiEdit"]:
        return "code_modification"
    elif tool_name == "Write":
        return "file_write"
    elif tool_name == "Read":
        return "file_read"
    elif tool_name in ["Grep", "Find"]:
        return "code_search"
    else:
        return "general_operation"


def calculate_complexity_score(analysis_results: Dict[str, Any]) -> float:
    """Calculate complexity score based on analysis findings."""
    complexity = 0.0

    # Anti-pattern complexity
    anti_patterns = analysis_results.get("anti_patterns", [])
    complexity += len(anti_patterns) * 0.1

    # Performance complexity with detailed analysis
    performance_metrics = analysis_results.get("performance_metrics", {})
    nested_loops = performance_metrics.get("nested_loops", [])
    high_complexity_funcs = performance_metrics.get("high_complexity_functions", [])
    memory_ops = performance_metrics.get("memory_intensive", [])

    # More sophisticated complexity calculation
    for loop in nested_loops:
        depth = loop.get("depth", 1)
        complexity += depth * 0.15  # More weight for deeper nesting

    for func in high_complexity_funcs:
        func_complexity = func.get("complexity", 0)
        if func_complexity > 20:
            complexity += 0.25
        elif func_complexity > 15:
            complexity += 0.2
        else:
            complexity += 0.1

    complexity += len(memory_ops) * 0.1

    # Project context complexity
    project_context = analysis_results.get("project_context", {})
    dependencies = len(project_context.get("config", {}).get("dependencies", []))
    complexity += min(dependencies * 0.01, 0.2)  # Cap dependency complexity

    return min(complexity, 1.0)


def calculate_recommendation_confidence(
    recommendations: List[str], analysis_results: Dict[str, Any]
) -> float:
    """Calculate confidence in recommendations based on analysis depth."""
    if not recommendations:
        return 0.0

    # Start with lower base confidence
    confidence = 0.4

    # Boost for evidence-based recommendations
    anti_patterns = analysis_results.get("anti_patterns", [])
    performance_metrics = analysis_results.get("performance_metrics", {})

    # More conservative scoring
    if anti_patterns:
        # Scale confidence based on severity of patterns
        critical_patterns = sum(
            1 for p in anti_patterns if p.get("severity") == "CRITICAL"
        )
        high_patterns = sum(1 for p in anti_patterns if p.get("severity") == "HIGH")

        if critical_patterns > 0:
            confidence += 0.3
        elif high_patterns > 0:
            confidence += 0.2
        else:
            confidence += 0.1

    if performance_metrics and performance_metrics.get("risk_level") != "minimal":
        risk_level = performance_metrics.get("risk_level", "minimal")
        if risk_level == "critical":
            confidence += 0.25
        elif risk_level == "high":
            confidence += 0.2
        else:
            confidence += 0.1

    # Boost for multiple types of analysis (but more conservative)
    analysis_types = 0
    if anti_patterns:
        analysis_types += 1
    if performance_metrics:
        analysis_types += 1
    if analysis_results.get("project_context"):
        analysis_types += 1

    confidence += analysis_types * 0.03

    # Penalty for weak recommendations (shorter recommendations may be less specific)
    if recommendations and len(" ".join(recommendations)) < 20:
        confidence -= 0.1

    return min(max(confidence, 0.0), 1.0)


def save_tool_pattern_to_memory(
    tool_name: str,
    tool_input: Dict[str, Any],
    session_id: str,
    recommendations: List[str],
    project_context: Optional[Dict[str, Any]] = None,
    cwd: Optional[str] = None,
) -> str:
    """
    Save tool usage patterns to memory with enhanced analysis integration.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        session_id: Current session identifier
        recommendations: ZEN tool recommendations generated
        project_context: Project context for richer memory storage
    """
    try:
        # Collect comprehensive analysis data
        analysis_results = collect_comprehensive_analysis_data(
            tool_name, tool_input, project_context
        )

        # Create enhanced pattern summary
        pattern_content = f"Tool: {tool_name}"

        # Add key input details
        input_summary = create_tool_input_summary(tool_name, tool_input)
        if input_summary != f"{tool_name} operation":
            pattern_content += f", {input_summary}"

        # Add recommendations if any
        if recommendations:
            pattern_content += f", Recommended: {recommendations[0]}"

        # Add analysis findings summary
        anti_patterns = analysis_results.get("anti_patterns", [])
        if anti_patterns:
            critical_count = sum(
                1 for p in anti_patterns if p.get("severity") == "CRITICAL"
            )
            high_count = sum(1 for p in anti_patterns if p.get("severity") == "HIGH")
            if critical_count > 0:
                pattern_content += (
                    f", CRITICAL: {critical_count} critical anti-patterns detected"
                )
            elif high_count > 0:
                pattern_content += f", HIGH: {high_count} high-risk patterns detected"

        performance_metrics = analysis_results.get("performance_metrics", {})
        risk_level = performance_metrics.get("risk_level", "minimal")
        if risk_level in ["critical", "high"]:
            pattern_content += f", Performance: {risk_level} risk detected"

        # Calculate risk score for enhanced relevance
        risk_score = calculate_composite_risk_score(analysis_results)

        # Determine appropriate memory type based on findings
        memory_type = classify_memory_type_from_analysis(analysis_results)

        # Enhanced tagging with analysis context
        context_tags = create_enhanced_tags(
            project_context, analysis_results, tool_name
        )

        # Calculate enhanced relevance score
        relevance = calculate_enhanced_relevance_score(analysis_results, context_tags)

        # Create enhanced metadata
        enhanced_metadata = {
            "tool_context": {
                "tool_name": tool_name,
                "file_paths": extract_file_paths(tool_input),
                "operation_type": classify_operation_type(tool_name, tool_input),
            },
            "risk_score": risk_score,
            "complexity_score": calculate_complexity_score(analysis_results),
            "recommendation_confidence": calculate_recommendation_confidence(
                recommendations, analysis_results
            ),
        }

        # Save to enhanced memory system
        memory_id = memory_manager.save_enhanced_memory(
            content=pattern_content,
            memory_type=memory_type,
            session_id=session_id,
            relevance_score=relevance,
            tags=context_tags,
            analysis_data=analysis_results,
            metadata=enhanced_metadata,
            risk_score=risk_score,
            cwd=cwd,
        )

        return memory_id

    except Exception:
        # Silent fail - don't break workflow if memory save fails
        return ""


def check_relevant_memories_notification(
    tool_name: str, tool_input: Dict[str, Any], session_id: str
) -> str:
    """
    Check if there are relevant memories that Claude should know about.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        session_id: Current session identifier

    Returns:
        Notification message if relevant memories found, empty string otherwise
    """
    try:
        # Create search context from tool usage
        search_context = f"{tool_name}"

        if tool_name == "Bash":
            command = tool_input.get("command", "")
            search_context += f" {command}"
        elif tool_name in ["Edit", "Write", "Read"]:
            file_path = tool_input.get("file_path", "")
            if file_path:
                search_context += f" {file_path}"

        # Look for relevant memories
        memories = memory_manager.get_relevant_memories(
            context=search_context, session_id=session_id, limit=3, min_relevance=0.6
        )

        if memories:
            memory_count = len(memories)
            highest_relevance = max(m.get("combined_relevance", 0) for m in memories)

            return f"📝 RELEVANT MEMORIES: Found {memory_count} related memories (max relevance: {highest_relevance:.2f}) - consider using mcp__zen tools for enhanced context"

        return ""

    except Exception:
        return ""


def sanitize_input(input_data: Dict[str, Any]) -> bool:
    """
    Sanitize and validate input data according to security requirements.

    Args:
        input_data: Hook event data

    Returns:
        True if input is safe, False otherwise
    """
    # Check for required fields
    required_fields = ["session_id", "transcript_path", "cwd", "hook_event_name"]
    for field in required_fields:
        if field not in input_data:
            return False

    # Validate paths for traversal attacks
    transcript_path = input_data.get("transcript_path", "")
    cwd = input_data.get("cwd", "")

    if ".." in transcript_path or ".." in cwd:
        print("Security: Path traversal blocked", file=sys.stderr)
        return False

    # Skip if no tool information
    if not input_data.get("tool_name", ""):
        return False

    return True


def classify_recommendation_severity(
    zen_recommendations: List[str],
    tool_name: str,
    tool_input: Dict[str, Any],
    cwd: str,
    project_context: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Classify the severity of ZEN recommendations based on detected issues.

    Args:
        zen_recommendations: List of ZEN tool recommendations
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        cwd: Current working directory
        project_context: Project context information

    Returns:
        Severity level: 'critical', 'high', 'medium', 'low'
    """
    if not zen_recommendations:
        return "low"

    # Check for critical security/anti-pattern indicators
    critical_patterns = [
        "CRITICAL:",
        "security",
        "secaudit",
        "hardcoded",
        "credentials",
        "injection",
        "vulnerability",
    ]

    high_patterns = [
        "debug",
        "performance",
        "O(n²)",
        "O(n³)",
        "nested loop",
        "sync I/O",
        "architecture",
        "violation",
    ]

    # Check recommendation content for severity indicators
    all_recs = " ".join(zen_recommendations).lower()

    # CRITICAL: Security/anti-pattern issues or explicit critical markers
    if any(pattern in all_recs for pattern in critical_patterns):
        return "critical"

    # Check for critical error context
    if project_context:
        recent_errors = project_context.get("errors", {}).get("recent_errors", [])
        if len(recent_errors) >= 3:
            return "critical"

    # HIGH: Performance issues or architecture violations
    if any(pattern in all_recs for pattern in high_patterns):
        return "high"

    # Check for Python file operations (potential for anti-patterns/performance issues)
    if tool_name in ["Edit", "Write", "MultiEdit"]:
        file_paths = []
        if "file_path" in tool_input and tool_input["file_path"]:
            file_paths.append(tool_input["file_path"])

        python_files = [fp for fp in file_paths if fp.endswith(".py")]
        if python_files:
            # Check for actual anti-patterns or performance issues
            try:
                from hook_tools.anti_patterns_detector import (
                    AntiPatternDetector,
                    Severity,
                )
                from hook_tools.analysis.performance_analyzer import (
                    detect_performance_hotspots_comprehensive,
                )
                import ast

                for file_path in python_files:
                    # Get file content
                    file_content = None
                    if tool_name == "Write":
                        file_content = tool_input.get("content", "")
                    elif os.path.exists(file_path):
                        try:
                            with open(file_path, "r", encoding="utf-8") as f:
                                file_content = f.read()
                        except Exception:
                            continue

                    if not file_content:
                        continue

                    # Check for critical anti-patterns
                    detector = AntiPatternDetector()
                    patterns = detector.detect_anti_patterns(file_path, file_content)
                    critical_patterns = [
                        p for p in patterns if p.severity == Severity.CRITICAL
                    ]
                    if critical_patterns:
                        return "critical"

                    high_patterns = [p for p in patterns if p.severity == Severity.HIGH]
                    if high_patterns:
                        return "high"

                    # Check for critical performance issues
                    try:
                        tree = ast.parse(file_content)
                        hotspots = detect_performance_hotspots_comprehensive(
                            file_path, tree, file_content
                        )
                        risk_level = hotspots.get("risk_level", "minimal")
                        if risk_level == "critical":
                            return "critical"
                        elif risk_level == "high":
                            return "high"
                    except SyntaxError:
                        pass  # Skip files with syntax errors

            except Exception:
                pass  # Don't block if analysis fails

    # MEDIUM: Multi-file operations or complex patterns
    if tool_name == "MultiEdit" and tool_input.get("edits", []):
        if len(tool_input.get("edits", [])) >= 5:
            return "high"
        elif len(tool_input.get("edits", [])) >= 3:
            return "medium"

    # Default to medium for pattern-based recommendations
    return "medium"


def should_trigger_python_fixer(tool_name: str, tool_input: Dict[str, Any]) -> bool:
    """
    Determine if python_auto_fixer should be triggered.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool

    Returns:
        True if python fixer should run, False otherwise
    """
    # Only trigger for file modification tools
    file_tools = [
        "Write",
        "Edit",
        "MultiEdit",
        "write_to_file",
        "apply_diff",
        "insert_content",
    ]
    if tool_name not in file_tools:
        return False

    # Check if any Python files are involved
    file_paths = []

    # Extract file paths from various tool input formats
    for key in ["file_path", "path", "filepath"]:
        if key in tool_input and tool_input[key]:
            file_paths.append(tool_input[key])

    # Handle 'args' structure (used by apply_diff and other tools)
    if "args" in tool_input and isinstance(tool_input["args"], list):
        for item in tool_input["args"]:
            if isinstance(item, dict) and "path" in item:
                file_paths.append(item["path"])

    # Check if any path is a Python file
    for file_path in file_paths:
        if isinstance(file_path, str) and file_path.endswith(".py"):
            # Skip hook files and test files to avoid infinite loops
            skip_patterns = [
                "hook_handlers",
                "hook_tools",
                "test_",
                "_test.py",
                "__pycache__",
            ]
            if not any(pattern in file_path.lower() for pattern in skip_patterns):
                return True

    return False


def extract_todo_content(tool_input: Dict[str, Any]) -> str:
    """Extract todo content from TodoWrite tool input."""
    todos = tool_input.get("todos", [])
    if not todos:
        return ""

    content_parts = []
    for todo in todos:
        if isinstance(todo, dict) and "content" in todo:
            content_parts.append(todo["content"])

    return " ".join(content_parts).lower()


def get_agent_info(agents_dir: str) -> List[Tuple[str, str, str]]:
    """Read agent files and extract name, description, and keywords.

    Returns:
        List of (filename, description, content) tuples
    """
    agents = []
    if not os.path.exists(agents_dir):
        return agents

    for filename in os.listdir(agents_dir):
        if filename.endswith(".md"):
            filepath = os.path.join(agents_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    # Extract first line as description (usually the title/summary)
                    lines = content.split("\n")
                    description = lines[0] if lines else filename
                    # Clean up markdown title formatting
                    description = re.sub(r"^#+\s*", "", description)
                    agents.append((filename, description, content.lower()))
            except Exception:
                continue

    return agents


def analyze_bash_command(command: str) -> List[Tuple[str, str, str]]:
    """Analyze bash command and suggest modern alternatives.

    Returns:
        List of (old_tool, modern_tool, reason) tuples
    """
    suggestions = []
    command_lower = command.lower()

    # Modern CLI tool mappings from CLAUDE.md CLI_CONTRACT
    replacements = {
        "grep": ("rg", "ripgrep is 10x faster with better defaults and colored output"),
        "find": ("fd", "fd is faster with intuitive syntax and respects .gitignore"),
        "ls": ("lsd", "lsd provides beautiful colored output with icons"),
        "sed": ("sd", "sd has simpler regex syntax and better error messages"),
        "du": ("dust", "dust shows disk usage with visual tree and faster scanning"),
        "df": ("duf", "duf displays disk usage with colors and human-readable format"),
        "ps": ("procs", "procs shows processes with colors and additional info"),
        "curl": ("xh", "xh has simpler syntax and JSON support built-in"),
        "dig": ("dog", "dog provides colored output and modern DNS lookups"),
        "diff": (
            "delta",
            "delta shows beautiful side-by-side diffs with syntax highlighting",
        ),
    }

    # Check for each old tool in the command
    for old_tool, (new_tool, reason) in replacements.items():
        # Look for the tool as a standalone command (not as part of another word)
        pattern = r"\b" + re.escape(old_tool) + r"\b"
        if re.search(pattern, command_lower):
            suggestions.append((old_tool, new_tool, reason))

    return suggestions


def analyze_and_recommend_agents(todo_content: str, cwd: str) -> List[str]:
    """Analyze todo content and recommend relevant agents.

    Returns:
        List of agent recommendations with descriptions
    """
    if not todo_content:
        # Fallback to generic project management agents
        return [
            "project-orchestrator.md - Complex multi-phase projects",
            "project-planner.md - Comprehensive project planning",
            "task-dispatch-director.md - Task coordination",
        ]

    agents_dir = os.path.join(cwd, ".claude", "agents")
    agents = get_agent_info(agents_dir)

    # Define keyword patterns for different types of work
    patterns = {
        "backend": r"\b(api|server|database|backend|rest|graphql|microservice|endpoint)\b",
        "frontend": r"\b(ui|frontend|react|vue|angular|component|styling|css|tailwind|scss)\b",
        "testing": r"\b(test|testing|unit|integration|e2e|pytest|jest|cypress|spec)\b",
        "devops": r"\b(deploy|docker|kubernetes|ci/cd|pipeline|build|infrastructure)\b",
        "database": r"\b(database|sql|postgres|mysql|mongodb|migration|schema|query)\b",
        "security": r"\b(security|auth|oauth|jwt|encryption|vulnerability|audit)\b",
        "mobile": r"\b(mobile|ios|android|react native|flutter|app)\b",
        "documentation": r"\b(doc|documentation|readme|guide|manual|wiki)\b",
        "performance": r"\b(performance|optimize|speed|benchmark|profiling|memory)\b",
        "refactor": r"\b(refactor|clean|improve|restructure|organize|simplify)\b",
    }

    # Score agents based on keyword matches
    scored_agents = []
    for filename, description, content in agents:
        score = 0
        matched_categories = []

        # Check if todo content keywords match agent content
        for category, pattern in patterns.items():
            if re.search(pattern, todo_content) and re.search(pattern, content):
                score += 2
                matched_categories.append(category)

        # Boost score for exact keyword matches in agent filename/description
        for word in todo_content.split():
            if len(word) > 3:  # Skip short words
                if word in filename.lower() or word in description.lower():
                    score += 1

        if score > 0:
            scored_agents.append((score, filename, description, matched_categories))

    # Sort by score and return top recommendations
    scored_agents.sort(key=lambda x: x[0], reverse=True)

    recommendations = []
    for score, filename, description, categories in scored_agents[:5]:
        cat_hint = f"({', '.join(categories)})" if categories else ""
        recommendations.append(f"{filename} - {description} {cat_hint}")

    # If no good matches, fall back to generic agents
    if not recommendations:
        recommendations = [
            "project-orchestrator.md - Complex multi-phase projects",
            "project-planner.md - Comprehensive project planning",
            "workflow-agent.md - Universal workflow orchestration",
        ]

    return recommendations[:5]  # Limit to 5 recommendations


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
                if logger.should_print_error(f"ANTI_PATTERN_CRITICAL_{file_path}"):
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
                    if logger.should_print_error(f"PERFORMANCE_HOTSPOT_{file_path}"):
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


def run_python_auto_fixer(tool_name: str, tool_input: Dict[str, Any], cwd: str) -> None:
    """
    Execute the python_auto_fixer.py script.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        cwd: Current working directory
    """
    try:
        # Import the fixer module using modern importlib approach
        import importlib.util
        import subprocess

        fixer_path = os.path.join(
            os.path.dirname(__file__), "..", "hook_tools", "python_auto_fixer.py"
        )

        if os.path.exists(fixer_path):
            try:
                # Load module dynamically using importlib.util
                spec = importlib.util.spec_from_file_location(
                    "python_auto_fixer", fixer_path
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    # Call the run_auto_fixer function
                    if hasattr(module, "run_auto_fixer"):
                        module.run_auto_fixer(tool_name, tool_input, cwd)
                    else:
                        raise AttributeError(
                            "run_auto_fixer function not found in module"
                        )
                else:
                    raise ImportError("Could not create module spec")

            except (ImportError, AttributeError):
                # Fallback to subprocess if import fails
                subprocess.Popen(
                    [
                        sys.executable,
                        fixer_path,
                        tool_name,
                        json.dumps(tool_input),
                        cwd,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                    cwd=cwd,
                )

    except Exception:
        # Silent fail - don't block the main workflow
        pass


def handle(input_data: Dict[str, Any]) -> None:
    """Handler function called by hook router."""
    # Validate input data
    if not sanitize_input(input_data):
        sys.exit(1)

    try:
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {})
        tool_response = input_data.get(
            "tool_response", {}
        )  # Fixed: PostToolUse receives tool_response, not tool_output
        session_id = input_data.get("session_id", "")
        cwd = input_data.get("cwd", "")

        # Detect if this is a Task tool (subagent) - these need special handling for parallel execution
        is_task_tool = tool_name == "Task"

        # Debug: Log ALL tools to see what's happening
        with open("/tmp/posttooluse_debug.log", "a") as f:
            f.write(f"\n[{datetime.now().isoformat()}] Tool: {tool_name}\n")
            f.write(f"Session: {session_id}\n")
            f.write(f"Response type: {type(tool_response)}\n")
            if isinstance(tool_response, dict):
                f.write(f"Response keys: {tool_response.keys()}\n")
                if tool_name.startswith("mcp__zen__"):
                    f.write(f"Full response: {tool_response}\n")
            elif isinstance(tool_response, list):
                f.write(f"List length: {len(tool_response)}\n")
                if tool_name.startswith("mcp__zen__") and len(tool_response) > 0:
                    f.write(f"First item type: {type(tool_response[0])}\n")
                    f.write(
                        f"First item: {tool_response[0][:500] if isinstance(tool_response[0], str) else tool_response[0]}\n"
                    )

        # Extract and store continuation_id from mcp__zen tools
        continuation_id = extract_continuation_id(tool_name, tool_input, tool_response)
        if continuation_id:
            store_continuation_id(session_id, continuation_id)
            # Debug: Log when continuation_id is found and stored
            print(
                f"DEBUG: Stored continuation_id '{continuation_id}' for session '{session_id}'",
                file=sys.stderr,
            )
        elif tool_name.startswith("mcp__zen__"):
            # Debug: Log when mcp__zen tool doesn't have continuation_id
            print(
                f"DEBUG: No continuation_id found in {tool_name} response: {tool_response}",
                file=sys.stderr,
            )

        # Check for Bash commands and provide modern CLI recommendations (non-blocking for Task tools)
        if tool_name == "Bash" and not is_task_tool:
            command = tool_input.get("command", "")
            if command:
                suggestions = analyze_bash_command(command)
                if suggestions:
                    for old_tool, new_tool, reason in suggestions:
                        error_msg = (
                            f"⚡💥 YOU MUST USE {new_tool} INSTEAD OF {old_tool}! 🚫❌"
                        )
                        if logger.should_print_error("MODERN_CLI_TOOL_RECOMMENDATION"):
                            print(error_msg, file=sys.stderr)
                            sys.exit(2)

        # Check for TodoWrite usage and recommend agents instead (skip for Task tools to avoid breaking parallel execution)
        if tool_name == "TodoWrite" and not is_task_tool:
            error_msg = "🔥⚡ VERY IMPORTANT: YOU ABSOLUTELY **MUST** HIRE AN AGENT **OR AGENTS FOR INDEPENDENT PARALLEL/BATCH TASK ITEMS** TO COMPLETE THIS CORRECTLY. PARALLELIZE HIRES (PER CLAUDE.md PATTERN_CONTRACT LAWS D2-D6)!!! 💥🚫"
            if logger.should_print_error(error_msg):
                print(error_msg, file=sys.stderr)
                sys.exit(2)

        # Run anti-pattern detection for Python file operations (skip for Task tools to avoid breaking parallel execution)
        if not is_task_tool:
            detect_anti_patterns_for_file_operation(tool_name, tool_input, cwd)
            # Note: Performance hotspot detection is integrated into ZEN recommendations via detect_zen_usage_patterns

        # Conditionally output ZEN recommendations based on patterns and frequency
        if not tool_name.startswith("mcp__zen__"):  # Don't suggest ZEN for ZEN tools
            # Check if session has existing continuation
            existing_continuation_id = (
                state_manager.get_continuation_id(session_id) or ""
            )
            has_continuation = bool(existing_continuation_id)

            # Collect project context for enhanced recommendations
            project_context = collect_project_context_cached(session_id, cwd)

            # Detect patterns for enhanced recommendations with context
            zen_recommendations = detect_zen_usage_patterns(
                tool_name, tool_input, session_id, cwd, project_context
            )

            # Save tool patterns to memory with enhanced context
            save_tool_pattern_to_memory(
                tool_name, tool_input, session_id, zen_recommendations, project_context
            )

            # Track tool use count for this session (stored in state manager)
            tool_count = state_manager.increment_tool_count(session_id)

            # Determine if we should show ZEN recommendations using severity-weighted logic
            should_show_zen = False
            severity = "low"

            # Classify severity of any recommendations
            if zen_recommendations:
                severity = classify_recommendation_severity(
                    zen_recommendations, tool_name, tool_input, cwd, project_context
                )

            # Apply severity-weighted triggering logic using configurable thresholds
            config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["low"])

            # CRITICAL SEVERITY: Always trigger immediately
            if severity == "critical" and tool_count % config["frequency"] == 0:
                should_show_zen = True

            # HIGH SEVERITY: Trigger on reduced frequency
            elif severity == "high" and tool_count % config["frequency"] == 0:
                should_show_zen = True

            # Pattern-based recommendations at medium/high severity
            elif zen_recommendations and severity in ["high", "medium"]:
                should_show_zen = True

            # High-priority tools that traditionally always trigger
            elif tool_name in [
                "Task",
                "Bash",
                "Grep",
                "Edit",
                "MultiEdit",
                "TodoWrite",
            ]:
                should_show_zen = True

            # MEDIUM SEVERITY: Use continuation-aware frequency
            elif severity == "medium":
                if (
                    has_continuation
                    and tool_count % config.get("frequency_with_continuation", 3) == 0
                ):
                    should_show_zen = True
                elif tool_count % config.get("frequency_without_continuation", 5) == 0:
                    should_show_zen = True

            # LOW SEVERITY: Use configured reduced frequency
            elif severity == "low" and tool_count % config["frequency"] == 0:
                should_show_zen = True

            # Multi-file operations trigger based on complexity
            if tool_name == "MultiEdit" and tool_input.get("edits", []):
                edit_count = len(tool_input.get("edits", []))
                if edit_count >= 5:  # High complexity
                    should_show_zen = True
                elif edit_count >= 3 and tool_count % 2 == 0:  # Medium complexity
                    should_show_zen = True

            # Check for relevant memories notification
            memory_notification = check_relevant_memories_notification(
                tool_name, tool_input, session_id
            )

            if should_show_zen or memory_notification:
                # Generate base continuation message
                if has_continuation:
                    base_message = f"🔗 ZEN CONTINUATION AVAILABLE: Use continuation_id='{existing_continuation_id}' with mcp__zen__* tools for context continuity"
                else:
                    base_message = "🚀 ZEN WORKFLOW MUST USE: Start with mcp__zen__* tools for enhanced analysis (200k token allowance + expert validation)"

                # Add pattern-based recommendations if available
                if zen_recommendations:
                    zen_prompt = generate_zen_prompt_template(
                        tool_name,
                        zen_recommendations,
                        has_continuation,
                        existing_continuation_id,
                        project_context,
                    )
                    if zen_prompt:
                        final_message = f"{base_message}\n\n{zen_prompt}"
                    else:
                        final_message = base_message
                else:
                    final_message = base_message

                # Add memory notification if available
                if memory_notification:
                    final_message = f"{final_message}\n\n{memory_notification}"

                # Apply severity-weighted rate limiting based on configuration
                severity_config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["low"])
                rate_limit_key = f"ZEN_CONTINUATION_AVAILABLE_{severity.upper()}"

                # Check if this severity bypasses rate limiting
                should_print = severity_config.get(
                    "bypass_rate_limit", False
                ) or logger.should_print_error(rate_limit_key)

                if should_print:
                    # Skip sys.exit(2) for Task tools to avoid breaking parallel execution
                    if not is_task_tool:
                        # Output the message using exit code 2 so Claude sees it
                        print(f"\n{final_message}", file=sys.stderr)
                        sys.exit(2)
                    else:
                        # For Task tools, just print to stderr without exiting
                        print(f"\n{final_message}", file=sys.stderr)

        # Check if we should trigger the Python auto-fixer
        if should_trigger_python_fixer(tool_name, tool_input):
            run_python_auto_fixer(tool_name, tool_input, cwd)

        # Output according to PostToolUse contract (success, no blocking)
        # PostToolUse cannot block tools (they already ran) but can provide feedback
        output: Dict[str, Any] = {
            "continue": True,
            "suppressOutput": False,  # Allow output to be visible
        }

        print(json.dumps(output))
        sys.exit(0)

    except Exception as e:
        print(f"Error in PostToolUse handler: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point for standalone execution."""
    try:
        # Read and validate JSON input from stdin
        input_data = json.load(sys.stdin)
        handle(input_data)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


# ENHANCEMENT SUMMARY: Severity-Weighted ZEN Triggering System
# ============================================================
#
# This file has been enhanced with a severity-weighted ZEN recommendation
# triggering system that prioritizes critical security and performance issues
# while maintaining rate limiting for lower-priority recommendations.
#
# KEY FEATURES:
# - classify_recommendation_severity(): Analyzes patterns, anti-patterns, and
#   performance issues to classify recommendations as critical/high/medium/low
# - SEVERITY_CONFIG: Configurable thresholds for different severity levels
# - Integrated anti-pattern detection for real-time security vulnerability detection
# - Performance hotspot analysis integration for O(n²)+ complexity detection
# - Severity-aware rate limiting that bypasses limits for critical issues
# - Backwards compatible with existing triggering logic
#
# SEVERITY LEVELS:
# - CRITICAL: Immediate trigger, bypasses rate limiting (security/anti-patterns)
# - HIGH: Every 2nd tool use (performance issues, architecture violations)
# - MEDIUM: Every 3rd/5th tool use (current behavior for general patterns)
# - LOW: Every 7th tool use (informational suggestions)
#
# CONFIGURATION:
# Modify SEVERITY_CONFIG at the top of the file to adjust frequency thresholds
# and rate limiting behavior for each severity level.
