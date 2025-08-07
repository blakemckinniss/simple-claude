#!/usr/bin/env python3
# claude-exempt: File Without Context Manager - Using context managers throughout for proper file handling
"""
Analysis data collection functions for comprehensive code analysis.

This module provides functions to collect comprehensive analysis data
for enhanced memory storage and tool usage pattern analysis.
"""

import os
import ast
from datetime import datetime
from typing import Dict, Any, List, Optional

from .anti_patterns_detector import AntiPatternDetector
from .analysis.performance_analyzer import detect_performance_hotspots_comprehensive
from .utilities.smart_truncate import truncate_for_preview


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