#!/usr/bin/env python3
"""
Classification helper functions for memory type and tag creation.

This module provides functions to classify memory types and create enhanced tags
based on analysis results and project context.
"""

from typing import Dict, Any, List, Optional

from .memory_manager import MemoryType


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