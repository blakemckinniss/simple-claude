#!/usr/bin/env python3
"""
Scoring calculation functions for risk assessment and recommendation confidence.

This module provides functions to calculate various scores including composite risk,
complexity, relevance, and recommendation confidence based on analysis results.
"""

from typing import Dict, Any, List


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