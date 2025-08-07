#!/usr/bin/env python3
# claude-exempt: File Without Context Manager - Existing code pattern from extracted functions
"""
Recommendation Helper Functions

Contains recommendation generation and analysis functions extracted from PostToolUse.py.
Provides ZEN tool recommendations, severity classification, and agent analysis.
"""

import os
from typing import Dict, Any, List, Optional


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

    return str("\n".join(template_parts))


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


def get_agent_info(agent_name: str) -> Dict[str, Any]:
    """
    Get information about a specific ZEN agent.

    Args:
        agent_name: Name of the ZEN agent (e.g., 'debug', 'secaudit')

    Returns:
        Dictionary containing agent information
    """
    # Remove 'mcp__zen__' prefix if present
    clean_name = agent_name.replace("mcp__zen__", "")

    agent_info = {
        "debug": {
            "name": "Debug & Root Cause Analysis",
            "description": "Systematic step-by-step investigation for complex bugs and issues",
            "use_cases": ["Complex bugs", "Mysterious errors", "Performance issues", "Race conditions"],
            "best_for": "When you need structured investigation with evidence gathering",
            "thinking_modes": ["low", "medium", "high", "max"],
            "continuation_support": True,
        },
        "secaudit": {
            "name": "Security Audit Workflow",
            "description": "Comprehensive security assessment with OWASP compliance",
            "use_cases": ["Security vulnerabilities", "OWASP Top 10", "Compliance review", "Threat modeling"],
            "best_for": "Security-critical applications and sensitive data handling",
            "thinking_modes": ["medium", "high", "max"],
            "continuation_support": True,
        },
        "codereview": {
            "name": "Code Review Workflow",
            "description": "Comprehensive code quality assessment and architectural review",
            "use_cases": ["Code quality", "Architecture review", "Best practices", "Maintainability"],
            "best_for": "Pre-commit validation and code quality improvement",
            "thinking_modes": ["low", "medium", "high"],
            "continuation_support": True,
        },
        "refactor": {
            "name": "Refactoring Analysis",
            "description": "Code improvement and modernization opportunities",
            "use_cases": ["Code smells", "Modernization", "Performance optimization", "Architecture improvement"],
            "best_for": "Legacy code improvement and technical debt reduction",
            "thinking_modes": ["medium", "high"],
            "continuation_support": True,
        },
        "analyze": {
            "name": "Comprehensive Analysis",
            "description": "Multi-faceted code and architectural analysis",
            "use_cases": ["Architecture assessment", "Performance analysis", "Strategic planning", "Technology evaluation"],
            "best_for": "Understanding complex systems and making strategic decisions",
            "thinking_modes": ["medium", "high", "max"],
            "continuation_support": True,
        },
        "testgen": {
            "name": "Test Generation",
            "description": "Comprehensive test suite creation with edge case coverage",
            "use_cases": ["Unit testing", "Integration testing", "Test coverage", "Edge cases"],
            "best_for": "Improving test coverage and ensuring code reliability",
            "thinking_modes": ["low", "medium", "high"],
            "continuation_support": True,
        },
        "precommit": {
            "name": "Pre-commit Validation",
            "description": "Comprehensive validation before code commits",
            "use_cases": ["Change validation", "Impact assessment", "Quality gates", "CI/CD preparation"],
            "best_for": "Ensuring code quality before commits",
            "thinking_modes": ["medium", "high"],
            "continuation_support": True,
        },
        "consensus": {
            "name": "Multi-Model Consensus",
            "description": "Build consensus on complex decisions using multiple AI perspectives",
            "use_cases": ["Architecture decisions", "Technology choices", "Design patterns", "Strategic planning"],
            "best_for": "Important decisions requiring multiple perspectives",
            "thinking_modes": ["high", "max"],
            "continuation_support": True,
        },
        "planner": {
            "name": "Sequential Planning",
            "description": "Break down complex tasks into structured implementation plans",
            "use_cases": ["Project planning", "Feature implementation", "Migration planning", "System design"],
            "best_for": "Complex multi-step projects with dependencies",
            "thinking_modes": ["medium", "high"],
            "continuation_support": True,
        },
        "tracer": {
            "name": "Code Tracing",
            "description": "Trace code execution flow and analyze dependencies",
            "use_cases": ["Code flow analysis", "Dependency mapping", "Call tracing", "Impact analysis"],
            "best_for": "Understanding complex code relationships",
            "thinking_modes": ["medium", "high"],
            "continuation_support": True,
        },
        "docgen": {
            "name": "Documentation Generation",
            "description": "Generate comprehensive documentation with examples",
            "use_cases": ["API documentation", "Code documentation", "User guides", "Architecture docs"],
            "best_for": "Creating and maintaining project documentation",
            "thinking_modes": ["low", "medium"],
            "continuation_support": False,
        },
        "chat": {
            "name": "General Chat & Thinking",
            "description": "Collaborative discussion and brainstorming",
            "use_cases": ["Brainstorming", "General questions", "Explanations", "Discussions"],
            "best_for": "Exploratory conversations and getting second opinions",
            "thinking_modes": ["minimal", "low", "medium"],
            "continuation_support": True,
        },
        "thinkdeep": {
            "name": "Deep Investigation",
            "description": "Multi-stage systematic investigation with expert analysis",
            "use_cases": ["Complex problems", "Research", "Architecture decisions", "Performance challenges"],
            "best_for": "When you need thorough systematic investigation",
            "thinking_modes": ["high", "max"],
            "continuation_support": True,
        },
    }

    return agent_info.get(clean_name, {
        "name": f"Unknown Agent ({clean_name})",
        "description": "Agent information not available",
        "use_cases": [],
        "best_for": "General purpose analysis",
        "thinking_modes": ["medium"],
        "continuation_support": False,
    })


def analyze_and_recommend_agents(
    recommendations: List[str], analysis_results: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Analyze recommendations and provide detailed agent suggestions.

    Args:
        recommendations: List of ZEN tool recommendations
        analysis_results: Analysis results from comprehensive data collection

    Returns:
        List of detailed agent recommendations with rationale
    """
    if not recommendations:
        return []

    detailed_recommendations = []

    for rec in recommendations[:3]:  # Limit to top 3
        # Extract agent name
        if " - " in rec:
            agent_part = rec.split(" - ")[0].replace("mcp__zen__", "")
            description = rec.split(" - ", 1)[1]
        else:
            agent_part = rec.replace("mcp__zen__", "")
            description = "Analysis recommended"

        # Get agent information
        agent_info = get_agent_info(agent_part)

        # Determine priority based on analysis results
        priority = "LOW"
        rationale = []

        # Check for critical issues
        anti_patterns = analysis_results.get("anti_patterns", [])
        critical_patterns = [p for p in anti_patterns if p.get("severity") == "CRITICAL"]
        high_patterns = [p for p in anti_patterns if p.get("severity") == "HIGH"]

        if critical_patterns:
            priority = "CRITICAL"
            rationale.append(f"{len(critical_patterns)} critical anti-patterns detected")
        elif high_patterns:
            priority = "HIGH"
            rationale.append(f"{len(high_patterns)} high-risk issues identified")

        # Check performance metrics
        performance_metrics = analysis_results.get("performance_metrics", {})
        risk_level = performance_metrics.get("risk_level", "minimal")
        
        if risk_level in ["critical", "high"] and priority != "CRITICAL":
            priority = "HIGH" if risk_level == "critical" else "MEDIUM"
            risk_score = performance_metrics.get("aggregate_risk_score", 0)
            rationale.append(f"Performance risk: {risk_level} (score: {risk_score})")

        # Check project context
        project_context = analysis_results.get("project_context", {})
        recent_errors = project_context.get("errors", {}).get("recent_errors", [])
        
        if len(recent_errors) >= 3 and priority not in ["CRITICAL", "HIGH"]:
            priority = "MEDIUM"
            rationale.append(f"{len(recent_errors)} recent errors require attention")

        # Recommend thinking mode based on priority and agent type
        thinking_mode = "medium"  # default
        if priority == "CRITICAL":
            thinking_mode = "max"
        elif priority == "HIGH":
            thinking_mode = "high"
        elif agent_part in ["debug", "secaudit", "thinkdeep"]:
            thinking_mode = "high"

        detailed_recommendations.append({
            "agent": agent_part,
            "full_tool": f"mcp__zen__{agent_part}",
            "description": description,
            "priority": priority,
            "rationale": rationale,
            "agent_info": agent_info,
            "recommended_thinking_mode": thinking_mode,
            "continuation_support": agent_info.get("continuation_support", False),
        })

    # Sort by priority (CRITICAL > HIGH > MEDIUM > LOW)
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    detailed_recommendations.sort(key=lambda x: priority_order.get(x["priority"], 3))

    return detailed_recommendations