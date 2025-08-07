#!/usr/bin/env python3
# claude-exempt: hook_handlers_py_protection - Enhancing ZEN triggering logic with severity-weighted system
"""
PostToolUse Hook Handler
========================

Compliant with HOOK_CONTRACT.md. This hook is called after Claude uses a tool.

Refactored Architecture:
- Extracted core functionality into specialized hook_tools modules:
  * analysis_collector: Tool input analysis and data collection
  * scoring_calculator: Risk scores and relevance calculations
  * classification_helpers: Memory classification and tagging
  * pattern_detector: ZEN usage patterns and anti-pattern detection
  * recommendation_helpers: ZEN recommendations and agent analysis
  * utility_functions: Input sanitization and content extraction
  * context/: Project context gathering (errors, config, tests, environment)

Key Features:
- Severity-weighted ZEN recommendation triggering (critical/high/medium/low)
- Rate-limited feedback with bypass for critical security issues
- Memory pattern storage with enhanced context
- CLI tool recommendations and Python auto-fixing
- Continuation ID management for ZEN tool workflows
- Anti-pattern detection and performance hotspot analysis
"""

import json
import sys
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

# Import state manager for continuation tracking, logger for rate limiting, and memory manager
from hook_tools.utilities.path_resolver import PathResolver
from hook_tools.state_manager import state_manager
from hook_tools.continuation_manager import extract_continuation_id, store_continuation_id
# from hook_logger import logger  # Not used in this module
from hook_tools.security_validator import check_rate_limit, RateLimitExceeded
from hook_tools.memory_manager import memory_manager
from hook_tools.analysis_collector import (
    collect_comprehensive_analysis_data,
    create_tool_input_summary,
    extract_file_paths,
    classify_operation_type,
)
from hook_tools.scoring_calculator import (
    calculate_composite_risk_score,
    calculate_complexity_score,
    calculate_enhanced_relevance_score,
    calculate_recommendation_confidence,
)
from hook_tools.classification_helpers import (
    classify_memory_type_from_analysis,
    create_enhanced_tags,
)
from hook_tools.pattern_detector import (
    collect_project_context_cached,
    detect_zen_usage_patterns,
    detect_anti_patterns_for_file_operation,
)
from hook_tools.recommendation_helpers import (
    generate_zen_prompt_template,
    classify_recommendation_severity,
)
from hook_tools.utility_functions import (
    sanitize_input,
    should_trigger_python_fixer,
    analyze_bash_command,
)

paths = PathResolver()

# Load configurable severity-weighted triggering thresholds from constants
try:
    constants = paths.load_constants()
    posttooluse_config = constants.get("post_tool_use", {})
    SEVERITY_CONFIG = posttooluse_config.get("severity_config", {})
    THRESHOLDS = posttooluse_config.get("thresholds", {})
    RATE_LIMITING = posttooluse_config.get("rate_limiting", {})
    HIGH_PRIORITY_TOOLS = posttooluse_config.get("high_priority_tools", [])
    MODERN_CLI_REPLACEMENTS = posttooluse_config.get("modern_cli_replacements", {})
    MESSAGES = posttooluse_config.get("messages", {})
    DEBUG_LOG_PATH = posttooluse_config.get("debug_log_path", "/tmp/posttooluse_debug.log")
except Exception:
    # Fallback configuration if constants loading fails
    SEVERITY_CONFIG = {
        "critical": {"frequency": 1, "bypass_rate_limit": True},
        "high": {"frequency": 2, "bypass_rate_limit": False},
        "medium": {"frequency_with_continuation": 3, "frequency_without_continuation": 5, "bypass_rate_limit": False},
        "low": {"frequency": 7, "bypass_rate_limit": False}
    }
    THRESHOLDS = {"memory_relevance_threshold": 0.6, "memory_search_limit": 3}
    RATE_LIMITING = {"modern_cli_tool_max_requests": 5, "modern_cli_tool_window_seconds": 120, "python_auto_fixer_max_requests": 3, "python_auto_fixer_window_seconds": 60, "zen_continuation_max_requests": 3, "zen_continuation_window_seconds": 60}
    HIGH_PRIORITY_TOOLS = ["Task", "Bash", "Grep", "Edit", "MultiEdit", "TodoWrite"]
    MODERN_CLI_REPLACEMENTS = {}
    MESSAGES = {}
    DEBUG_LOG_PATH = "/tmp/posttooluse_debug.log"


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
            context=search_context, 
            session_id=session_id, 
            limit=THRESHOLDS.get("memory_search_limit", 3), 
            min_relevance=THRESHOLDS.get("memory_relevance_threshold", 0.6)
        )

        if memories:
            memory_count = len(memories)
            highest_relevance = max(m.get("combined_relevance", 0) for m in memories)

            return MESSAGES.get("memory_notification", "📝 RELEVANT MEMORIES: Found {memory_count} related memories (max relevance: {highest_relevance:.2f}) - consider using mcp__zen tools for enhanced context").format(
                memory_count=memory_count,
                highest_relevance=highest_relevance
            )

        return ""

    except Exception:
        return ""



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
        with open(DEBUG_LOG_PATH, "a") as f:
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
                suggestions = analyze_bash_command(command, MODERN_CLI_REPLACEMENTS)
                if suggestions:
                    for old_tool, new_tool, _reason in suggestions:
                        error_msg = MESSAGES.get("modern_cli_error", "⚡💥 YOU MUST USE {new_tool} INSTEAD OF {old_tool}! 🚫❌").format(
                            new_tool=new_tool, old_tool=old_tool
                        )
                        try:
                            check_rate_limit(
                                "MODERN_CLI_TOOL_RECOMMENDATION", 
                                max_requests=RATE_LIMITING.get("modern_cli_tool_max_requests", 5), 
                                window_seconds=RATE_LIMITING.get("modern_cli_tool_window_seconds", 120)
                            )
                            should_show_cli_rec = True
                        except RateLimitExceeded:
                            should_show_cli_rec = False
                            
                        if should_show_cli_rec:
                            print(error_msg, file=sys.stderr)
                            sys.exit(2)

        # Check for TodoWrite usage and recommend agents instead (skip for Task tools to avoid breaking parallel execution)
        if tool_name == "TodoWrite" and not is_task_tool:
            error_msg = MESSAGES.get("todo_write_error", "🔥⚡ VERY IMPORTANT: YOU ABSOLUTELY **MUST** HIRE AN AGENT **OR AGENTS FOR INDEPENDENT PARALLEL/BATCH TASK ITEMS** TO COMPLETE THIS CORRECTLY. PARALLELIZE HIRES (PER CLAUDE.md PATTERN_CONTRACT LAWS D2-D6)!!! 💥🚫")
            try:
                check_rate_limit(
                    "PYTHON_AUTO_FIXER_ERROR", 
                    max_requests=RATE_LIMITING.get("python_auto_fixer_max_requests", 3), 
                    window_seconds=RATE_LIMITING.get("python_auto_fixer_window_seconds", 60)
                )
                should_show_error = True
            except RateLimitExceeded:
                should_show_error = False
                
            if should_show_error:
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
            elif tool_name in HIGH_PRIORITY_TOOLS:
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
                if edit_count >= THRESHOLDS.get("multi_edit_high_complexity", 5):  # High complexity
                    should_show_zen = True
                elif edit_count >= THRESHOLDS.get("multi_edit_medium_complexity", 3) and tool_count % 2 == 0:  # Medium complexity
                    should_show_zen = True

            # Check for relevant memories notification
            memory_notification = check_relevant_memories_notification(
                tool_name, tool_input, session_id
            )

            if should_show_zen or memory_notification:
                # Generate base continuation message
                if has_continuation:
                    base_message = MESSAGES.get("zen_continuation_available", "🔗 ZEN CONTINUATION AVAILABLE: Use continuation_id='{continuation_id}' with mcp__zen__* tools for context continuity").format(
                        continuation_id=existing_continuation_id
                    )
                else:
                    base_message = MESSAGES.get("zen_workflow_start", "🚀 ZEN WORKFLOW MUST USE: Start with mcp__zen__* tools for enhanced analysis (200k token allowance + expert validation)")

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
                # Use strict rate limiting from security_validator
                should_print = severity_config.get("bypass_rate_limit", False)
                
                if not should_print:
                    try:
                        check_rate_limit(
                            identifier=rate_limit_key,
                            max_requests=RATE_LIMITING.get("zen_continuation_max_requests", 3),
                            window_seconds=RATE_LIMITING.get("zen_continuation_window_seconds", 60)
                        )
                        should_print = True
                    except RateLimitExceeded:
                        should_print = False

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
        if should_trigger_python_fixer(tool_name, tool_input, cwd):
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
