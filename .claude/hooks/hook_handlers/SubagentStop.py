#!/usr/bin/env python3
# claude-exempt: hook_handlers_py_protection - Enhancing SubagentStop with comprehensive tracking features
"""
Enhanced SubagentStop hook handler.
This hook is called when a subagent stops processing.
Provides comprehensive tracking of subagent lifecycle events, performance metrics,
and integration with continuation/memory management systems.
"""

import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional

# Import state manager, memory manager, and continuation helpers
from hook_tools.state_manager import state_manager
from hook_tools.memory_manager import memory_manager, MemoryType
from hook_tools.utilities.path_resolver import PathResolver
from hook_tools.security_validator import check_rate_limit, RateLimitExceeded

paths = PathResolver()


def extract_continuation_from_subagent(subagent_info: Dict[str, Any]) -> Optional[str]:
    """
    Extract continuation_id from subagent response if it's an mcp__zen tool.

    Args:
        subagent_info: Subagent information dictionary

    Returns:
        continuation_id if found, None otherwise
    """
    # Check if subagent was an mcp__zen tool
    tool_name = subagent_info.get("tool_name", "")
    if not tool_name.startswith("mcp__zen__"):
        return None

    # Look for continuation_id in response
    response = subagent_info.get("response", {})
    if isinstance(response, dict):
        continuation_offer = response.get("continuation_offer", {})
        if isinstance(continuation_offer, dict):
            return continuation_offer.get("continuation_id")

    return None


def calculate_duration(start_time: Optional[str]) -> Optional[float]:
    """
    Calculate duration from start time to now.

    Args:
        start_time: ISO format timestamp string

    Returns:
        Duration in seconds or None if start_time invalid
    """
    if not start_time:
        return None

    try:
        start = datetime.fromisoformat(start_time)
        end = datetime.now()
        return (end - start).total_seconds()
    except (ValueError, TypeError):
        return None


def handle(data: Dict[str, Any]) -> None:
    """
    Handle SubagentStop hook events with comprehensive tracking and management.

    Args:
        data: Hook event data containing subagent stop information
    """
    try:
        # Extract core information
        hook_event_name = data.get("hook_event_name", "")
        session_id = data.get("session_id", "")
        subagent_id = data.get("subagent_id", "")
        stop_reason = data.get("stop_reason", "")
        subagent_info = data.get("subagent_info", {})

        # Performance tracking
        start_time = subagent_info.get("start_time")
        duration = calculate_duration(start_time)

        # Determine success/failure status
        success_indicators = ["completed", "success", "done", "finished"]
        failure_indicators = ["error", "failed", "aborted", "timeout", "cancelled"]

        success = any(
            indicator in stop_reason.lower() for indicator in success_indicators
        )
        failure = any(
            indicator in stop_reason.lower() for indicator in failure_indicators
        )

        # Extract error details if failed
        error_details = None
        if failure or not success:
            error_details = subagent_info.get("error") or subagent_info.get(
                "error_message"
            )
            if not error_details and "exception" in subagent_info:
                error_details = str(subagent_info["exception"])

        # Extract subagent results
        result_summary = subagent_info.get("result") or subagent_info.get("output")
        tool_name = subagent_info.get("tool_name", "")

        # Handle continuation tracking for mcp__zen tools
        continuation_id = extract_continuation_from_subagent(subagent_info)
        if continuation_id and session_id:
            try:
                state_manager.set_continuation_id(session_id, continuation_id)
                print(
                    f"Subagent {subagent_id} provided continuation: {continuation_id}",
                    file=sys.stderr,
                )
            except Exception as e:
                print(f"Warning: Failed to store continuation_id: {e}", file=sys.stderr)

        # Store subagent results in memory for future reference
        if session_id and subagent_id:
            try:
                # Determine memory type based on success/failure
                memory_type = MemoryType.TOOL_PATTERNS if success else MemoryType.ERRORS

                # Prepare memory content
                memory_content = f"Subagent {subagent_id} ({tool_name}) {stop_reason}"
                if result_summary:
                    memory_content += f"\nResult: {str(result_summary)[:500]}"
                if error_details:
                    memory_content += f"\nError: {error_details}"

                # Save to memory with metadata
                memory_manager.save_enhanced_memory(
                    content=memory_content,
                    memory_type=memory_type,
                    session_id=session_id,
                    metadata={
                        "subagent_id": subagent_id,
                        "tool_name": tool_name,
                        "duration_seconds": duration,
                        "success": success,
                        "stop_reason": stop_reason,
                        "has_continuation": bool(continuation_id),
                        "timestamp": datetime.now().isoformat(),
                    },
                )
            except Exception as e:
                print(f"Warning: Failed to save subagent memory: {e}", file=sys.stderr)

        # Update session state with subagent completion
        if session_id:
            try:
                # Get existing session info or use empty dict if session doesn't exist
                # update_session will automatically initialize the session if needed
                session_info = state_manager.get_session_info(session_id) or {}

                # Track subagent executions in session
                subagent_history = session_info.get("subagent_history", [])
                subagent_history.append(
                    {
                        "subagent_id": subagent_id,
                        "tool_name": tool_name,
                        "stop_reason": stop_reason,
                        "duration": duration,
                        "success": success,
                        "timestamp": datetime.now().isoformat(),
                    }
                )
                # Keep only last 50 subagent executions
                if len(subagent_history) > 50:
                    subagent_history = subagent_history[-50:]

                state_manager.update_session(
                    session_id,
                    {
                        "subagent_history": subagent_history,
                        "last_subagent_id": subagent_id,
                        "last_subagent_status": "success" if success else "failure",
                    },
                )
            except Exception as e:
                print(f"Warning: Failed to update session state: {e}", file=sys.stderr)

        # Rate-limited error reporting for failures
        if failure and error_details:
            try:
                # Limit error reporting to prevent spam
                check_rate_limit(
                    f"SUBAGENT_ERROR_{tool_name}",
                    max_requests=5,
                    window_seconds=300,  # 5 errors per 5 minutes per tool type
                )

                # Output detailed error information
                print("\n⚠️ Subagent Failure Detected:", file=sys.stderr)
                print(f"  ID: {subagent_id}", file=sys.stderr)
                print(f"  Tool: {tool_name}", file=sys.stderr)
                print(f"  Reason: {stop_reason}", file=sys.stderr)
                print(
                    (
                        f"  Duration: {duration:.2f}s"
                        if duration
                        else "  Duration: Unknown"
                    ),
                    file=sys.stderr,
                )
                print(f"  Error: {error_details}", file=sys.stderr)

            except RateLimitExceeded:
                # Silently skip if rate limit exceeded
                pass

        # Log successful completions with significant duration
        elif (
            success and duration and duration > 10.0
        ):  # Log if took more than 10 seconds
            print(
                f"✓ Subagent {subagent_id} completed in {duration:.2f}s",
                file=sys.stderr,
            )

        # Performance warning for long-running subagents
        if duration and duration > 60.0:  # Warn if took more than 1 minute
            print(
                f"⏱️ Performance Warning: Subagent {subagent_id} took {duration:.2f}s",
                file=sys.stderr,
            )

    except Exception as e:
        # Critical error handling - log but don't crash
        print(f"Critical error in SubagentStop handler: {e}", file=sys.stderr)
        print(
            f"Data received: {json.dumps(data, default=str, indent=2)}", file=sys.stderr
        )
        # Don't exit to prevent breaking the entire hook chain
        # sys.exit(1)
