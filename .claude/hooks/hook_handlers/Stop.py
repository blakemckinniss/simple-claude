# \!/usr/bin/env python3
# claude-exempt: hook_handlers_py_protection - Adding JSON output control, rate limiting, and security improvements
"""
Stop hook handler with session cleanup and archival logic.
This hook is called when Claude stops processing.
"""

import atexit
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

# Import state manager for continuation tracking and memory manager
from hook_tools.utilities.path_resolver import PathResolver
from hook_tools.state_manager import state_manager
from hook_logger import logger
from hook_tools.security_validator import check_rate_limit, RateLimitExceeded
from hook_tools.memory_manager import memory_manager, MemoryType

paths = PathResolver()

# Session ID validation pattern (UUID format)
# Matches standard UUID format: 8-4-4-4-12 hexadecimal characters
SESSION_ID_PATTERN = re.compile(
    r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',
    re.IGNORECASE
)

# Module-level thread pool for background cleanup tasks
_background_executor = ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="stop-cleanup"
)


# Ensure proper cleanup on module exit
def _cleanup_executor():
    """Cleanup function to properly shutdown the thread pool."""
    try:
        _background_executor.shutdown(wait=True)
    except Exception:
        pass


atexit.register(_cleanup_executor)


def validate_session_id(session_id: str) -> bool:
    """
    Validate session ID format to prevent path traversal attacks.
    
    Args:
        session_id: Session identifier to validate
        
    Returns:
        True if session_id is valid UUID format, False otherwise
    """
    if not session_id:
        return False
    
    # Check for path traversal attempts
    if ".." in session_id or "/" in session_id or "\\" in session_id:
        return False
    
    # Validate UUID format
    return bool(SESSION_ID_PATTERN.match(session_id))


def sanitize_session_id(session_id: str) -> str:
    """
    Sanitize session ID for safe use in file operations.
    
    Args:
        session_id: Session identifier to sanitize
        
    Returns:
        Sanitized session_id or 'invalid_session' if validation fails
    """
    if validate_session_id(session_id):
        return session_id
    return "invalid_session"


def calculate_session_duration(session_info: Dict[str, Any]) -> Optional[float]:
    """Calculate session duration in seconds from session info."""
    try:
        created_at = session_info.get("created_at")
        if not created_at:
            return None

        start_time = datetime.fromisoformat(created_at)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        return duration
    except (ValueError, TypeError):
        return None


def archive_session_data(
    session_id: str, session_info: Dict[str, Any], archive_dir: Path
) -> bool:
    """
    Archive session data before cleanup.

    Args:
        session_id: Session identifier to archive
        session_info: Session data to archive
        archive_dir: Directory to store archived sessions

    Returns:
        True if archival succeeded, False otherwise
    """
    try:
        # Validate session_id to prevent path traversal
        if not validate_session_id(session_id):
            # Log security warning
            print(f"Security Warning: Invalid session_id format detected: {session_id}", file=sys.stderr)
            return False
        
        # Create archive directory if it doesn't exist
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Create archive entry
        archive_entry = {
            "session_id": session_id,
            "archived_at": datetime.now().isoformat(),
            "session_data": session_info,
            "cleanup_reason": "session_stop",
        }

        # Generate archive filename with timestamp (using validated session_id)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Use only first 8 chars of validated UUID for filename
        safe_session_prefix = session_id[:8]
        archive_file = archive_dir / f"session_{safe_session_prefix}_{timestamp}.json"

        # Write archive atomically
        temp_file = archive_file.with_suffix(".tmp")
        with open(temp_file, "w") as f:
            json.dump(archive_entry, f, indent=2)

        temp_file.replace(archive_file)
        return True

    except Exception:
        # Silent fail - archival is optional
        return False


def cleanup_session_state(
    session_id: str, archive_session: bool = True
) -> Dict[str, Any]:
    """
    Clean up session state with optional archival.

    Args:
        session_id: Session identifier to clean up
        archive_session: Whether to archive session data before cleanup

    Returns:
        Cleanup statistics and status
    """
    cleanup_stats = {
        "session_id": session_id,
        "cleanup_time": datetime.now().isoformat(),
        "archived": False,
        "session_processed": False,
        "session_duration": None,
        "error": None,
    }

    # Validate session_id before any file operations
    if not validate_session_id(session_id):
        cleanup_stats["error"] = f"Invalid session_id format: {session_id[:50]}"
        print(f"Security Warning: Cleanup rejected for invalid session_id: {session_id[:50]}", file=sys.stderr)
        return cleanup_stats

    try:
        # Get session info before cleanup
        session_info = state_manager.get_session_info(session_id)

        if session_info:
            # Calculate session duration
            cleanup_stats["session_duration"] = calculate_session_duration(session_info)

            # Archive session data if requested
            if archive_session:
                archive_dir = (
                    Path(__file__).parent.parent / "logs" / "archived_sessions"
                )
                archived = archive_session_data(session_id, session_info, archive_dir)
                cleanup_stats["archived"] = archived

            # Update session stop time without clearing continuation_id
            # (Continuations should persist across sessions for context revival)
            try:
                # Just mark that session was processed - don't clear continuation_id
                # The continuation_id should persist to enable context revival in future sessions
                cleanup_stats["session_processed"] = True

            except Exception as e:
                cleanup_stats["error"] = f"Failed to process session: {str(e)}"

        return cleanup_stats

    except Exception as e:
        cleanup_stats["error"] = f"Cleanup failed: {str(e)}"
        return cleanup_stats


def cleanup_old_archives(archive_dir: Path, retention_days: int = 30) -> None:
    """
    Clean up old archived sessions beyond retention period.

    Args:
        archive_dir: Directory containing archived sessions
        retention_days: Number of days to retain archives
    """
    try:
        if not archive_dir.exists():
            return

        cutoff_date = datetime.now() - timedelta(days=retention_days)

        for archive_file in archive_dir.glob("session_*.json"):
            try:
                file_time = datetime.fromtimestamp(archive_file.stat().st_mtime)
                if file_time < cutoff_date:
                    archive_file.unlink()
            except Exception:
                # Skip files we can't process
                continue

    except Exception:
        # Silent fail - cleanup is not critical
        pass


def save_session_summary_to_memory(
    session_id: str, stop_reason: str, cleanup_stats: Dict[str, Any]
) -> None:
    """
    Save session summary and achievements to memory for future reference.

    Args:
        session_id: Session identifier that ended
        stop_reason: Reason for session stop
        cleanup_stats: Statistics from cleanup operation
    """
    # Validate session_id before using in memory operations
    if not validate_session_id(session_id):
        # Skip memory save for invalid session_ids
        return
    
    try:
        # Create session summary
        duration = cleanup_stats.get("session_duration")
        duration_str = f"{duration:.1f}s" if duration else "unknown"

        summary_content = f"Session ended: {stop_reason}, Duration: {duration_str}"

        # Add key achievements if available
        if cleanup_stats.get("session_processed"):
            summary_content += ", Successfully processed"

        if cleanup_stats.get("archived"):
            summary_content += ", Archived"

        # Determine relevance based on duration and reason
        relevance_score = 0.7
        if duration and duration > 300:  # Long sessions (5+ minutes) are more relevant
            relevance_score = 0.8
        if stop_reason in [
            "user_request",
            "completion",
        ]:  # Normal endings are more relevant
            relevance_score += 0.1

        # Save session summary to memory
        memory_manager.save_memory(
            content=summary_content,
            memory_type=MemoryType.CRITICAL_CONTEXT,
            session_id=session_id,
            relevance_score=min(relevance_score, 1.0),
            tags=["session_summary", stop_reason, "completion"],
        )

        # If this was a successful session, save it as a discovery
        if stop_reason in ["completion", "success"] and duration and duration > 60:
            memory_manager.save_memory(
                content=f"Successful session completed: {duration_str} duration, achieved goals",
                memory_type=MemoryType.DISCOVERIES,
                session_id=session_id,
                relevance_score=0.8,
                tags=["success", "achievement", "completion"],
            )

    except Exception:
        # Silent fail - memory save shouldn't break session cleanup
        pass


def log_session_end(
    session_id: str, stop_reason: str, cleanup_stats: Dict[str, Any]
) -> None:
    """
    Log session end with duration statistics.

    Args:
        session_id: Session identifier that ended
        stop_reason: Reason for session stop
        cleanup_stats: Statistics from cleanup operation
    """
    try:
        log_entry = {
            "event_type": "session_end",
            "session_id": session_id,
            "stop_reason": stop_reason,
            "cleanup_stats": cleanup_stats,
        }

        logger.log_event(log_entry)

    except Exception:
        # Silent fail - logging is not critical
        pass


def handle(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle Stop hook events with comprehensive cleanup logic.

    Args:
        data: Hook event data containing stop information
        
    Returns:
        Dict[str, Any]: JSON output control structure with:
            - continue: bool (whether Claude should continue)
            - suppressOutput: bool (hide from transcript)
            - stopReason: string (message when continue is false)
            - sessionStats: dict (duration, archived, processed status)
    """
    cleanup_stats = {}

    try:
        # Extract relevant information
        hook_event_name = data.get("hook_event_name", "")
        stop_reason = data.get("stop_reason", "unknown")
        raw_session_id = data.get("session_id", "")
        session_info = data.get("session_info", {})

        # Validate and sanitize session_id to prevent path traversal
        if raw_session_id:
            session_id = sanitize_session_id(raw_session_id)
            if session_id == "invalid_session":
                # Log security warning for invalid session_id
                print(f"Security Warning: Rejected invalid session_id format: {raw_session_id[:50]}", file=sys.stderr)
                # Try to extract from session_info as fallback
                fallback_id = session_info.get("session_id", "")
                if fallback_id:
                    session_id = sanitize_session_id(fallback_id)
                else:
                    session_id = "unknown_session"
        else:
            # Try to extract from session_info or generate placeholder
            fallback_id = session_info.get("session_id", "")
            if fallback_id:
                session_id = sanitize_session_id(fallback_id)
            else:
                session_id = "unknown_session"

        # Rate limiting check
        if session_id and session_id != "unknown_session":
            try:
                check_rate_limit("stop_hook", max_requests=10, window_seconds=60)
            except RateLimitExceeded:
                return {
                    "continue": False,
                    "suppressOutput": True,
                    "stopReason": "Rate limit exceeded for stop hook",
                    "sessionStats": {
                        "duration": None,
                        "archived": False,
                        "processed": False,
                        "cleanup_time": datetime.now().isoformat(),
                        "session_id": session_id,
                        "error": "Rate limit exceeded"
                    }
                }

        # Update session with stop_time before cleanup
        if session_id and session_id != "unknown_session" and session_id != "invalid_session":
            # Additional validation check before file operations
            if validate_session_id(session_id):
                try:
                    # Load current sessions
                    sessions_file = Path(__file__).parent.parent / "state" / "sessions.json"
                    if sessions_file.exists():
                        with open(sessions_file, "r") as f:
                            sessions_data = json.load(f)

                        # Update session with stop_time
                        if (
                            "sessions" in sessions_data
                            and session_id in sessions_data["sessions"]
                        ):
                            sessions_data["sessions"][session_id][
                                "stop_time"
                            ] = datetime.now().isoformat()
                            sessions_data["sessions"][session_id][
                                "stop_reason"
                            ] = stop_reason

                            # Update metadata
                            sessions_data["metadata"][
                                "last_updated"
                            ] = datetime.now().isoformat()

                            # Write back atomically
                            temp_file = sessions_file.with_suffix(".tmp")
                            with open(temp_file, "w") as f:
                                json.dump(sessions_data, f, indent=2)
                            temp_file.replace(sessions_file)
                except Exception as e:
                    # Log but don't fail - this is non-critical
                    print(
                        f"Warning: Could not update session stop_time: {e}", file=sys.stderr
                    )

        # Perform thread-safe cleanup
        if session_id and session_id != "unknown_session" and session_id != "invalid_session":
            # Additional validation before cleanup operations
            if validate_session_id(session_id):
                # Run cleanup in current thread for immediate execution
                cleanup_stats = cleanup_session_state(
                    session_id=session_id, archive_session=True  # Always archive on stop
                )
            else:
                # Create error cleanup stats for invalid session
                cleanup_stats = {
                    "session_id": session_id,
                    "cleanup_time": datetime.now().isoformat(),
                    "archived": False,
                    "session_processed": False,
                    "session_duration": None,
                    "error": f"Invalid session_id format: {session_id[:50]}"
                }

            # Save session summary to memory for future reference
            save_session_summary_to_memory(session_id, stop_reason, cleanup_stats)

            # Log session end with statistics
            log_session_end(session_id, stop_reason, cleanup_stats)

            # Schedule background cleanup of old archives (non-blocking)
            def background_cleanup():
                """Background cleanup with comprehensive error handling."""
                try:
                    archive_dir = (
                        Path(__file__).parent.parent / "logs" / "archived_sessions"
                    )
                    cleanup_old_archives(archive_dir, retention_days=30)
                except Exception as e:
                    print(f"Archive cleanup warning: {e}", file=sys.stderr)

                try:
                    # Also cleanup old session data
                    state_manager.cleanup_old_sessions(days=7)
                except Exception as e:
                    print(f"Session cleanup warning: {e}", file=sys.stderr)

            # Submit cleanup task to managed thread pool
            try:
                future = _background_executor.submit(background_cleanup)

                # Optional: Add error handling for the background task
                def handle_cleanup_result(fut):
                    try:
                        fut.result(timeout=1.0)  # Quick check, don't block
                    except Exception as e:
                        # Log cleanup errors but don't fail the main operation
                        print(f"Background cleanup warning: {e}", file=sys.stderr)

                # Add callback for error handling (non-blocking)
                future.add_done_callback(handle_cleanup_result)
            except Exception as e:
                # Fallback: if executor is unavailable, skip background cleanup
                print(f"Warning: Background cleanup skipped: {e}", file=sys.stderr)

        # Optional debug output (can be enabled for troubleshooting)
        debug_mode = data.get("debug", False)
        if debug_mode:
            debug_info = {
                "stop_reason": stop_reason,
                "session_id": session_id,
                "cleanup_stats": cleanup_stats,
                "hook_event_name": hook_event_name,
            }
            print(
                f"Stop handler debug: {json.dumps(debug_info, indent=2)}",
                file=sys.stderr,
            )

    except Exception as e:
        error_msg = f"Error in Stop handler: {e}"
        print(error_msg, file=sys.stderr)

        # Log error but don't exit with error code - cleanup failure shouldn't break the workflow
        try:
            logger.log_error(error_msg, {"hook_data": data})
        except Exception:
            pass
    
    # Return JSON output control structure per HOOK_CONTRACT.md
    return {
        "continue": True,  # Allow Claude to continue normally after stop
        "suppressOutput": False,  # Show cleanup info in transcript
        "stopReason": data.get("stop_reason", "Session ended"),
        "sessionStats": {
            "duration": cleanup_stats.get("session_duration"),
            "archived": cleanup_stats.get("archived", False),
            "processed": cleanup_stats.get("session_processed", False),
            "cleanup_time": cleanup_stats.get("cleanup_time"),
            "session_id": cleanup_stats.get("session_id"),
            "error": cleanup_stats.get("error")
        }
    }


def main():
    """Main entry point for standalone execution."""
    try:
        # Read JSON input from stdin
        input_data = json.load(sys.stdin)
        handle(input_data)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
