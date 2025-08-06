#!/usr/bin/env python3
"""
Stop hook handler with session cleanup and archival logic.
This hook is called when Claude stops processing.
"""

import json
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

# Import state manager for continuation tracking and memory manager
from hook_tools.utilities.path_resolver import PathResolver
paths = PathResolver()
from hook_tools.state_manager import state_manager
from hook_logger import logger
from hook_tools.memory_manager import memory_manager, MemoryType


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


def archive_session_data(session_id: str, session_info: Dict[str, Any], archive_dir: Path) -> bool:
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
        # Create archive directory if it doesn't exist
        archive_dir.mkdir(parents=True, exist_ok=True)
        
        # Create archive entry
        archive_entry = {
            "session_id": session_id,
            "archived_at": datetime.now().isoformat(),
            "session_data": session_info,
            "cleanup_reason": "session_stop"
        }
        
        # Generate archive filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_file = archive_dir / f"session_{session_id[:8]}_{timestamp}.json"
        
        # Write archive atomically
        temp_file = archive_file.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(archive_entry, f, indent=2)
        
        temp_file.replace(archive_file)
        return True
        
    except Exception:
        # Silent fail - archival is optional
        return False


def cleanup_session_state(session_id: str, archive_session: bool = True) -> Dict[str, Any]:
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
        "error": None
    }
    
    try:
        # Get session info before cleanup
        session_info = state_manager.get_session_info(session_id)
        
        if session_info:
            # Calculate session duration
            cleanup_stats["session_duration"] = calculate_session_duration(session_info)
            
            # Archive session data if requested
            if archive_session:
                archive_dir = Path(__file__).parent.parent / "logs" / "archived_sessions"
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


def save_session_summary_to_memory(session_id: str, stop_reason: str, cleanup_stats: Dict[str, Any]) -> None:
    """
    Save session summary and achievements to memory for future reference.
    
    Args:
        session_id: Session identifier that ended
        stop_reason: Reason for session stop
        cleanup_stats: Statistics from cleanup operation
    """
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
        if stop_reason in ["user_request", "completion"]:  # Normal endings are more relevant
            relevance_score += 0.1
            
        # Save session summary to memory
        memory_manager.save_memory(
            content=summary_content,
            memory_type=MemoryType.CRITICAL_CONTEXT,
            session_id=session_id,
            relevance_score=min(relevance_score, 1.0),
            tags=["session_summary", stop_reason, "completion"]
        )
        
        # If this was a successful session, save it as a discovery
        if stop_reason in ["completion", "success"] and duration and duration > 60:
            memory_manager.save_memory(
                content=f"Successful session completed: {duration_str} duration, achieved goals",
                memory_type=MemoryType.DISCOVERIES,
                session_id=session_id,
                relevance_score=0.8,
                tags=["success", "achievement", "completion"]
            )
            
    except Exception:
        # Silent fail - memory save shouldn't break session cleanup
        pass

def log_session_end(session_id: str, stop_reason: str, cleanup_stats: Dict[str, Any]) -> None:
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
            "cleanup_stats": cleanup_stats
        }
        
        logger.log_event(log_entry)
        
    except Exception:
        # Silent fail - logging is not critical
        pass


def handle(data: Dict[str, Any]) -> None:
    """
    Handle Stop hook events with comprehensive cleanup logic.
    
    Args:
        data: Hook event data containing stop information
    """
    cleanup_stats = {}
    
    try:
        # Extract relevant information
        hook_event_name = data.get("hook_event_name", "")
        stop_reason = data.get("stop_reason", "unknown")
        session_id = data.get("session_id", "")
        session_info = data.get("session_info", {})
        
        # Gracefully handle missing session_id
        if not session_id:
            # Try to extract from session_info or generate placeholder
            session_id = session_info.get("session_id", "unknown_session")
        
        # Update session with stop_time before cleanup
        if session_id and session_id != "unknown_session":
            try:
                # Load current sessions
                sessions_file = Path(__file__).parent.parent / "state" / "sessions.json"
                if sessions_file.exists():
                    with open(sessions_file, 'r') as f:
                        sessions_data = json.load(f)
                    
                    # Update session with stop_time
                    if "sessions" in sessions_data and session_id in sessions_data["sessions"]:
                        sessions_data["sessions"][session_id]["stop_time"] = datetime.now().isoformat()
                        sessions_data["sessions"][session_id]["stop_reason"] = stop_reason
                        
                        # Update metadata
                        sessions_data["metadata"]["last_updated"] = datetime.now().isoformat()
                        
                        # Write back atomically
                        temp_file = sessions_file.with_suffix('.tmp')
                        with open(temp_file, 'w') as f:
                            json.dump(sessions_data, f, indent=2)
                        temp_file.replace(sessions_file)
            except Exception as e:
                # Log but don't fail - this is non-critical
                print(f"Warning: Could not update session stop_time: {e}", file=sys.stderr)
        
        # Perform thread-safe cleanup
        if session_id and session_id != "unknown_session":
            # Run cleanup in current thread for immediate execution
            cleanup_stats = cleanup_session_state(
                session_id=session_id,
                archive_session=True  # Always archive on stop
            )
            
            # Save session summary to memory for future reference
            save_session_summary_to_memory(session_id, stop_reason, cleanup_stats)
            
            # Log session end with statistics
            log_session_end(session_id, stop_reason, cleanup_stats)
            
            # Schedule background cleanup of old archives (non-blocking)
            def background_cleanup():
                archive_dir = Path(__file__).parent.parent / "logs" / "archived_sessions"
                cleanup_old_archives(archive_dir, retention_days=30)
                # Also cleanup old session data
                state_manager.cleanup_old_sessions(days=7)
            
            # Run cleanup in background thread
            cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
            cleanup_thread.start()
        
        # Optional debug output (can be enabled for troubleshooting)
        debug_mode = data.get("debug", False)
        if debug_mode:
            debug_info = {
                "stop_reason": stop_reason,
                "session_id": session_id,
                "cleanup_stats": cleanup_stats,
                "hook_event_name": hook_event_name
            }
            print(f"Stop handler debug: {json.dumps(debug_info, indent=2)}", file=sys.stderr)
        
    except Exception as e:
        error_msg = f"Error in Stop handler: {e}"
        print(error_msg, file=sys.stderr)
        
        # Log error but don't exit with error code - cleanup failure shouldn't break the workflow
        try:
            logger.log_error(error_msg, {"hook_data": data})
        except Exception:
            pass


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