#!/usr/bin/env python3
"""
SessionStart hook handler for initializing global continuation tracking.
Ensures thread-safe initialization of session state and outputs initialization context for Claude.
"""

import sys
import subprocess
import json
import uuid
from pathlib import Path
from typing import Dict, Any

# Import state manager for continuation tracking
sys.path.insert(0, str(Path(__file__).parent.parent))
from hook_tools.state_manager import state_manager

def handle(input_data: Dict[str, Any]) -> None:
    """
    Handle session start by initializing continuation tracking and outputting context for Claude.
    
    Args:
        input_data: Hook input containing session information
    """
    session_id = None
    session_info = None
    
    try:
        # Extract or generate session ID
        session_id = input_data.get('session_id')
        if not session_id:
            # Generate session ID if not provided
            session_id = state_manager.generate_session_id()
            
        # Initialize continuation tracking for this session
        state_manager.initialize_session(session_id)
        
        # Get session info for context
        session_info = state_manager.get_session_info(session_id)
        
        # Cleanup old sessions (runs in background, non-blocking)
        state_manager.cleanup_old_sessions(days=7)
        
    except Exception as e:
        # Don't let session initialization errors break the hook
        print(f"Warning: Session initialization failed: {e}", file=sys.stderr)
    
    # Get the latest continuation_id from any previous session
    latest_continuation_id = None
    try:
        all_sessions = state_manager.get_all_sessions()
        # Find the most recent session with a non-null continuation_id
        sessions_with_continuation = [
            (sid, sdata) for sid, sdata in all_sessions.items()
            if sid != session_id  # Exclude current session
        ]
        if sessions_with_continuation:
            # Sort by last_updated timestamp to get the most recent
            sessions_with_continuation.sort(
                key=lambda x: x[1].get('last_updated', ''),
                reverse=True
            )
            latest_continuation_id = sessions_with_continuation[0][1].get('continuation_id')
    except Exception as e:
        print(f"Warning: Could not retrieve latest continuation_id: {e}", file=sys.stderr)
    
    # Format continuation_id display
    continuation_display = f"Latest continuation_id: {latest_continuation_id}" if latest_continuation_id else "No previous continuation_id available"
    
    # Update session_info with the latest continuation_id for display
    if session_info and latest_continuation_id:
        session_info['continuation_id'] = latest_continuation_id
    
    # Create context message for Claude
    context_message = f"""
CLAUDE SESSION INITIALIZED (ID: {session_id})

Continuation System Active:
- Session state tracking enabled
- Cross-conversation memory available
- {continuation_display}
- Use mcp__zen tools with continuation_id parameter for persistent context

Available mcp__zen tools with continuation support:
- mcp__zen__chat: General discussion with continuation
- mcp__zen__debug: Step-by-step debugging with state persistence  
- mcp__zen__analyze: Code analysis with cumulative insights
- mcp__zen__thinkdeep: Complex investigation with memory
- mcp__zen__consensus: Multi-model consensus with history
- mcp__zen__planner: Sequential planning with context
- mcp__zen__codereview: Comprehensive code review workflow
- mcp__zen__refactor: Refactoring analysis with continuity

To continue previous conversations, use the continuation_id parameter in any mcp__zen tool call.
Session info: {json.dumps(session_info, indent=2) if session_info else 'Available'}

ALWAYS USE:
- zen for planning and recommendations
- serena for semantic code retrieval and editing tools
- context7 for up to date documentation on third party code
- sequential thinking for any decision making

READ the CLAUDE.MD root file before you do anything."""
    
    # Add git ls-files output for context
    try:
        git_files_result = subprocess.run(
            ['git', 'ls-files'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if git_files_result.returncode == 0:
            git_files_list = git_files_result.stdout.strip()
            if git_files_list:
                context_message += f"\n\nGIT TRACKED FILES:\n{git_files_list}"
    except Exception as e:
        print(f"Warning: Could not retrieve git ls-files: {e}", file=sys.stderr)
    
    # Add session IDs from sessions.json
    try:
        sessions_file = Path(__file__).parent.parent / "state" / "sessions.json"
        if sessions_file.exists():
            with open(sessions_file, 'r') as f:
                sessions_data = json.load(f)
            
            if "sessions" in sessions_data:
                session_ids = list(sessions_data["sessions"].keys())
                if session_ids:
                    # Limit to the latest 3 session IDs
                    recent_session_ids = session_ids[-3:] if len(session_ids) > 3 else session_ids
                    context_message += f"\n\nRECENT SESSION IDS IN claude/state/sessions.json:\n" + "\n".join(recent_session_ids)
    except Exception as e:
        print(f"Warning: Could not retrieve session IDs: {e}", file=sys.stderr)
    
    # Strip any trailing whitespace from final message
    context_message = context_message.strip()
    
    # Output JSON with additionalContext for Claude to see
    output = {
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context_message
        }
    }
    
    print(json.dumps(output, indent=2))
    sys.exit(0)

if __name__ == "__main__":
    try:
        raw_input = sys.stdin.read().strip()
        if raw_input:
            input_data = json.loads(raw_input)
        else:
            # Handle case where no input is provided
            input_data = {}
        
        handle(input_data)
        
    except json.JSONDecodeError as e:
        print(f"Error parsing input JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error in SessionStart handler: {e}", file=sys.stderr)
        sys.exit(1)