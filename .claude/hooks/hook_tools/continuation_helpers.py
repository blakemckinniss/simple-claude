#!/usr/bin/env python3
"""
Simple continuation tracking helpers for Claude hooks.
Provides easy-to-use functions for continuation management.
"""

from typing import Optional

# Import shared dependencies (sys.path now managed by path_resolver)
from state_manager import state_manager


def get_continuation_id(session_id: str) -> str:
    """
    Get continuation_id for a session.
    
    Args:
        session_id: Current session identifier
        
    Returns:
        continuation_id if exists, empty string otherwise
    """
    if not session_id:
        return ""
    
    continuation_id = state_manager.get_continuation_id(session_id)
    return continuation_id or ""


def set_continuation_id(session_id: str, continuation_id: str) -> None:
    """
    Set continuation_id for a session.
    
    Args:
        session_id: Current session identifier
        continuation_id: Continuation ID to store
    """
    if session_id and continuation_id:
        state_manager.set_continuation_id(session_id, continuation_id)


def has_continuation(session_id: str) -> bool:
    """
    Check if session has an active continuation.
    
    Args:
        session_id: Current session identifier
        
    Returns:
        True if session has continuation, False otherwise
    """
    if not session_id:
        return False
    
    return state_manager.has_continuation(session_id)


def format_continuation_context(session_id: str) -> str:
    """
    Format continuation information for context injection.
    
    Args:
        session_id: Current session identifier
        
    Returns:
        Formatted continuation context string
    """
    if not session_id:
        return ""
    
    continuation_id = get_continuation_id(session_id)
    if continuation_id:
        return f"\n\nCONTINUATION_ID: {continuation_id} (Use this in mcp__zen tools for conversation continuity)"
    else:
        return "\n\nNO_CONTINUATION: This is a new conversation thread"


def extract_and_store_continuation(session_id: str, tool_name: str, tool_output: dict) -> bool:
    """
    Extract continuation_id from tool output and store it.
    
    Args:
        session_id: Current session identifier
        tool_name: Name of the tool that was used
        tool_output: Output from the tool
        
    Returns:
        True if continuation_id was found and stored, False otherwise
    """
    if not session_id or not tool_name.startswith('mcp__zen__'):
        return False
    
    if not isinstance(tool_output, dict):
        return False
    
    # Look for continuation_offer structure
    continuation_offer = tool_output.get('continuation_offer', {})
    if isinstance(continuation_offer, dict):
        continuation_id = continuation_offer.get('continuation_id', '')
        if continuation_id:
            set_continuation_id(session_id, continuation_id)
            return True
    
    # Also check direct continuation_id field
    continuation_id = tool_output.get('continuation_id', '')
    if continuation_id:
        set_continuation_id(session_id, continuation_id)
        return True
    
    return False