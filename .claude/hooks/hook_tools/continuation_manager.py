#!/usr/bin/env python3
"""
Continuation management module for Claude hooks.
Handles extraction and storage of continuation IDs from ZEN tool responses.
"""

import json
from typing import Dict, Any

from .state_manager import state_manager


def extract_continuation_id(
    tool_name: str, tool_input: Dict[str, Any], tool_response: Any
) -> str:
    """
    Extract continuation_id from mcp__zen tool responses.

    Args:
        tool_name: Name of the tool that was used
        tool_input: Input parameters to the tool
        tool_response: Response from the tool (can be dict, list, or string)

    Returns:
        continuation_id if found, empty string otherwise
    """
    # Only process mcp__zen tools
    if not tool_name.startswith("mcp__zen__"):
        return ""

    # Handle different response types
    response_to_check = tool_response

    # If response is a list, check the first item
    if isinstance(tool_response, list) and len(tool_response) > 0:
        response_to_check = tool_response[0]

        # If the first item is a dict with a 'text' field containing JSON
        if isinstance(response_to_check, dict) and "text" in response_to_check:
            text_content = response_to_check.get("text", "")
            if isinstance(text_content, str):
                try:
                    response_to_check = json.loads(text_content)
                except (json.JSONDecodeError, ValueError):
                    pass

    # If response is a string, try to parse it as JSON
    elif isinstance(response_to_check, str):
        try:
            response_to_check = json.loads(response_to_check)
        except (json.JSONDecodeError, ValueError):
            pass

    # Check for continuation_id in the response
    if isinstance(response_to_check, dict):
        # Look for continuation_offer structure
        continuation_offer = response_to_check.get("continuation_offer", {})
        if isinstance(continuation_offer, dict):
            continuation_id = continuation_offer.get("continuation_id", "")
            if continuation_id:
                return continuation_id

        # Also check direct continuation_id field
        continuation_id = response_to_check.get("continuation_id", "")
        if continuation_id:
            return continuation_id

    return ""


def store_continuation_id(session_id: str, continuation_id: str) -> None:
    """
    Store continuation_id for the current session.

    Args:
        session_id: Current session identifier
        continuation_id: Continuation ID to store
    """
    if session_id and continuation_id:
        state_manager.set_continuation_id(session_id, continuation_id)


def get_continuation_id(session_id: str) -> str:
    """
    Get stored continuation_id for the current session.

    Args:
        session_id: Current session identifier

    Returns:
        continuation_id if found, empty string otherwise
    """
    if session_id:
        return state_manager.get_continuation_id(session_id) or ""
    return ""


def has_continuation(session_id: str) -> bool:
    """
    Check if session has an existing continuation ID.

    Args:
        session_id: Current session identifier

    Returns:
        True if session has continuation ID, False otherwise
    """
    return bool(get_continuation_id(session_id))


def clear_continuation_id(session_id: str) -> None:
    """
    Clear continuation_id for the current session.

    Args:
        session_id: Current session identifier
    """
    if session_id:
        state_manager.set_continuation_id(session_id, "")