#!/usr/bin/env python3
"""
Generic SubagentStop hook handler.
This hook is called when a subagent stops processing.
"""

import json
import sys
from typing import Dict, Any


def handle(data: Dict[str, Any]) -> None:
    """
    Handle SubagentStop hook events.
    
    Args:
        data: Hook event data containing subagent stop information
    """
    try:
        # Extract relevant information
        hook_event_name = data.get("hook_event_name", "")
        subagent_id = data.get("subagent_id", "")
        stop_reason = data.get("stop_reason", "")
        subagent_info = data.get("subagent_info", {})
        
        # Generic handler - could be extended to:
        # - Log subagent completion
        # - Collect subagent results
        # - Track subagent performance
        # - Handle subagent errors
        # - etc.
        
        # For now, just pass through silently
        # Uncomment below to see what data is available:
        # print(f"SubagentStop: {subagent_id} - {stop_reason}", file=sys.stderr)
        
    except Exception as e:
        print(f"Error in SubagentStop handler: {e}", file=sys.stderr)
        sys.exit(1)