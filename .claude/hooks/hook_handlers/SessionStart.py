#!/usr/bin/env python3
"""
Generic SessionStart hook handler.
This hook is called when a Claude session starts.
"""

import json
import sys
from typing import Dict, Any


def handle(data: Dict[str, Any]) -> None:
    """
    Handle SessionStart hook events.
    
    Args:
        data: Hook event data containing session start information
    """
    try:
        # Extract relevant information
        hook_event_name = data.get("hook_event_name", "")
        session_id = data.get("session_id", "")
        user_info = data.get("user_info", {})
        environment_info = data.get("environment_info", {})
        
        # Generic handler - could be extended to:
        # - Log session start
        # - Initialize resources
        # - Load user preferences
        # - Set up monitoring
        # - etc.
        
        # For now, just pass through silently
        # Uncomment below to see what data is available:
        # print(f"SessionStart: {session_id}", file=sys.stderr)
        
    except Exception as e:
        print(f"Error in SessionStart handler: {e}", file=sys.stderr)
        sys.exit(1)