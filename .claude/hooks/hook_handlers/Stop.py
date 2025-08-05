#!/usr/bin/env python3
"""
Generic Stop hook handler.
This hook is called when Claude stops processing.
"""

import json
import sys
from typing import Dict, Any


def handle(data: Dict[str, Any]) -> None:
    """
    Handle Stop hook events.
    
    Args:
        data: Hook event data containing stop information
    """
    try:
        # Extract relevant information
        hook_event_name = data.get("hook_event_name", "")
        stop_reason = data.get("stop_reason", "")
        session_info = data.get("session_info", {})
        
        # Generic handler - could be extended to:
        # - Log session end
        # - Save session data
        # - Send completion notifications
        # - Clean up resources
        # - etc.
        
        # For now, just pass through silently
        # Uncomment below to see what data is available:
        # print(f"Stop: {stop_reason} - {json.dumps(data, indent=2)}", file=sys.stderr)
        
    except Exception as e:
        print(f"Error in Stop handler: {e}", file=sys.stderr)
        sys.exit(1)