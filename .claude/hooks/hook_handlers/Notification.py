#!/usr/bin/env python3
"""
Generic Notification hook handler.
This hook is called when Claude sends a notification.
"""

import json
import sys
from typing import Dict, Any


def handle(data: Dict[str, Any]) -> None:
    """
    Handle Notification hook events.
    
    Args:
        data: Hook event data containing notification information
    """
    try:
        # Extract relevant information
        hook_event_name = data.get("hook_event_name", "")
        notification_type = data.get("notification_type", "")
        message = data.get("message", "")
        
        # Generic handler - could be extended to:
        # - Log notifications
        # - Send external notifications
        # - Filter notifications
        # - Format notifications
        # - etc.
        
        # For now, just pass through silently
        # Uncomment below to see what data is available:
        # print(f"Notification: {notification_type} - {message}", file=sys.stderr)
        
    except Exception as e:
        print(f"Error in Notification handler: {e}", file=sys.stderr)
        sys.exit(1)