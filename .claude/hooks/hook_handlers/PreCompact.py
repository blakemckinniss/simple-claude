#!/usr/bin/env python3
"""
Generic PreCompact hook handler.
This hook is called before Claude compacts its memory/context.
"""

import json
import sys
from typing import Dict, Any


def handle(data: Dict[str, Any]) -> None:
    """
    Handle PreCompact hook events.
    
    Args:
        data: Hook event data containing compaction information
    """
    try:
        # Extract relevant information
        hook_event_name = data.get("hook_event_name", "")
        context_size = data.get("context_size", 0)
        memory_info = data.get("memory_info", {})
        
        # Generic handler - could be extended to:
        # - Log memory usage
        # - Save important context
        # - Trigger external backups
        # - Monitor performance
        # - etc.
        
        # For now, just pass through silently
        # Uncomment below to see what data is available:
        # print(f"PreCompact: context_size={context_size}", file=sys.stderr)
        
    except Exception as e:
        print(f"Error in PreCompact handler: {e}", file=sys.stderr)
        sys.exit(1)