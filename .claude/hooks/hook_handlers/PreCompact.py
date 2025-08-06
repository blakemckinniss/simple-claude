#!/usr/bin/env python3
"""
Generic PreCompact hook handler.
This hook is called before Claude compacts its memory/context.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any

# Import memory manager for critical context storage
from hook_tools.utilities.path_resolver import PathResolver
paths = PathResolver()
from hook_tools.memory_manager import memory_manager, MemoryType


def handle(data: Dict[str, Any]) -> None:
    """
    Handle PreCompact hook events.
    Save critical memories before compaction with high relevance scores.
    
    Args:
        data: Hook event data containing compaction information
    """
    try:
        # Extract relevant information
        hook_event_name = data.get("hook_event_name", "")
        context_size = data.get("context_size", 0)
        memory_info = data.get("memory_info", {})
        session_id = data.get("session_id", "")
        compaction_reason = data.get("compaction_reason", "unknown")
        
        # Save critical context before compaction
        if context_size > 0 or memory_info:
            try:
                # Extract important context information
                context_summary = f"Context size: {context_size}"
                if memory_info:
                    context_summary += f", Memory info: {str(memory_info)[:200]}"
                
                # Determine if this is manual or automatic compaction
                is_manual = compaction_reason == "manual"
                relevance_score = 0.9 if is_manual else 0.7
                
                # Save critical context memory
                memory_manager.save_memory(
                    content=f"Pre-compaction context: {context_summary}. Reason: {compaction_reason}",
                    memory_type=MemoryType.CRITICAL_CONTEXT,
                    session_id=session_id,
                    relevance_score=relevance_score,
                    tags=["compaction", "context-preservation", compaction_reason]
                )
                
                # Save any important discoveries or decisions from memory_info
                if isinstance(memory_info, dict):
                    for key, value in memory_info.items():
                        if key in ["important_decisions", "key_discoveries", "critical_errors"]:
                            memory_manager.save_memory(
                                content=f"{key}: {str(value)[:500]}",
                                memory_type=MemoryType.DISCOVERIES if "discover" in key else 
                                           MemoryType.DECISIONS if "decision" in key else 
                                           MemoryType.ERRORS,
                                session_id=session_id,
                                relevance_score=0.8,
                                tags=["compaction", key, "pre-compaction"]
                            )
                            
            except Exception as e:
                # Log error but don't fail the compaction process
                print(f"Warning: Could not save pre-compaction memories: {e}", file=sys.stderr)
        
    except Exception as e:
        print(f"Error in PreCompact handler: {e}", file=sys.stderr)
        sys.exit(1)