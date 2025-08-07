#!/usr/bin/env python3
"""
Cache Utilities Module
Provides caching functionality for tool outputs to reduce redundancy.
"""

import time
from typing import Dict, Any, Optional


# Tool output cache for synthesis
TOOL_OUTPUT_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = 300  # 5 minutes


def synthesize_tool_outputs(cache_key: Optional[str] = None, output: Optional[Any] = None) -> Optional[Any]:
    """Cache and synthesize tool outputs to reduce redundancy.
    
    Args:
        cache_key: Key to store/retrieve cached output
        output: Output to cache (when storing)
        
    Returns:
        Cached output if retrieving, None otherwise
    """
    global TOOL_OUTPUT_CACHE
    current_time = time.time()
    
    # Clean expired cache entries
    TOOL_OUTPUT_CACHE = {k: v for k, v in TOOL_OUTPUT_CACHE.items() 
                        if current_time - v['timestamp'] < CACHE_TTL}
    
    if cache_key and output:
        # Store output in cache
        TOOL_OUTPUT_CACHE[cache_key] = {
            'output': output,
            'timestamp': current_time
        }
    elif cache_key:
        # Retrieve from cache
        cached = TOOL_OUTPUT_CACHE.get(cache_key)
        if cached:
            return cached['output']
    
    return None