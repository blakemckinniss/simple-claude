#!/usr/bin/env python3
"""
Ultra-optimized UserPromptSubmit hook handler.
Target: <50ms execution time with aggressive optimizations.
"""

import json
import sys
import os
import subprocess
import time
from typing import Dict, Any, Optional
from threading import Thread
from functools import lru_cache

# Optimized cache with memory management
_cache = {}
_cache_timestamps = {}
CACHE_TTL = 45  # Reduced TTL for fresher data
CACHE_MAX_SIZE = 50  # Smaller cache to reduce memory overhead

@lru_cache(maxsize=16)
def _get_env_path() -> str:
    """Cached environment PATH."""
    return os.environ.get('PATH', '')

def _get_cache(key: str) -> Optional[Any]:
    """Get cached value if still valid."""
    if key in _cache:
        if time.time() - _cache_timestamps.get(key, 0) < CACHE_TTL:
            return _cache[key]
        # Expired - remove immediately
        _cache.pop(key, None)
        _cache_timestamps.pop(key, None)
    return None

def _set_cache(key: str, value: Any) -> None:
    """Set cached value with aggressive cleanup."""
    # Aggressive cache cleanup
    if len(_cache) >= CACHE_MAX_SIZE:
        # Remove oldest 20% of entries
        oldest_keys = sorted(_cache_timestamps.items(), key=lambda x: x[1])[:10]
        for k, _ in oldest_keys:
            _cache.pop(k, None)
            _cache_timestamps.pop(k, None)
    
    _cache[key] = value
    _cache_timestamps[key] = time.time()

def _run_ultra_fast(command: list, cwd: str) -> Optional[str]:
    """Ultra-fast command execution with minimal overhead."""
    try:
        # Pre-allocate result for speed
        result = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=0.15,
            env={'PATH': _get_env_path()}, bufsize=0, shell=False
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except:
        return None

@lru_cache(maxsize=16)
def _is_git_repo(cwd: str) -> bool:
    """Cached git repo detection."""
    return os.path.exists(os.path.join(cwd, '.git'))

def _collect_git_minimal(cwd: str) -> Dict[str, Any]:
    """Minimal git collection - only essential info."""
    # Time-bucketed cache key (30-second buckets)
    bucket = int(time.time() // 30)
    cache_key = f"git_{hash(cwd)}_{bucket}"
    
    cached = _get_cache(cache_key)
    if cached:
        return cached
    
    if not _is_git_repo(cwd):
        result = {"git": False}
        _set_cache(cache_key, result)
        return result
    
    # Single git command for all info
    git_info = _run_ultra_fast(['git', 'symbolic-ref', '--short', 'HEAD'], cwd)
    result = {
        "git": True,
        "branch": git_info[:20] if git_info else "unknown"  # Truncate branch name
    }
    
    _set_cache(cache_key, result)
    return result

def _collect_files_minimal(cwd: str) -> Dict[str, Any]:
    """Minimal file collection - count only."""
    # Time-bucketed cache (60-second buckets for file counts)
    bucket = int(time.time() // 60)
    cache_key = f"files_{hash(cwd)}_{bucket}"
    
    cached = _get_cache(cache_key)
    if cached:
        return cached
    
    # Try fd with strict limits
    fd_output = _run_ultra_fast(['fd', '.', '-t', 'f', '--max-results', '200'], cwd)
    if fd_output:
        count = len(fd_output.split('\n'))
        result = {"files": min(count, 200)}  # Cap at 200 for consistency
    else:
        # Ultra-fast fallback
        try:
            items = os.listdir(cwd)
            count = sum(1 for _ in items if os.path.isfile(os.path.join(cwd, _)))
            result = {"files": count}
        except:
            result = {"files": 0}
    
    _set_cache(cache_key, result)
    return result

def _collect_context_minimal(cwd: str) -> str:
    """Minimal context collection - return formatted string directly."""
    git_data = _collect_git_minimal(cwd)
    file_data = _collect_files_minimal(cwd)
    
    # Build context string directly (no JSON overhead)
    parts = []
    if git_data.get("git"):
        parts.append(f"git:{git_data.get('branch', 'main')}")
    parts.append(f"files:{file_data['files']}")
    parts.append(f"dir:{os.path.basename(cwd)[:15]}")  # Truncate long dir names
    
    return " ".join(parts)

def handle(input_data: Dict[str, Any]) -> None:
    """Ultra-optimized hook handler - target <50ms execution."""
    # Fast validation
    if (input_data.get("hook_event_name") != "UserPromptSubmit" or 
        not input_data.get("cwd")):
        sys.exit(2)
    
    try:
        cwd = input_data["cwd"]
        
        # Get minimal context
        context = _collect_context_minimal(cwd)
        
        # Pre-built output structure (avoid dict creation overhead)
        output_json = f'{{"continue":true,"hookSpecificOutput":{{"hookEventName":"UserPromptSubmit","additionalContext":"{context}"}}}}'
        
        print(output_json)
        sys.exit(0)
        
    except:
        # Ultra-minimal fallback
        print('{"continue":true,"hookSpecificOutput":{"hookEventName":"UserPromptSubmit"}}')
        sys.exit(0)

def main():
    """Ultra-optimized main entry point."""
    try:
        # Read with size limit
        raw_input = sys.stdin.read(50000)  # 50KB limit
        if not raw_input:
            sys.exit(2)
        
        input_data = json.loads(raw_input)
        handle(input_data)
        
    except:
        sys.exit(2)

if __name__ == "__main__":
    main()