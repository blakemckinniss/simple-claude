"""
Configuration for optimized UserPromptSubmit hook.
"""

import os

# Environment-based configuration
CONFIG = {
    # Enable/disable API enhancement (default: enabled if API key present)
    'enable_api_enhancement': os.getenv('CLAUDE_HOOK_ENABLE_API', '1') == '1',
    
    # Cache TTL in seconds (default: 60 seconds)
    'cache_ttl': int(os.getenv('CLAUDE_HOOK_CACHE_TTL', '60')),
    
    # Maximum timeout for fast commands (default: 0.5 seconds)
    'fast_timeout': float(os.getenv('CLAUDE_HOOK_FAST_TIMEOUT', '0.5')),
    
    # Enable/disable collectors (default: all enabled)
    'enable_git_collector': os.getenv('CLAUDE_HOOK_ENABLE_GIT', '1') == '1',
    'enable_code_collector': os.getenv('CLAUDE_HOOK_ENABLE_CODE', '1') == '1',
    'enable_system_collector': os.getenv('CLAUDE_HOOK_ENABLE_SYSTEM', '1') == '1',
    
    # API rate limiting (requests per minute)
    'api_rate_limit': int(os.getenv('CLAUDE_HOOK_API_RATE_LIMIT', '10')),
    
    # Debug mode (default: disabled)
    'debug_mode': os.getenv('CLAUDE_HOOK_DEBUG', '0') == '1',
}