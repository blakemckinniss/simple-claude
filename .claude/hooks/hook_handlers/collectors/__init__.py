"""
Collectors package for gathering context data in parallel.
"""

from .git_collector import GitCollector
from .code_collector import CodeCollector  
from .system_collector import SystemCollector

__all__ = ['GitCollector', 'CodeCollector', 'SystemCollector']