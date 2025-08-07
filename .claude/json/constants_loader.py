#!/usr/bin/env python3
# claude-exempt: fragile_path_construction - Using PathResolver for proper path handling and fallback for standalone usage
# claude-exempt: deep_nesting - Project structure requires deep nesting for module organization
# claude-exempt: file_without_context_manager - Using context manager correctly in _load_constants method
# claude-exempt: fragile_path_pattern - Using PathResolver for proper path handling and fallback for standalone usage
"""
Constants loader for PostToolUse hook handler.
Provides centralized access to configuration constants from constants.json.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    # Add hooks directory to sys.path for hook_tools imports
    hooks_dir = Path(__file__).parent.parent / "hooks"
    if str(hooks_dir) not in sys.path:
        sys.path.insert(0, str(hooks_dir))

    from hook_tools.utilities.path_resolver import (  # pyright: ignore[reportMissingImports]
        PathResolver,
    )

    paths = PathResolver()
    CONSTANTS_PATH = paths.claude_dir / "json" / "constants.json"
except ImportError:
    # Fallback for standalone usage
    CONSTANTS_PATH = os.path.join(os.path.dirname(__file__), "constants.json")


class ConstantsLoader:
    """Centralized constants loader for PostToolUse configuration."""

    _instance = None
    _constants: Optional[Dict[str, Any]] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._constants is None:
            self._load_constants()

    def _load_constants(self) -> None:
        """Load constants from constants.json file."""
        try:
            with open(CONSTANTS_PATH, "r", encoding="utf-8") as f:
                self._constants = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Fallback to embedded constants if file loading fails
            self._constants = self._get_fallback_constants()

    def _get_fallback_constants(self) -> Dict[str, Any]:
        """Provide fallback constants if loading fails."""
        return {
            "post_tool_use": {
                "severity_config": {
                    "critical": {"frequency": 1, "bypass_rate_limit": True},
                    "high": {"frequency": 2, "bypass_rate_limit": False},
                    "medium": {
                        "frequency_with_continuation": 3,
                        "frequency_without_continuation": 5,
                        "bypass_rate_limit": False,
                    },
                    "low": {"frequency": 7, "bypass_rate_limit": False},
                },
                "thresholds": {
                    "error_count_critical": 3,
                    "error_count_medium": 2,
                    "recommendation_count_limit": 3,
                    "memory_relevance_threshold": 0.6,
                    "memory_search_limit": 3,
                },
            }
        }

    @property
    def post_tool_use(self) -> Dict[str, Any]:
        """Get PostToolUse-specific constants."""
        if self._constants is None:
            return {}
        return self._constants.get("post_tool_use", {})

    @property
    def severity_config(self) -> Dict[str, Dict[str, Any]]:
        """Get severity configuration."""
        return self.post_tool_use.get("severity_config", {})

    @property
    def thresholds(self) -> Dict[str, Any]:
        """Get threshold values."""
        return self.post_tool_use.get("thresholds", {})

    @property
    def rate_limiting(self) -> Dict[str, Any]:
        """Get rate limiting configuration."""
        return self.post_tool_use.get("rate_limiting", {})

    @property
    def file_tools(self) -> List[str]:
        """Get list of file modification tools."""
        return self.post_tool_use.get("file_tools", [])

    @property
    def high_priority_tools(self) -> List[str]:
        """Get list of high priority tools."""
        return self.post_tool_use.get("high_priority_tools", [])

    @property
    def debug_patterns(self) -> List[str]:
        """Get debug command patterns."""
        return self.post_tool_use.get("debug_patterns", [])

    @property
    def security_patterns(self) -> List[str]:
        """Get security-related patterns."""
        return self.post_tool_use.get("security_patterns", [])

    @property
    def modern_cli_replacements(self) -> Dict[str, Dict[str, str]]:
        """Get modern CLI tool replacements."""
        return self.post_tool_use.get("modern_cli_replacements", {})

    @property
    def messages(self) -> Dict[str, str]:
        """Get message templates."""
        return self.post_tool_use.get("messages", {})

    def get_threshold(self, name: str, default: Any = None) -> Any:
        """Get specific threshold value with fallback."""
        return self.thresholds.get(name, default)

    def get_rate_limit_config(self, name: str) -> Optional[Dict[str, int]]:
        """Get rate limiting configuration for specific component."""
        config = self.rate_limiting
        max_requests_key = f"{name}_max_requests"
        window_seconds_key = f"{name}_window_seconds"

        if max_requests_key in config and window_seconds_key in config:
            return {
                "max_requests": config[max_requests_key],
                "window_seconds": config[window_seconds_key],
            }
        return None

    def get_message(self, name: str, **kwargs) -> str:
        """Get formatted message template."""
        template = self.messages.get(name, "")
        if template and kwargs:
            try:
                return template.format(**kwargs)
            except (KeyError, ValueError):
                return template
        return template


# Singleton instance
constants = ConstantsLoader()


# Convenience functions for backward compatibility
def get_severity_config() -> Dict[str, Dict[str, Any]]:
    """Get severity configuration (backward compatibility)."""
    return constants.severity_config


def get_thresholds() -> Dict[str, Any]:
    """Get thresholds (backward compatibility)."""
    return constants.thresholds


def get_file_tools() -> List[str]:
    """Get file modification tools (backward compatibility)."""
    return constants.file_tools


def get_modern_cli_replacements() -> Dict[str, Dict[str, str]]:
    """Get modern CLI replacements (backward compatibility)."""
    return constants.modern_cli_replacements
