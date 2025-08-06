#!/usr/bin/env python3
"""
Centralized path resolution module for hook_tools.

This module provides consistent path resolution for all hook_tools modules,
eliminating the need for fragile sys.path.insert() manipulations and 
duplicated path calculation logic.

Key Features:
- Automatic sys.path configuration on import
- Consistent path resolution across all modules  
- Context manager for temporary path additions
- Cached path calculations for performance
- Robust error handling with fallbacks

Usage:
    from hook_tools.utilities.path_resolver import paths
    
    # Get common paths
    constants_file = paths.constants_file
    project_root = paths.project_root
    
    # Load constants easily
    constants = paths.load_constants()
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional
from contextlib import contextmanager
from functools import cached_property


class PathResolver:
    """Centralized path resolution for hook_tools ecosystem."""
    
    def __init__(self):
        """Initialize path resolver with automatic sys.path setup."""
        self._setup_sys_path()
    
    def _setup_sys_path(self) -> None:
        """Configure sys.path once on initialization."""
        # Add hook_tools root to sys.path for internal imports
        hook_tools_root = self.hook_tools_dir
        if str(hook_tools_root) not in sys.path:
            sys.path.insert(0, str(hook_tools_root))
        
        # Add hooks root for accessing hook_logger and other hook modules
        hooks_root = self.hooks_dir
        if str(hooks_root) not in sys.path:
            sys.path.insert(0, str(hooks_root))
    
    @cached_property
    def _current_file(self) -> Path:
        """Get current file path (this module's path)."""
        return Path(__file__).resolve()
    
    @cached_property
    def utilities_dir(self) -> Path:
        """Get utilities directory path."""
        return self._current_file.parent
    
    @cached_property
    def hook_tools_dir(self) -> Path:
        """Get hook_tools root directory path."""
        return self.utilities_dir.parent
    
    @cached_property 
    def hooks_dir(self) -> Path:
        """Get hooks root directory path."""
        return self.hook_tools_dir.parent
    
    @cached_property
    def claude_dir(self) -> Path:
        """Get .claude directory path."""
        return self.hooks_dir.parent
    
    @cached_property
    def project_root(self) -> Path:
        """Get project root directory path."""
        return self.claude_dir.parent
    
    @cached_property
    def json_dir(self) -> Path:
        """Get json configuration directory path."""
        return self.claude_dir / "json"
    
    @cached_property
    def constants_file(self) -> Path:
        """Get constants.json file path."""
        return self.json_dir / "constants.json"
    
    def get_env_file_path(self, constants: Optional[Dict[str, Any]] = None) -> Path:
        """
        Get environment file path using constants configuration.
        
        Args:
            constants: Optional pre-loaded constants dict
            
        Returns:
            Path to .env file
        """
        if constants is None:
            constants = self.load_constants()
        
        env_relative_path = constants["file_paths"]["env_file_relative_path"]
        return self.project_root / env_relative_path
    
    def load_constants(self) -> Dict[str, Any]:
        """
        Load configuration constants from JSON file.
        
        Returns:
            Configuration constants dictionary
            
        Raises:
            RuntimeError: If constants file is not found or contains invalid JSON
        """
        try:
            with open(self.constants_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"Constants file not found: {self.constants_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON in constants file: {e}")
    
    def load_env(self, constants: Optional[Dict[str, Any]] = None) -> None:
        """
        Load environment variables from .env file.
        
        Args:
            constants: Optional pre-loaded constants dict
            
        Side Effects:
            Sets environment variables from .env file into os.environ
        """
        env_path = self.get_env_file_path(constants)
        
        if not env_path.exists():
            return
            
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()
    
    @contextmanager
    def temporary_path(self, path: Path):
        """
        Context manager for temporarily adding a path to sys.path.
        
        Args:
            path: Path to temporarily add
            
        Example:
            with paths.temporary_path(some_custom_dir):
                import custom_module
        """
        path_str = str(path.resolve())
        added = False
        
        if path_str not in sys.path:
            sys.path.insert(0, path_str)
            added = True
        
        try:
            yield
        finally:
            if added and path_str in sys.path:
                sys.path.remove(path_str)
    
    def get_relative_path(self, target: Path, base: Optional[Path] = None) -> Path:
        """
        Get relative path from base to target.
        
        Args:
            target: Target path
            base: Base path (defaults to project_root)
            
        Returns:
            Relative path from base to target
        """
        if base is None:
            base = self.project_root
            
        try:
            return target.relative_to(base)
        except ValueError:
            # Paths don't share common base, return absolute
            return target.resolve()
    
    def ensure_dir(self, path: Path) -> Path:
        """
        Ensure directory exists, creating it if necessary.
        
        Args:
            path: Directory path to ensure exists
            
        Returns:
            The path (for chaining)
        """
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    def get_memory_dir(self) -> Path:
        """Get memory storage directory path."""
        return self.hooks_dir / "memory"
    
    def get_state_dir(self) -> Path:
        """Get state storage directory path.""" 
        return self.hooks_dir / "state"
    
    def get_hook_handlers_dir(self) -> Path:
        """Get hook handlers directory path."""
        return self.hooks_dir / "hook_handlers"
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"PathResolver(project_root={self.project_root})"


# Global instance - automatically configures sys.path on import
paths = PathResolver()


# Convenience functions for backward compatibility
def get_project_root() -> Path:
    """Get project root directory path."""
    return paths.project_root


def get_hooks_dir() -> Path:  
    """Get hooks directory path."""
    return paths.hooks_dir


def get_hook_tools_dir() -> Path:
    """Get hook_tools directory path."""
    return paths.hook_tools_dir


def load_constants() -> Dict[str, Any]:
    """Load configuration constants."""
    return paths.load_constants()


def load_env() -> None:
    """Load environment variables from .env file."""
    paths.load_env()