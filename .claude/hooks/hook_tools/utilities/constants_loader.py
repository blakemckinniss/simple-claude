#!/usr/bin/env python3
"""
Constants and environment loading utilities.

DEPRECATED: This module is deprecated. Use path_resolver directly:
    from utilities.path_resolver import paths
    constants = paths.load_constants()
    paths.load_env()

This module now provides backward compatibility wrappers around path_resolver.
"""

import warnings
from typing import Dict, Any
from .path_resolver import paths


def load_constants() -> Dict[str, Any]:
    """
    Load configuration constants from JSON file.
    
    DEPRECATED: Use paths.load_constants() instead.
    
    Returns:
        dict: Configuration constants loaded from constants.json
        
    Raises:
        RuntimeError: If constants file is not found or contains invalid JSON
    """
    warnings.warn(
        "load_constants() is deprecated. Use 'from utilities.path_resolver import paths; paths.load_constants()' instead.",
        DeprecationWarning,
        stacklevel=2
    )
    return paths.load_constants()


def load_env(constants: Dict[str, Any]) -> None:
    """
    Load environment variables from .env file.
    
    DEPRECATED: Use paths.load_env() instead.
    
    Args:
        constants: Configuration constants dictionary (ignored, will be loaded automatically)
        
    Side Effects:
        Sets environment variables from .env file into os.environ
    """
    warnings.warn(
        "load_env() is deprecated. Use 'from utilities.path_resolver import paths; paths.load_env()' instead.",
        DeprecationWarning,
        stacklevel=2
    )
    paths.load_env(constants)