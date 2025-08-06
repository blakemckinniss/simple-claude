#!/usr/bin/env python3
"""
Outline generation utilities for project summarization.

This module provides functions to generate project outlines and bootstrap
summary data for semantic analysis.
"""

import os
import json
import time
from pathlib import Path
from subprocess import check_output
from typing import Dict, Any

# Import dependencies
from .file_summarizer import summarize_file


def generate_outline(file_list):
    """
    Generate a project outline by summarizing files.
    
    Args:
        file_list: List of file paths to process
        
    Returns:
        dict: Mapping of file paths to their summaries
        
    Performance Note:
        Processes files in batches and limits total to 500 files for performance.
    """
    outline = {}
    # Performance: Process files in batches and limit total
    max_files = min(len(file_list), 500)
    
    for path in file_list[:max_files]:
        if os.path.exists(path):
            try:
                outline[path] = summarize_file(path)
            except Exception as e:
                # Log error but continue processing
                outline[path] = {"description": f"Error processing file: {e}"}
    return outline


def bootstrap_summary(json_path: str, constants: Dict[str, Any]) -> Dict[str, Any]:
    """
    Bootstrap project summary with caching.
    
    Args:
        json_path: Path to the summary cache file
        constants: Configuration constants dictionary
        
    Returns:
        dict: Project outline/summary data
        
    Caching:
        Uses 1-hour cache to avoid regenerating summaries unnecessarily.
        Cache is invalidated if older than 3600 seconds (1 hour).
    """
    if os.path.exists(json_path):
        try:
            # Check if cache is recent (within 1 hour)
            cache_age = time.time() - os.path.getmtime(json_path)
            if cache_age < 3600:  # 1 hour cache
                with open(json_path, 'r') as f:
                    return json.load(f)
        except:
            pass

    try:
        file_list = check_output(constants["git_commands"]["list_files"], text=True).splitlines()
        # Performance: Limit to 500 files max
        file_list = file_list[:500]
    except Exception as e:
        # Note: Would normally log error here, but avoiding logger import
        print(f"Cannot list files from git: {e}")
        return {}

    outline = generate_outline(file_list)
    try:
        os.makedirs(os.path.dirname(json_path), exist_ok=True)
        with open(json_path, 'w', encoding=constants["file_encoding"]["default"]) as f:
            json.dump(outline, f, indent=constants["json_formatting"]["indent"])
    except Exception as e:
        # Note: Would normally log error here, but avoiding logger import
        print(f"Failed to write summary cache: {e}")

    return outline