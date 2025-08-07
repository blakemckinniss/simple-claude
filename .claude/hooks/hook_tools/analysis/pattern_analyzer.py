#!/usr/bin/env python3
"""
Pattern Analysis Module
Provides functions for analyzing cross-file patterns and calculating context depth.
"""

from typing import Dict, Any
from collections import defaultdict


def calculate_context_depth(prompt: str) -> Dict[str, Any]:
    """Dynamically calculate context depth based on prompt complexity.
    
    Args:
        prompt: The user prompt to analyze
        
    Returns:
        Dict containing context configuration with keys:
        - top_k: Number of files to include
        - include_body: Whether to include function/class bodies
        - depth: String description of analysis depth
        - focus: Optional focus area for specialized analysis
    """
    prompt_lower = prompt.lower()
    
    # Deep analysis keywords
    if any(word in prompt_lower for word in ['debug', 'deep dive', 'analyze', 'investigate', 'trace', 'why']):
        return {"top_k": 50, "include_body": True, "depth": "deep"}
    
    # Refactoring keywords
    elif any(word in prompt_lower for word in ['refactor', 'improve', 'optimize', 'clean', 'restructure']):
        return {"top_k": 30, "include_body": True, "depth": "refactor", "focus": "complexity"}
    
    # Overview keywords
    elif any(word in prompt_lower for word in ['summary', 'overview', 'quick', 'brief', 'what']):
        return {"top_k": 10, "include_body": False, "depth": "overview"}
    
    # Performance keywords
    elif any(word in prompt_lower for word in ['performance', 'slow', 'bottleneck', 'speed']):
        return {"top_k": 25, "include_body": True, "depth": "performance", "focus": "hotspots"}
    
    # Default moderate depth
    return {"top_k": 20, "include_body": False, "depth": "moderate"}


def aggregate_cross_file_patterns(verbose_outline: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate patterns across multiple files for project-wide insights.
    
    Args:
        verbose_outline: Dictionary mapping file paths to their analysis summaries
        
    Returns:
        Dict containing aggregated patterns with keys:
        - repeated_patterns: Dict of import/pattern counts
        - naming_inconsistencies: List of naming issues
        - architectural_patterns: List of detected architectural patterns
        - common_issues: Dict categorizing issues by type
    """
    patterns = {
        "repeated_patterns": defaultdict(int),
        "naming_inconsistencies": [],
        "architectural_patterns": [],
        "common_issues": defaultdict(list)
    }
    
    # Analyze patterns across files
    for filepath, summary in verbose_outline.items():
        if 'imports' in summary:
            # Track import patterns
            for imp in summary['imports']:
                patterns['repeated_patterns'][imp] += 1
        
        if 'todos' in summary:
            # Aggregate TODOs by category
            for todo in summary['todos']:
                category = 'general'
                if 'refactor' in todo.lower():
                    category = 'refactor'
                elif 'fix' in todo.lower() or 'bug' in todo.lower():
                    category = 'bug'
                elif 'optimize' in todo.lower() or 'performance' in todo.lower():
                    category = 'performance'
                
                patterns['common_issues'][category].append({'file': filepath, 'todo': todo})
    
    # Identify architectural patterns
    import_strs = str(patterns['repeated_patterns'])
    if 'flask' in import_strs.lower():
        patterns['architectural_patterns'].append('Flask Web Framework')
    if 'django' in import_strs.lower():
        patterns['architectural_patterns'].append('Django Web Framework')
    if 'fastapi' in import_strs.lower():
        patterns['architectural_patterns'].append('FastAPI')
    
    return dict(patterns)