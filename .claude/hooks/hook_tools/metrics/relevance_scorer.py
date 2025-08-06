#!/usr/bin/env python3
"""
Relevance Scoring Module
Provides file relevance scoring functions for context filtering.
"""

import re
from typing import Dict, List, Any


def extract_keywords(prompt: str) -> List[str]:
    """Extract meaningful keywords from user prompt.
    
    Args:
        prompt: User prompt text
        
    Returns:
        List of meaningful keywords with stopwords removed
    """
    # Remove common words and extract meaningful tokens
    stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 
                  'of', 'with', 'by', 'from', 'up', 'about', 'into', 'through', 'during',
                  'how', 'what', 'where', 'when', 'why', 'can', 'could', 'should', 'would'}
    words = re.findall(r'\b\w+\b', prompt.lower())
    keywords = [w for w in words if w not in stop_words and len(w) > 2]
    return keywords


def score_file_relevance(prompt: str, filepath: str, summary: Dict[str, Any]) -> float:
    """Score file relevance to prompt using keyword matching.
    
    Args:
        prompt: User prompt text
        filepath: Path to the file
        summary: File summary dictionary
        
    Returns:
        Relevance score between 0.0 and 1.0
    """
    prompt_tokens = set(extract_keywords(prompt))
    
    # Extract tokens from file path and summary
    file_tokens = set(re.findall(r'\b\w+\b', filepath.lower()))
    file_tokens.update(re.findall(r'\b\w+\b', str(summary).lower()))
    
    # Calculate Jaccard similarity
    intersection = prompt_tokens & file_tokens
    union = prompt_tokens | file_tokens
    return len(intersection) / len(union) if union else 0.0


def filter_relevant_files(prompt: str, outline: Dict[str, Any], top_k: int = 20) -> Dict[str, Any]:
    """Filter outline to only include files most relevant to the prompt.
    
    Args:
        prompt: User prompt text
        outline: Dictionary mapping file paths to summaries
        top_k: Maximum number of files to return
        
    Returns:
        Filtered outline with only the most relevant files
    """
    scored_files = [(path, summary, score_file_relevance(prompt, path, summary)) 
                    for path, summary in outline.items()]
    scored_files.sort(key=lambda x: x[2], reverse=True)
    return {path: summary for path, summary, _ in scored_files[:top_k]}