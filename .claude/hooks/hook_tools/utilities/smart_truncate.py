#!/usr/bin/env python3
"""
Smart truncation utilities for preserving context while limiting content length.
Implements intelligent truncation that keeps beginning and end portions.
"""

from typing import Optional


def smart_truncate(
    content: str, 
    max_length: int = 1000, 
    preserve_ratio: float = 0.4,
    separator: str = " ... "
) -> str:
    """
    Intelligently truncate content while preserving context from beginning and end.
    
    Args:
        content: The content to truncate
        max_length: Maximum allowed length (default: 1000)
        preserve_ratio: Ratio of content to preserve from beginning (default: 0.4)
        separator: String to use between beginning and end portions
        
    Returns:
        Truncated content with context preserved
        
    Examples:
        >>> smart_truncate("This is a very long string that needs truncation", 30)
        "This is a very ... truncation"
        
        >>> smart_truncate("Short content", 1000)
        "Short content"
    """
    if not content or len(content) <= max_length:
        return content
        
    # Calculate space available for actual content (excluding separator)
    available_space = max_length - len(separator)
    if available_space <= 10:  # Safety check for very small limits
        return content[:max_length]
    
    # Calculate beginning and end portions
    beginning_length = int(available_space * preserve_ratio)
    ending_length = available_space - beginning_length
    
    # Extract portions
    beginning = content[:beginning_length].rstrip()
    ending = content[-ending_length:].lstrip()
    
    # Ensure we don't split words awkwardly
    beginning = _trim_to_word_boundary(beginning, from_end=True)
    ending = _trim_to_word_boundary(ending, from_end=False)
    
    return f"{beginning}{separator}{ending}"


def _trim_to_word_boundary(text: str, from_end: bool = True) -> str:
    """
    Trim text to nearest word boundary to avoid splitting words.
    
    Args:
        text: Text to trim
        from_end: If True, trim from end; if False, trim from beginning
        
    Returns:
        Text trimmed to word boundary
    """
    if not text:
        return text
        
    if from_end:
        # Find last complete word
        last_space = text.rfind(' ')
        if last_space > len(text) * 0.7:  # Only trim if we don't lose too much
            return text[:last_space]
    else:
        # Find first complete word
        first_space = text.find(' ')
        if first_space != -1 and first_space < len(text) * 0.3:  # Only trim if we don't lose too much
            return text[first_space + 1:]
            
    return text


def truncate_for_memory(content: str) -> str:
    """
    Standard truncation for memory content with 1000 character limit.
    
    Args:
        content: Content to truncate
        
    Returns:
        Truncated content optimized for memory storage
    """
    return smart_truncate(content, max_length=1000, preserve_ratio=0.45, separator=" ... ")


def truncate_for_preview(content: str, max_length: int = 200) -> str:
    """
    Truncation for preview/display purposes with smaller limits.
    
    Args:
        content: Content to truncate
        max_length: Maximum length for preview
        
    Returns:
        Truncated content optimized for preview display
    """
    return smart_truncate(content, max_length=max_length, preserve_ratio=0.6, separator="...")