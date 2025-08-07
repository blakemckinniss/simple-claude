#!/usr/bin/env python3
"""
Enhanced Relevance Scoring Module with Semantic Embeddings
Provides advanced file relevance scoring using semantic understanding.
"""

import re
import os
import json
import numpy as np
from typing import Dict, List, Any, Optional
from functools import lru_cache

try:
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False


class SemanticRelevanceScorer:
    """Semantic relevance scorer with embedding-based similarity."""
    
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2', cache_dir: Optional[str] = None):
        """Initialize semantic relevance scorer with embedding model.
        
        Args:
            model_name: Sentence transformer model name
            cache_dir: Optional directory for caching embeddings
        """
        if not EMBEDDINGS_AVAILABLE:
            raise ImportError("sentence-transformers and scikit-learn required. Install with: pip install sentence-transformers scikit-learn")
            
        self.model = SentenceTransformer(model_name)
        self.cache_dir = cache_dir or os.path.join(os.path.dirname(__file__), '.embedding_cache')
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Task-specific boost configurations
        self.task_boost_factors = {
            'debug': 1.5,      # Boost debugging-related contexts
            'error': 1.4,      # Boost error handling contexts  
            'fix': 1.3,        # Boost fix-related contexts
            'performance': 1.3, # Boost performance-related contexts
            'test': 1.2,       # Boost test-related contexts
            'default': 1.0
        }
        
        # Error/debug related keywords for task detection
        self.debug_indicators = {'error', 'exception', 'traceback', 'bug', 'fix', 'crash', 'fail', 'issue'}
        self.performance_indicators = {'slow', 'performance', 'optimize', 'bottleneck', 'speed', 'latency'}

    @lru_cache(maxsize=500)
    def _get_embedding(self, text: str) -> np.ndarray:
        """Cached embedding generation with LRU caching.
        
        Args:
            text: Input text to embed
        
        Returns:
            Numpy array of text embedding
        """
        return self.model.encode(text, convert_to_tensor=False)

    def _get_file_cache_key(self, filepath: str) -> str:
        """Generate cache key for file embedding."""
        # Use file path hash for cache key to handle long paths
        import hashlib
        path_hash = hashlib.md5(filepath.encode()).hexdigest()[:12]
        return os.path.join(self.cache_dir, f"{path_hash}_embedding.npz")

    def _load_cached_embedding(self, filepath: str) -> Optional[np.ndarray]:
        """Load cached embedding for a file if available.
        
        Args:
            filepath: Path to the file
        
        Returns:
            Cached embedding or None
        """
        cache_file = self._get_file_cache_key(filepath)
        
        try:
            if os.path.exists(cache_file):
                data = np.load(cache_file)
                return data['embedding']
        except Exception:
            pass
        
        return None

    def _save_cached_embedding(self, filepath: str, embedding: np.ndarray):
        """Save embedding to cache.
        
        Args:
            filepath: Path to the file
            embedding: Numpy array of embedding
        """
        cache_file = self._get_file_cache_key(filepath)
        
        try:
            np.savez_compressed(cache_file, embedding=embedding)
        except Exception:
            pass

    def detect_task_type(self, prompt: str) -> str:
        """Detect task type from prompt for contextual boosting.
        
        Args:
            prompt: User's input prompt
            
        Returns:
            Detected task type
        """
        prompt_lower = prompt.lower()
        
        # Check for debugging/error indicators
        if any(indicator in prompt_lower for indicator in self.debug_indicators):
            return 'debug'
        
        # Check for performance indicators
        if any(indicator in prompt_lower for indicator in self.performance_indicators):
            return 'performance'
        
        # Check for test-related keywords
        if 'test' in prompt_lower or 'pytest' in prompt_lower:
            return 'test'
        
        return 'default'

    def score_file_relevance(self, prompt: str, filepath: str, summary: Dict[str, Any], 
                           task_type: Optional[str] = None) -> float:
        """Advanced semantic relevance scoring using embeddings.
        
        Args:
            prompt: User's input prompt
            filepath: Path to the file
            summary: File summary dictionary
            task_type: Type of task for contextual boosting
        
        Returns:
            Relevance score between 0.0 and 1.0
        """
        # Auto-detect task type if not provided
        if task_type is None:
            task_type = self.detect_task_type(prompt)
        
        # Construct comprehensive text representation
        file_components = []
        
        # Add filepath components
        file_components.append(os.path.basename(filepath))
        file_components.append(os.path.dirname(filepath))
        
        # Add summary components if available
        if isinstance(summary, dict):
            if 'description' in summary:
                file_components.append(str(summary['description']))
            if 'functions' in summary:
                file_components.extend(summary['functions'][:5])  # Top 5 functions
            if 'classes' in summary:
                file_components.extend(summary['classes'][:5])    # Top 5 classes
            if 'imports' in summary:
                file_components.extend(summary['imports'][:3])    # Top 3 imports
        
        # Combine text for file embedding
        file_text = ' '.join(filter(None, file_components))
        
        # Check cache first
        cached_embedding = self._load_cached_embedding(filepath)
        
        if cached_embedding is not None:
            file_embedding = cached_embedding
        else:
            # Generate new embedding
            file_embedding = self._get_embedding(file_text)
            # Cache for future use
            self._save_cached_embedding(filepath, file_embedding)
        
        # Get prompt embedding
        prompt_embedding = self._get_embedding(prompt)
        
        # Compute cosine similarity
        similarity = cosine_similarity(
            prompt_embedding.reshape(1, -1),
            file_embedding.reshape(1, -1)
        )[0][0]
        
        # Apply task-specific boost
        boost_factor = self.task_boost_factors.get(task_type, 1.0)
        
        # Apply special boost for error-related files in debug mode
        if task_type == 'debug':
            if 'error' in filepath.lower() or 'exception' in filepath.lower():
                boost_factor *= 1.2
        
        return min(similarity * boost_factor, 1.0)

    def filter_relevant_files(self, prompt: str, outline: Dict[str, Any], 
                            top_k: int = 20, task_type: Optional[str] = None) -> Dict[str, Any]:
        """Filter outline using semantic embeddings with task-aware scoring.
        
        Args:
            prompt: User's input prompt
            outline: Dictionary mapping file paths to summaries
            top_k: Maximum number of files to return
            task_type: Type of task for contextual boosting
        
        Returns:
            Filtered outline with most relevant files
        """
        # Auto-detect task type if not provided
        if task_type is None:
            task_type = self.detect_task_type(prompt)
        
        scored_files = [
            (path, summary, self.score_file_relevance(prompt, path, summary, task_type))
            for path, summary in outline.items()
        ]
        
        # Sort by relevance score, descending
        scored_files.sort(key=lambda x: x[2], reverse=True)
        
        return {path: summary for path, summary, _ in scored_files[:top_k]}


# Global instance for backward compatibility
_scorer_instance = None

def _get_scorer() -> SemanticRelevanceScorer:
    """Get or create global scorer instance."""
    global _scorer_instance
    if _scorer_instance is None and EMBEDDINGS_AVAILABLE:
        _scorer_instance = SemanticRelevanceScorer()
    return _scorer_instance


def extract_keywords(prompt: str) -> List[str]:
    """Extract meaningful keywords from user prompt.
    
    Args:
        prompt: User prompt text
        
    Returns:
        List of meaningful keywords with stopwords removed
    """
    # Enhanced keyword extraction with task awareness
    stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for'}
    
    # Detect if this is a debug/error context and preserve those keywords
    debug_keywords = {'error', 'exception', 'traceback', 'bug', 'fix', 'crash', 'fail'}
    if any(keyword in prompt.lower() for keyword in debug_keywords):
        stop_words = stop_words - debug_keywords
    
    words = re.findall(r'\b\w+\b', prompt.lower())
    keywords = [w for w in words if w not in stop_words and len(w) > 2]
    return keywords


def score_file_relevance(prompt: str, filepath: str, summary: Dict[str, Any]) -> float:
    """Score file relevance using semantic embeddings or fallback to keyword matching.
    
    Args:
        prompt: User prompt text
        filepath: Path to the file
        summary: File summary dictionary
        
    Returns:
        Relevance score between 0.0 and 1.0
    """
    # Try to use semantic scoring if available
    if EMBEDDINGS_AVAILABLE:
        try:
            scorer = _get_scorer()
            if scorer:
                return scorer.score_file_relevance(prompt, filepath, summary)
        except Exception:
            pass  # Fall back to keyword matching
    
    # Fallback to original Jaccard similarity
    prompt_tokens = set(extract_keywords(prompt))
    
    # Extract tokens from file path and summary
    file_tokens = set(re.findall(r'\b\w+\b', filepath.lower()))
    file_tokens.update(re.findall(r'\b\w+\b', str(summary).lower()))
    
    # Calculate Jaccard similarity
    intersection = prompt_tokens & file_tokens
    union = prompt_tokens | file_tokens
    return len(intersection) / len(union) if union else 0.0


def filter_relevant_files(prompt: str, outline: Dict[str, Any], top_k: int = 20) -> Dict[str, Any]:
    """Filter outline using semantic embeddings or fallback to keyword matching.
    
    Args:
        prompt: User prompt text
        outline: Dictionary mapping file paths to summaries
        top_k: Maximum number of files to return
        
    Returns:
        Filtered outline with only the most relevant files
    """
    # Try to use semantic filtering if available
    if EMBEDDINGS_AVAILABLE:
        try:
            scorer = _get_scorer()
            if scorer:
                return scorer.filter_relevant_files(prompt, outline, top_k)
        except Exception:
            pass  # Fall back to keyword matching
    
    # Fallback to original implementation
    scored_files = [(path, summary, score_file_relevance(prompt, path, summary)) 
                    for path, summary in outline.items()]
    scored_files.sort(key=lambda x: x[2], reverse=True)
    return {path: summary for path, summary, _ in scored_files[:top_k]}