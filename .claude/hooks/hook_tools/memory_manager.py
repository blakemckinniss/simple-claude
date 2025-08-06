#!/usr/bin/env python3
"""
Comprehensive memory management system for Claude Code hooks.
Provides project-based isolation, session tracking, and relevance-based retrieval.
"""

import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
from enum import Enum


class MemoryType(Enum):
    """Memory categorization types."""
    CRITICAL_CONTEXT = "critical_context"
    TOOL_PATTERNS = "tool_patterns"
    DECISIONS = "decisions"
    ERRORS = "errors"
    DISCOVERIES = "discoveries"


class MemoryManager:
    """Thread-safe memory management with project isolation and relevance scoring."""
    
    def __init__(self):
        self._lock = threading.RLock()
        self._base_dir = Path(__file__).parent.parent / "memory"
        self._ensure_memory_directory()
        
        # Memory configuration
        self._max_memories_per_project = 1000
        self._max_memory_age_days = 30
        self._relevance_decay_factor = 0.95  # Daily decay
        self._min_relevance_threshold = 0.1
    
    def _ensure_memory_directory(self) -> None:
        """Ensure memory directory structure exists."""
        self._base_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_project_hash(self, cwd: Optional[str] = None) -> str:
        """Generate project identifier from current working directory."""
        if cwd is None:
            cwd = os.getcwd()
        
        # Use first 16 chars of SHA256 hash for project identification
        return hashlib.sha256(cwd.encode()).hexdigest()[:16]
    
    def _get_project_memory_dir(self, project_hash: str) -> Path:
        """Get memory directory for specific project."""
        project_dir = self._base_dir / project_hash
        project_dir.mkdir(parents=True, exist_ok=True)
        return project_dir
    
    def _get_memory_file(self, project_hash: str) -> Path:
        """Get memory file path for project."""
        return self._get_project_memory_dir(project_hash) / "memories.json"
    
    def _read_project_memories(self, project_hash: str) -> Dict[str, Any]:
        """Read memory data for specific project."""
        memory_file = self._get_memory_file(project_hash)
        
        try:
            if memory_file.exists():
                with open(memory_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            pass
        
        # Return default structure
        return {
            "project_hash": project_hash,
            "project_path": os.getcwd(),
            "memories": {},
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "version": "1.0",
                "memory_count": 0
            }
        }
    
    def _write_project_memories(self, project_hash: str, memory_data: Dict[str, Any]) -> None:
        """Write memory data for project atomically."""
        memory_file = self._get_memory_file(project_hash)
        
        # Update metadata
        memory_data.setdefault("metadata", {})
        memory_data["metadata"]["last_updated"] = datetime.now().isoformat()
        memory_data["metadata"]["memory_count"] = len(memory_data.get("memories", {}))
        
        # Atomic write using temporary file
        temp_file = memory_file.with_suffix('.tmp')
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(memory_data, f, indent=2, ensure_ascii=False)
            temp_file.replace(memory_file)
        except Exception:
            # Clean up temp file if write failed
            if temp_file.exists():
                temp_file.unlink()
            raise
    
    def _calculate_relevance_score(self, memory_entry: Dict[str, Any]) -> float:
        """Calculate current relevance score with time decay."""
        try:
            created_at = datetime.fromisoformat(memory_entry.get("timestamp", ""))
            days_old = (datetime.now() - created_at).days
            
            # Base relevance score
            base_score = memory_entry.get("relevance_score", 1.0)
            
            # Apply time decay
            decayed_score = base_score * (self._relevance_decay_factor ** days_old)
            
            # Boost score based on access count
            access_count = memory_entry.get("access_count", 0)
            access_boost = min(access_count * 0.1, 0.5)  # Max 0.5 boost
            
            # Boost score based on memory type importance
            memory_type = memory_entry.get("memory_type", MemoryType.DISCOVERIES.value)
            type_boost = {
                MemoryType.CRITICAL_CONTEXT.value: 0.3,
                MemoryType.ERRORS.value: 0.2,
                MemoryType.DECISIONS.value: 0.15,
                MemoryType.TOOL_PATTERNS.value: 0.1,
                MemoryType.DISCOVERIES.value: 0.0
            }.get(memory_type, 0.0)
            
            return min(decayed_score + access_boost + type_boost, 1.0)
            
        except (ValueError, TypeError):
            return 0.1  # Minimum relevance for corrupted entries
    
    def _generate_memory_id(self) -> str:
        """Generate unique memory identifier."""
        return str(uuid.uuid4())
    
    def save_memory(
        self,
        content: str,
        memory_type: Union[MemoryType, str],
        session_id: Optional[str] = None,
        continuation_id: Optional[str] = None,
        relevance_score: float = 1.0,
        tags: Optional[List[str]] = None,
        cwd: Optional[str] = None
    ) -> str:
        """
        Save memory entry with project isolation.
        
        Args:
            content: Memory content
            memory_type: Type of memory (MemoryType enum or string)
            session_id: Optional session identifier
            continuation_id: Optional continuation identifier
            relevance_score: Initial relevance score (0.0-1.0)
            tags: Optional list of tags for categorization
            cwd: Override current working directory
            
        Returns:
            Generated memory_id
        """
        if isinstance(memory_type, MemoryType):
            memory_type = memory_type.value
        
        with self._lock:
            project_hash = self._get_project_hash(cwd)
            memory_data = self._read_project_memories(project_hash)
            memories = memory_data.setdefault("memories", {})
            
            memory_id = self._generate_memory_id()
            timestamp = datetime.now().isoformat()
            
            memory_entry = {
                "memory_id": memory_id,
                "content": content,
                "memory_type": memory_type,
                "timestamp": timestamp,
                "session_id": session_id,
                "continuation_id": continuation_id,
                "relevance_score": max(0.0, min(1.0, relevance_score)),
                "access_count": 0,
                "last_accessed": timestamp,
                "tags": tags or [],
                "project_hash": project_hash
            }
            
            memories[memory_id] = memory_entry
            
            # Clean up if too many memories
            if len(memories) > self._max_memories_per_project:
                self._cleanup_low_relevance_memories(project_hash, memory_data)
            
            self._write_project_memories(project_hash, memory_data)
            return memory_id
    
    def retrieve_memories(
        self,
        memory_type: Optional[Union[MemoryType, str]] = None,
        session_id: Optional[str] = None,
        continuation_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: Optional[int] = None,
        min_relevance: Optional[float] = None,
        cwd: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve memories with filtering and relevance sorting.
        
        Args:
            memory_type: Filter by memory type
            session_id: Filter by session ID
            continuation_id: Filter by continuation ID
            tags: Filter by tags (any match)
            limit: Maximum number of memories to return
            min_relevance: Minimum relevance threshold
            cwd: Override current working directory
            
        Returns:
            List of memory entries sorted by relevance (desc)
        """
        if isinstance(memory_type, MemoryType):
            memory_type = memory_type.value
        
        with self._lock:
            project_hash = self._get_project_hash(cwd)
            memory_data = self._read_project_memories(project_hash)
            memories = memory_data.get("memories", {})
            
            filtered_memories = []
            current_time = datetime.now().isoformat()
            
            for memory_id, memory_entry in memories.items():
                # Apply filters
                if memory_type and memory_entry.get("memory_type") != memory_type:
                    continue
                    
                if session_id and memory_entry.get("session_id") != session_id:
                    continue
                    
                if continuation_id and memory_entry.get("continuation_id") != continuation_id:
                    continue
                
                if tags:
                    memory_tags = set(memory_entry.get("tags", []))
                    if not memory_tags.intersection(set(tags)):
                        continue
                
                # Calculate current relevance
                current_relevance = self._calculate_relevance_score(memory_entry)
                
                # Apply relevance threshold
                relevance_threshold = min_relevance or self._min_relevance_threshold
                if current_relevance < relevance_threshold:
                    continue
                
                # Update access statistics
                memory_entry["access_count"] = memory_entry.get("access_count", 0) + 1
                memory_entry["last_accessed"] = current_time
                memory_entry["current_relevance"] = current_relevance
                
                filtered_memories.append(memory_entry.copy())
            
            # Sort by relevance (descending)
            filtered_memories.sort(key=lambda m: m.get("current_relevance", 0), reverse=True)
            
            # Apply limit
            if limit:
                filtered_memories = filtered_memories[:limit]
            
            # Update access statistics in storage
            if filtered_memories:
                self._write_project_memories(project_hash, memory_data)
            
            return filtered_memories
    
    def get_relevant_memories(
        self,
        context: str,
        memory_types: Optional[List[Union[MemoryType, str]]] = None,
        session_id: Optional[str] = None,
        limit: int = 5,
        min_relevance: float = 0.3,
        cwd: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get memories relevant to given context with content similarity.
        
        Args:
            context: Context string for relevance matching
            memory_types: Filter by memory types
            session_id: Filter by session ID
            limit: Maximum number of memories
            min_relevance: Minimum relevance threshold
            cwd: Override current working directory
            
        Returns:
            List of relevant memory entries
        """
        if memory_types:
            memory_types = [t.value if isinstance(t, MemoryType) else t for t in memory_types]
        
        with self._lock:
            project_hash = self._get_project_hash(cwd)
            memory_data = self._read_project_memories(project_hash)
            memories = memory_data.get("memories", {})
            
            relevant_memories = []
            context_lower = context.lower()
            context_words = set(context_lower.split())
            
            for memory_entry in memories.values():
                # Apply type filter
                if memory_types and memory_entry.get("memory_type") not in memory_types:
                    continue
                    
                # Apply session filter
                if session_id and memory_entry.get("session_id") != session_id:
                    continue
                
                # Calculate base relevance
                base_relevance = self._calculate_relevance_score(memory_entry)
                
                # Calculate content similarity
                content_lower = memory_entry.get("content", "").lower()
                content_words = set(content_lower.split())
                
                # Simple word overlap similarity
                if context_words and content_words:
                    overlap = len(context_words.intersection(content_words))
                    union = len(context_words.union(content_words))
                    content_similarity = overlap / union if union > 0 else 0
                else:
                    content_similarity = 0
                
                # Tag similarity
                tag_similarity = 0
                if context_words:
                    memory_tags = set(tag.lower() for tag in memory_entry.get("tags", []))
                    if memory_tags:
                        tag_overlap = len(context_words.intersection(memory_tags))
                        tag_similarity = tag_overlap / len(context_words)
                
                # Combined relevance score
                combined_relevance = (
                    base_relevance * 0.4 +
                    content_similarity * 0.4 +
                    tag_similarity * 0.2
                )
                
                if combined_relevance >= min_relevance:
                    memory_entry = memory_entry.copy()
                    memory_entry["combined_relevance"] = combined_relevance
                    memory_entry["content_similarity"] = content_similarity
                    memory_entry["tag_similarity"] = tag_similarity
                    relevant_memories.append(memory_entry)
            
            # Sort by combined relevance
            relevant_memories.sort(key=lambda m: m.get("combined_relevance", 0), reverse=True)
            
            return relevant_memories[:limit]
    
    def _cleanup_low_relevance_memories(self, project_hash: str, memory_data: Dict[str, Any]) -> None:
        """Remove low relevance memories to maintain limits."""
        memories = memory_data.get("memories", {})
        
        # Calculate relevance for all memories
        memory_scores = []
        for memory_id, memory_entry in memories.items():
            relevance = self._calculate_relevance_score(memory_entry)
            memory_scores.append((memory_id, relevance))
        
        # Sort by relevance (ascending for removal)
        memory_scores.sort(key=lambda x: x[1])
        
        # Remove lowest relevance memories
        remove_count = len(memories) - int(self._max_memories_per_project * 0.8)  # Keep 80%
        for i in range(min(remove_count, len(memory_scores))):
            memory_id = memory_scores[i][0]
            del memories[memory_id]
    
    def cleanup_old_memories(self, project_hash: Optional[str] = None, days: int = None) -> int:
        """
        Clean up old or low-relevance memories.
        
        Args:
            project_hash: Specific project to clean (None for all)
            days: Age threshold in days (uses default if None)
            
        Returns:
            Number of memories cleaned up
        """
        if days is None:
            days = self._max_memory_age_days
        
        with self._lock:
            total_cleaned = 0
            
            if project_hash:
                project_hashes = [project_hash]
            else:
                # Clean all projects
                project_hashes = [d.name for d in self._base_dir.iterdir() if d.is_dir()]
            
            cutoff_date = datetime.now() - timedelta(days=days)
            
            for proj_hash in project_hashes:
                try:
                    memory_data = self._read_project_memories(proj_hash)
                    memories = memory_data.get("memories", {})
                    
                    memories_to_remove = []
                    
                    for memory_id, memory_entry in memories.items():
                        try:
                            # Check age
                            timestamp_str = memory_entry.get("timestamp", "")
                            if timestamp_str:
                                created_at = datetime.fromisoformat(timestamp_str)
                                if created_at < cutoff_date:
                                    memories_to_remove.append(memory_id)
                                    continue
                            
                            # Check relevance
                            current_relevance = self._calculate_relevance_score(memory_entry)
                            if current_relevance < self._min_relevance_threshold:
                                memories_to_remove.append(memory_id)
                            
                        except (ValueError, TypeError):
                            # Remove corrupted entries
                            memories_to_remove.append(memory_id)
                    
                    # Remove identified memories
                    for memory_id in memories_to_remove:
                        del memories[memory_id]
                        total_cleaned += 1
                    
                    if memories_to_remove:
                        self._write_project_memories(proj_hash, memory_data)
                        
                except Exception:
                    # Skip problematic projects
                    continue
            
            return total_cleaned
    
    def get_project_stats(self, cwd: Optional[str] = None) -> Dict[str, Any]:
        """Get memory statistics for current project."""
        with self._lock:
            project_hash = self._get_project_hash(cwd)
            memory_data = self._read_project_memories(project_hash)
            memories = memory_data.get("memories", {})
            
            # Calculate statistics
            stats = {
                "project_hash": project_hash,
                "project_path": memory_data.get("project_path", "unknown"),
                "total_memories": len(memories),
                "memory_types": {},
                "average_relevance": 0.0,
                "oldest_memory": None,
                "newest_memory": None,
                "total_access_count": 0
            }
            
            if not memories:
                return stats
            
            relevance_sum = 0
            oldest_timestamp = None
            newest_timestamp = None
            
            for memory_entry in memories.values():
                # Count by type
                memory_type = memory_entry.get("memory_type", "unknown")
                stats["memory_types"][memory_type] = stats["memory_types"].get(memory_type, 0) + 1
                
                # Relevance
                relevance = self._calculate_relevance_score(memory_entry)
                relevance_sum += relevance
                
                # Timestamps
                timestamp = memory_entry.get("timestamp", "")
                if timestamp:
                    if oldest_timestamp is None or timestamp < oldest_timestamp:
                        oldest_timestamp = timestamp
                    if newest_timestamp is None or timestamp > newest_timestamp:
                        newest_timestamp = timestamp
                
                # Access count
                stats["total_access_count"] += memory_entry.get("access_count", 0)
            
            stats["average_relevance"] = relevance_sum / len(memories)
            stats["oldest_memory"] = oldest_timestamp
            stats["newest_memory"] = newest_timestamp
            
            return stats
    
    def delete_memory(self, memory_id: str, cwd: Optional[str] = None) -> bool:
        """Delete specific memory entry."""
        with self._lock:
            project_hash = self._get_project_hash(cwd)
            memory_data = self._read_project_memories(project_hash)
            memories = memory_data.get("memories", {})
            
            if memory_id in memories:
                del memories[memory_id]
                self._write_project_memories(project_hash, memory_data)
                return True
            
            return False
    
    def get_memory(self, memory_id: str, cwd: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve specific memory by ID."""
        with self._lock:
            project_hash = self._get_project_hash(cwd)
            memory_data = self._read_project_memories(project_hash)
            memories = memory_data.get("memories", {})
            
            memory_entry = memories.get(memory_id)
            if memory_entry:
                # Update access statistics
                current_time = datetime.now().isoformat()
                memory_entry["access_count"] = memory_entry.get("access_count", 0) + 1
                memory_entry["last_accessed"] = current_time
                
                self._write_project_memories(project_hash, memory_data)
                return memory_entry.copy()
            
            return None


# Global singleton instance
memory_manager = MemoryManager()


if __name__ == "__main__":
    # Test the memory manager
    print("Testing MemoryManager...")
    
    # Test saving memories
    memory_id1 = memory_manager.save_memory(
        "Critical context about user authentication flow",
        MemoryType.CRITICAL_CONTEXT,
        session_id="test-session-1",
        tags=["auth", "security"]
    )
    print(f"Saved critical context: {memory_id1}")
    
    memory_id2 = memory_manager.save_memory(
        "Error occurred when parsing JSON response",
        MemoryType.ERRORS,
        session_id="test-session-1",
        relevance_score=0.8,
        tags=["json", "parsing"]
    )
    print(f"Saved error memory: {memory_id2}")
    
    memory_id3 = memory_manager.save_memory(
        "Discovered optimal caching strategy",
        MemoryType.DISCOVERIES,
        session_id="test-session-2",
        tags=["performance", "caching"]
    )
    print(f"Saved discovery: {memory_id3}")
    
    # Test retrieval
    all_memories = memory_manager.retrieve_memories(limit=10)
    print(f"Retrieved {len(all_memories)} memories")
    
    # Test filtered retrieval
    error_memories = memory_manager.retrieve_memories(memory_type=MemoryType.ERRORS)
    print(f"Retrieved {len(error_memories)} error memories")
    
    # Test relevant memories
    relevant = memory_manager.get_relevant_memories("authentication security", limit=3)
    print(f"Found {len(relevant)} relevant memories for 'authentication security'")
    
    # Test project stats
    stats = memory_manager.get_project_stats()
    print(f"Project stats: {stats}")
    
    # Test cleanup
    cleaned = memory_manager.cleanup_old_memories(days=0)  # Clean all
    print(f"Cleaned up {cleaned} memories")
    
    print("MemoryManager tests completed successfully!")