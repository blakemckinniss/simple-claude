#!/usr/bin/env python3
"""
Thread-safe state manager for Claude hooks continuation tracking.
Manages session state in separate JSON file outside of settings.json schema.
"""

import json
import sys
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

from hook_tools.utilities.path_resolver import PathResolver

# Initialize path resolver for consistent path handling
paths = PathResolver()


class StateManager:
    """Thread-safe state management for session continuation tracking."""

    def __init__(self):
        self._lock = threading.RLock()
        self._state_file = Path(__file__).parent.parent / "state" / "sessions.json"
        self._ensure_state_directory()

    def _ensure_state_directory(self) -> None:
        """Ensure state directory exists."""
        self._state_file.parent.mkdir(parents=True, exist_ok=True)

    def _read_state(self) -> Dict[str, Any]:
        """Read state data from JSON file."""
        try:
            if self._state_file.exists():
                with open(self._state_file, "r") as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

        # Return default structure
        return {
            "sessions": {},
            "metadata": {"created_at": datetime.now().isoformat(), "version": "1.0"},
        }

    def _write_state(self, state_data: Dict[str, Any]) -> None:
        """Write state data to JSON file atomically."""
        # Update metadata
        state_data.setdefault("metadata", {})
        state_data["metadata"]["last_updated"] = datetime.now().isoformat()

        # Atomic write using temporary file
        temp_file = self._state_file.with_suffix(".tmp")
        try:
            with open(temp_file, "w") as f:
                json.dump(state_data, f, indent=2)
            temp_file.replace(self._state_file)
        except Exception:
            # Clean up temp file if write failed
            if temp_file.exists():
                temp_file.unlink()
            raise

    def generate_session_id(self) -> str:
        """Generate a new unique session ID."""
        return str(uuid.uuid4())

    def initialize_session(self, session_id: str) -> bool:
        """
        Initialize a new session or update existing one.

        Args:
            session_id: Session identifier

        Returns:
            True if session was newly created, False if updated
        """
        with self._lock:
            state = self._read_state()
            sessions = state.setdefault("sessions", {})

            is_new = session_id not in sessions

            if is_new:
                sessions[session_id] = {
                    "continuation_id": None,
                    "created_at": datetime.now().isoformat(),
                    "last_updated": datetime.now().isoformat(),
                }
            else:
                sessions[session_id]["last_updated"] = datetime.now().isoformat()

            self._write_state(state)
            return is_new

    def get_continuation_id(self, session_id: str) -> Optional[str]:
        """
        Get continuation_id for a session.

        Args:
            session_id: Session identifier

        Returns:
            continuation_id or None if not set/found
        """
        with self._lock:
            state = self._read_state()
            sessions = state.get("sessions", {})
            session_data = sessions.get(session_id, {})
            return session_data.get("continuation_id")

    def set_continuation_id(self, session_id: str, continuation_id: str) -> None:
        """
        Set continuation_id for a session.

        Args:
            session_id: Session identifier
            continuation_id: Continuation ID to store
        """
        with self._lock:
            state = self._read_state()
            sessions = state.setdefault("sessions", {})

            # Initialize session if it doesn't exist
            if session_id not in sessions:
                self.initialize_session(session_id)
                # Re-read state after initialization
                state = self._read_state()
                sessions = state["sessions"]

            sessions[session_id]["continuation_id"] = continuation_id
            sessions[session_id]["last_updated"] = datetime.now().isoformat()

            self._write_state(state)

    def has_continuation(self, session_id: str) -> bool:
        """
        Check if session has an active continuation.

        Args:
            session_id: Session identifier

        Returns:
            True if session has continuation_id set
        """
        continuation_id = self.get_continuation_id(session_id)
        return continuation_id is not None and continuation_id.strip() != ""

    def increment_tool_count(self, session_id: str) -> int:
        """
        Increment and return the tool use count for a session.

        Args:
            session_id: Session identifier

        Returns:
            Updated tool count for the session
        """
        with self._lock:
            state = self._read_state()
            sessions = state.setdefault("sessions", {})

            # Initialize session if it doesn't exist
            if session_id not in sessions:
                self.initialize_session(session_id)
                # Re-read state after initialization
                state = self._read_state()
                sessions = state["sessions"]

            # Increment tool count
            current_count = sessions[session_id].get("tool_count", 0)
            new_count = current_count + 1
            sessions[session_id]["tool_count"] = new_count
            sessions[session_id]["last_updated"] = datetime.now().isoformat()

            self._write_state(state)
            return new_count

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get complete session information.

        Args:
            session_id: Session identifier

        Returns:
            Session data dictionary or None if not found
        """
        with self._lock:
            state = self._read_state()
            sessions = state.get("sessions", {})
            return sessions.get(session_id)

    def update_session(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update session data with arbitrary key-value pairs.

        Args:
            session_id: Session identifier
            updates: Dictionary of data to update in the session

        Returns:
            True if session was updated, False if session not found
        """
        with self._lock:
            state = self._read_state()
            sessions = state.setdefault("sessions", {})

            # Initialize session if it doesn't exist
            if session_id not in sessions:
                self.initialize_session(session_id)
                # Re-read state after initialization
                state = self._read_state()
                sessions = state["sessions"]

            # Update session data with new values
            sessions[session_id].update(updates)
            sessions[session_id]["last_updated"] = datetime.now().isoformat()

            self._write_state(state)
            return True

    def clear_continuation(self, session_id: str) -> bool:
        """
        Clear continuation_id for a session without removing the session.

        Args:
            session_id: Session identifier

        Returns:
            True if continuation was cleared, False if session not found
        """
        with self._lock:
            state = self._read_state()
            sessions = state.get("sessions", {})

            if session_id in sessions:
                sessions[session_id]["continuation_id"] = None
                sessions[session_id]["last_updated"] = datetime.now().isoformat()
                sessions[session_id]["stopped_at"] = datetime.now().isoformat()
                self._write_state(state)
                return True

            return False

    def cleanup_old_sessions(self, days: int = 7) -> int:
        """
        Remove sessions older than specified days.

        Args:
            days: Number of days to keep sessions

        Returns:
            Number of sessions cleaned up
        """
        with self._lock:
            state = self._read_state()
            sessions = state.get("sessions", {})

            cutoff_date = datetime.now() - timedelta(days=days)
            sessions_to_remove = []

            for session_id, session_data in sessions.items():
                try:
                    created_at_str = session_data.get("created_at", "")
                    if created_at_str:
                        created_at = datetime.fromisoformat(created_at_str)
                        if created_at < cutoff_date:
                            sessions_to_remove.append(session_id)
                except (ValueError, TypeError):
                    # Remove sessions with invalid timestamps
                    sessions_to_remove.append(session_id)

            # Remove old sessions
            for session_id in sessions_to_remove:
                del sessions[session_id]

            if sessions_to_remove:
                self._write_state(state)

            return len(sessions_to_remove)

    def get_all_sessions(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all session data (primarily for debugging/monitoring).

        Returns:
            Dictionary of all sessions
        """
        with self._lock:
            state = self._read_state()
            return state.get("sessions", {})

    def migrate_from_settings(self, settings_file: Path) -> int:
        """
        Migrate continuation_tracking data from settings.json to state file.

        Args:
            settings_file: Path to settings.json file

        Returns:
            Number of sessions migrated
        """
        if not settings_file.exists():
            return 0

        try:
            with open(settings_file, "r") as f:
                settings_data = json.load(f)

            continuation_tracking = settings_data.get("continuation_tracking", {})
            old_sessions = continuation_tracking.get("sessions", {})

            if not old_sessions:
                return 0

            # Migrate to new state format
            with self._lock:
                state = self._read_state()
                sessions = state.setdefault("sessions", {})

                migrated_count = 0
                for session_id, session_data in old_sessions.items():
                    # Only migrate if not already exists or if old data is newer
                    if session_id not in sessions:
                        sessions[session_id] = session_data.copy()
                        migrated_count += 1
                    else:
                        # Check if old data is newer
                        try:
                            old_updated = datetime.fromisoformat(
                                session_data.get("last_updated", "")
                            )
                            current_updated = datetime.fromisoformat(
                                sessions[session_id].get("last_updated", "")
                            )
                            if old_updated > current_updated:
                                sessions[session_id] = session_data.copy()
                                migrated_count += 1
                        except (ValueError, TypeError):
                            pass

                if migrated_count > 0:
                    self._write_state(state)

                return migrated_count

        except (json.JSONDecodeError, OSError):
            return 0


# Global singleton instance
state_manager = StateManager()


def migrate_from_settings_json() -> None:
    """Migration helper function to be called during initialization."""
    settings_file = Path(__file__).parent.parent / "settings.json"
    if settings_file.exists():
        migrated = state_manager.migrate_from_settings(settings_file)
        if migrated > 0:
            print(
                f"Migrated {migrated} sessions from settings.json to state file",
                file=sys.stderr,
            )


if __name__ == "__main__":
    # Test the state manager
    import sys

    print("Testing StateManager...")

    # Test session operations
    session_id = state_manager.generate_session_id()
    print(f"Generated session ID: {session_id}")

    # Initialize session
    is_new = state_manager.initialize_session(session_id)
    print(f"Session initialized (new: {is_new})")

    # Test continuation operations
    test_continuation = "test-continuation-123"
    state_manager.set_continuation_id(session_id, test_continuation)
    retrieved = state_manager.get_continuation_id(session_id)
    print(f"Continuation ID stored and retrieved: {retrieved == test_continuation}")

    # Test has_continuation
    has_cont = state_manager.has_continuation(session_id)
    print(f"Has continuation: {has_cont}")

    # Test increment_tool_count
    count1 = state_manager.increment_tool_count(session_id)
    count2 = state_manager.increment_tool_count(session_id)
    count3 = state_manager.increment_tool_count(session_id)
    print(f"Tool count increments: {count1}, {count2}, {count3}")

    # Test session info
    info = state_manager.get_session_info(session_id)
    print(f"Session info: {info}")

    # Test clear continuation
    cleared = state_manager.clear_continuation(session_id)
    print(f"Continuation cleared: {cleared}")

    # Test cleanup (shouldn't remove recent session)
    cleaned = state_manager.cleanup_old_sessions(days=0)
    print(f"Cleaned up {cleaned} old sessions")

    print("StateManager tests completed successfully!")
