#!/usr/bin/env python3
"""
Comprehensive logging system for Claude Code hooks.
Provides logging with text abridging, rotation, and organization.
"""

import hashlib
import json
import time
import traceback
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional


class HookLogger:
    """Comprehensive logger for Claude Code hooks."""
    
    # Log levels
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    
    # Abridging thresholds
    MAX_STRING_LENGTH = 1000  # Max length for string fields
    MAX_ARRAY_ITEMS = 20     # Max items to show in arrays
    MAX_OBJECT_DEPTH = 5     # Max depth for nested objects
    MAX_LOG_FILE_SIZE = 10 * 1024 * 1024  # 10MB per log file
    MAX_LOG_FILES = 100      # Max log files per directory
    
    # Cleanup settings
    MAX_LOG_AGE_DAYS = 7     # Delete logs older than this
    MAX_TOTAL_SIZE_MB = 500  # Maximum total log size in MB
    CLEANUP_INTERVAL_HOURS = 6  # Run cleanup every N hours
    
    def __init__(self, base_dir: str = "/home/devcontainers/better-claude/.claude/logs"):
        """Initialize the comprehensive logger."""
        self.base_dir = Path(base_dir)
        self.hooks_dir = self.base_dir / "hooks"
        self.system_dir = self.base_dir / "system"
        self.errors_dir = self.base_dir / "errors"
        
        # Create directories
        for dir_path in [self.hooks_dir, self.system_dir, self.errors_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Session tracking
        self.session_cache = {}
        self.log_level = self.INFO
        
        # Performance tracking
        self.metrics = {
            "total_logs": 0,
            "abridged_count": 0,
            "errors_count": 0,
            "start_time": time.time()
        }
        
        # Initialize cleanup tracking
        self.last_cleanup = datetime.now()
        self.cleanup_state_file = self.base_dir / ".cleanup_state"
        self._load_cleanup_state()
    
    def set_log_level(self, level: int):
        """Set the logging level."""
        self.log_level = level
    
    def _abridge_value(self, value: Any, depth: int = 0) -> Any:
        """Abridge large values to prevent log overflow."""
        if depth > self.MAX_OBJECT_DEPTH:
            return f"<TRUNCATED: max depth {self.MAX_OBJECT_DEPTH} exceeded>"
        
        if isinstance(value, str):
            if len(value) > self.MAX_STRING_LENGTH:
                self.metrics["abridged_count"] += 1
                hash_val = hashlib.md5(value.encode()).hexdigest()[:8]
                return f"{value[:self.MAX_STRING_LENGTH]}... <TRUNCATED: {len(value)} chars, hash: {hash_val}>"
            return value
        
        elif isinstance(value, (list, tuple)):
            if len(value) > self.MAX_ARRAY_ITEMS:
                self.metrics["abridged_count"] += 1
                abridged = [self._abridge_value(v, depth + 1) for v in value[:self.MAX_ARRAY_ITEMS]]
                return abridged + [f"... <TRUNCATED: {len(value) - self.MAX_ARRAY_ITEMS} more items>"]
            return [self._abridge_value(v, depth + 1) for v in value]
        
        elif isinstance(value, dict):
            abridged = {}
            for k, v in list(value.items())[:self.MAX_ARRAY_ITEMS]:
                abridged[k] = self._abridge_value(v, depth + 1)
            if len(value) > self.MAX_ARRAY_ITEMS:
                self.metrics["abridged_count"] += 1
                abridged["__truncated__"] = f"{len(value) - self.MAX_ARRAY_ITEMS} more items"
            return abridged
        
        elif isinstance(value, (int, float, bool, type(None))):
            return value
        
        else:
            # For other types, convert to string and abridge
            str_val = str(value)
            return self._abridge_value(str_val, depth)
    
    def _get_log_path(self, hook_event: str, session_id: str, timestamp: datetime) -> Path:
        """Get the appropriate log file path for a hook event."""
        # Organize by: hooks/{event_type}/{date}/{hour}/session_{id}.jsonl
        event_dir = self.hooks_dir / hook_event.lower()
        date_dir = event_dir / timestamp.strftime("%Y-%m-%d")
        hour_dir = date_dir / timestamp.strftime("%H")
        hour_dir.mkdir(parents=True, exist_ok=True)
        
        # Use session ID for filename
        session_short = session_id[:8] if session_id else "unknown"
        log_file = hour_dir / f"session_{session_short}.jsonl"
        
        # Check rotation
        if log_file.exists() and log_file.stat().st_size > self.MAX_LOG_FILE_SIZE:
            # Rotate log file
            rotation_index = 1
            while True:
                rotated_file = hour_dir / f"session_{session_short}.{rotation_index}.jsonl"
                if not rotated_file.exists():
                    log_file.rename(rotated_file)
                    break
                rotation_index += 1
                if rotation_index > self.MAX_LOG_FILES:
                    # Delete oldest files if too many
                    self._cleanup_old_logs(hour_dir)
                    break
        
        return log_file
    
    def _cleanup_old_logs(self, directory: Path):
        """Clean up old log files when limit is reached."""
        log_files = sorted(directory.glob("*.jsonl*"), key=lambda f: f.stat().st_mtime)
        if len(log_files) > self.MAX_LOG_FILES:
            for old_file in log_files[:len(log_files) - self.MAX_LOG_FILES]:
                old_file.unlink()
    
    def _load_cleanup_state(self):
        """Load last cleanup timestamp from state file."""
        if self.cleanup_state_file.exists():
            try:
                with open(self.cleanup_state_file, 'r') as f:
                    state = json.load(f)
                    self.last_cleanup = datetime.fromisoformat(state.get('last_cleanup', datetime.now().isoformat()))
            except Exception:
                pass
    
    def _save_cleanup_state(self):
        """Save cleanup timestamp to state file."""
        try:
            with open(self.cleanup_state_file, 'w') as f:
                json.dump({'last_cleanup': self.last_cleanup.isoformat()}, f)
        except Exception:
            pass
    
    def _should_run_cleanup(self) -> bool:
        """Check if cleanup should run based on interval."""
        hours_since_cleanup = (datetime.now() - self.last_cleanup).total_seconds() / 3600
        return hours_since_cleanup >= self.CLEANUP_INTERVAL_HOURS
    
    def _get_directory_size(self, directory: Path) -> int:
        """Get total size of all files in directory tree."""
        total_size = 0
        for path in directory.rglob('*'):
            if path.is_file():
                total_size += path.stat().st_size
        return total_size
    
    def _comprehensive_cleanup(self):
        """Perform comprehensive log cleanup based on age and size limits."""
        if not self._should_run_cleanup():
            return
        
        try:
            cleanup_stats = {
                'deleted_files': 0,
                'deleted_bytes': 0,
                'start_time': datetime.now().isoformat()
            }
            
            # Age-based cleanup
            cutoff_date = datetime.now() - timedelta(days=self.MAX_LOG_AGE_DAYS)
            
            for base_dir in [self.hooks_dir, self.system_dir, self.errors_dir]:
                if not base_dir.exists():
                    continue
                    
                for log_file in base_dir.rglob('*.jsonl*'):
                    if log_file.is_file():
                        file_mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                        if file_mtime < cutoff_date:
                            file_size = log_file.stat().st_size
                            log_file.unlink()
                            cleanup_stats['deleted_files'] += 1
                            cleanup_stats['deleted_bytes'] += file_size
                
                # Also clean up .log files (human-readable logs)
                for log_file in base_dir.rglob('*.log'):
                    if log_file.is_file():
                        file_mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                        if file_mtime < cutoff_date:
                            file_size = log_file.stat().st_size
                            log_file.unlink()
                            cleanup_stats['deleted_files'] += 1
                            cleanup_stats['deleted_bytes'] += file_size
            
            # Size-based cleanup
            total_size_mb = self._get_directory_size(self.base_dir) / (1024 * 1024)
            
            if total_size_mb > self.MAX_TOTAL_SIZE_MB:
                # Get all log files sorted by modification time (oldest first)
                all_logs = []
                for base_dir in [self.hooks_dir, self.system_dir, self.errors_dir]:
                    if base_dir.exists():
                        all_logs.extend(base_dir.rglob('*.jsonl*'))
                        all_logs.extend(base_dir.rglob('*.log'))
                
                all_logs = sorted(
                    [f for f in all_logs if f.is_file()],
                    key=lambda f: f.stat().st_mtime
                )
                
                # Delete oldest files until under size limit
                for log_file in all_logs:
                    if total_size_mb <= self.MAX_TOTAL_SIZE_MB:
                        break
                    
                    file_size = log_file.stat().st_size
                    log_file.unlink()
                    cleanup_stats['deleted_files'] += 1
                    cleanup_stats['deleted_bytes'] += file_size
                    total_size_mb -= file_size / (1024 * 1024)
            
            # Clean up empty directories
            for base_dir in [self.hooks_dir, self.system_dir]:
                if base_dir.exists():
                    for dir_path in sorted(base_dir.rglob('*'), reverse=True):
                        if dir_path.is_dir() and not any(dir_path.iterdir()):
                            dir_path.rmdir()
            
            # Update cleanup state
            self.last_cleanup = datetime.now()
            self._save_cleanup_state()
            
            # Log cleanup stats
            if cleanup_stats['deleted_files'] > 0:
                cleanup_stats['end_time'] = datetime.now().isoformat()
                cleanup_stats['deleted_mb'] = round(cleanup_stats['deleted_bytes'] / (1024 * 1024), 2)
                self._log_system_event("cleanup_completed", cleanup_stats)
                
        except Exception as e:
            self._log_error({
                'error': f"Cleanup failed: {str(e)}",
                'timestamp': datetime.now().isoformat()
            })
    
    def _log_system_event(self, event_type: str, data: Dict[str, Any]):
        """Log system events like cleanup."""
        system_file = self.system_dir / f"system_{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'data': data
        }
        with open(system_file, 'a') as f:
            f.write(json.dumps(entry, indent=2) + '\n')
    
    def log_hook_call(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log a hook call - main entry point for backward compatibility."""
        return self.log_hook_event(data, self.INFO)
    
    def log_hook_event(self, data: Dict[str, Any], level: int = INFO) -> Dict[str, Any]:
        """Log a hook event with comprehensive information."""
        if level < self.log_level:
            return data
        
        try:
            # Run cleanup if needed
            self._comprehensive_cleanup()
            
            self.metrics["total_logs"] += 1
            timestamp = datetime.now()
            
            # Extract base information
            hook_event = data.get("hook_event_name", "unknown")
            session_id = data.get("session_id", "unknown")
            
            # Create log entry
            log_entry = {
                "timestamp": timestamp.isoformat(),
                "level": self._level_name(level),
                "hook_event": hook_event,
                "session_id": session_id,
                "transcript_path": data.get("transcript_path", ""),
                "cwd": data.get("cwd", ""),
                "metrics": {
                    "log_number": self.metrics["total_logs"],
                    "session_duration": time.time() - self.metrics.get("start_time", time.time())
                }
            }
            
            # Add hook-specific data (abridged)
            if hook_event == "PreToolUse" or hook_event == "PostToolUse":
                log_entry["tool"] = {
                    "name": data.get("tool_name", ""),
                    "input": self._abridge_value(data.get("tool_input", {})),
                }
                if hook_event == "PostToolUse":
                    log_entry["tool"]["response"] = self._abridge_value(data.get("tool_response", {}))
            
            elif hook_event == "UserPromptSubmit":
                prompt = data.get("prompt", "")
                log_entry["prompt"] = {
                    "length": len(prompt),
                    "preview": self._abridge_value(prompt),
                    "hash": hashlib.md5(prompt.encode()).hexdigest()[:8]
                }
            
            elif hook_event == "SessionStart":
                log_entry["source"] = data.get("source", "")
                self.metrics["start_time"] = time.time()
            
            # Add any custom data
            for key in ["result", "error", "decision", "reason", "blocked"]:
                if key in data:
                    log_entry[key] = self._abridge_value(data[key])
            
            # Write to appropriate log file
            log_path = self._get_log_path(hook_event, session_id, timestamp)
            with open(log_path, "a") as f:
                f.write(json.dumps(log_entry, indent=2) + "\n")
            
            # Also write summary in human-readable format
            self._write_human_readable_log(log_path.with_suffix(".log"), log_entry)
            
            # Also write errors to error log
            if level >= self.ERROR:
                self._log_error(log_entry)
            
            return log_entry
            
        except Exception as e:
            self.metrics["errors_count"] += 1
            error_entry = {
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "traceback": traceback.format_exc(),
                "original_data": self._abridge_value(data)
            }
            self._log_error(error_entry)
            return data
    
    def _write_human_readable_log(self, log_path: Path, log_entry: Dict[str, Any]):
        """Write human-readable version of log entry."""
        with open(log_path, "a") as f:
            f.write(f"\n{'=' * 80}\n")
            f.write(f"[{log_entry['timestamp']}] {log_entry['hook_event']} - {log_entry['level']}\n")
            f.write(f"Session: {log_entry['session_id'][:16]}...\n")
            
            if "tool" in log_entry:
                f.write(f"\nTool: {log_entry['tool']['name']}\n")
                if log_entry['tool']['name'] == 'Bash':
                    cmd = log_entry['tool']['input'].get('command', 'N/A')
                    f.write(f"Command: {cmd}\n")
                elif log_entry['tool']['name'] in ['Edit', 'Write', 'MultiEdit']:
                    f.write(f"File: {log_entry['tool']['input'].get('file_path', 'N/A')}\n")
            
            if "prompt" in log_entry:
                f.write(f"\nPrompt Length: {log_entry['prompt']['length']} chars\n")
                f.write(f"Hash: {log_entry['prompt']['hash']}\n")
            
            if "error" in log_entry:
                f.write(f"\n⚠️  ERROR: {log_entry['error']}\n")
            
            if "decision" in log_entry:
                f.write(f"\nDecision: {log_entry['decision']}\n")
                if "reason" in log_entry:
                    f.write(f"Reason: {log_entry['reason']}\n")
    
    def _log_error(self, entry: Dict[str, Any]):
        """Log errors to separate error log."""
        error_file = self.errors_dir / f"errors_{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        with open(error_file, "a") as f:
            f.write(json.dumps(entry, indent=2) + "\n")
    
    def _level_name(self, level: int) -> str:
        """Get level name from level number."""
        levels = {
            self.DEBUG: "DEBUG",
            self.INFO: "INFO",
            self.WARNING: "WARNING",
            self.ERROR: "ERROR",
            self.CRITICAL: "CRITICAL"
        }
        return levels.get(level, "UNKNOWN")
    
    def log_debug(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log debug level event."""
        return self.log_hook_event(data, self.DEBUG)
    
    def log_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log info level event."""
        return self.log_hook_event(data, self.INFO)
    
    def log_warning(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log warning level event."""
        return self.log_hook_event(data, self.WARNING)
    
    def log_error(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log error level event."""
        return self.log_hook_event(data, self.ERROR)
    
    def log_critical(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log critical level event."""
        return self.log_hook_event(data, self.CRITICAL)
    
    def get_session_logs(self, session_id: str, hook_event: Optional[str] = None) -> list:
        """Retrieve logs for a specific session."""
        logs = []
        session_short = session_id[:8]
        
        # Search through hook directories
        search_dirs = [self.hooks_dir / hook_event.lower()] if hook_event else list(self.hooks_dir.iterdir())
        
        for event_dir in search_dirs:
            if not event_dir.is_dir():
                continue
            
            for date_dir in event_dir.iterdir():
                if not date_dir.is_dir():
                    continue
                
                for hour_dir in date_dir.iterdir():
                    if not hour_dir.is_dir():
                        continue
                    
                    # Look for session files
                    for log_file in hour_dir.glob(f"session_{session_short}*.jsonl"):
                        with open(log_file, "r") as f:
                            for line in f:
                                try:
                                    log_entry = json.loads(line.strip())
                                    if log_entry.get("session_id", "").startswith(session_short):
                                        logs.append(log_entry)
                                except:
                                    continue
        
        # Sort by timestamp
        logs.sort(key=lambda x: x.get("timestamp", ""))
        return logs
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get logger metrics."""
        return {
            **self.metrics,
            "runtime_seconds": time.time() - self.metrics["start_time"],
            "logs_per_second": self.metrics["total_logs"] / max(1, time.time() - self.metrics["start_time"])
        }
    
    def create_summary_report(self, session_id: Optional[str] = None) -> str:
        """Create a human-readable summary report."""
        report_lines = ["=" * 80, "HOOK LOGGER SUMMARY REPORT", "=" * 80]
        
        # Add metrics
        metrics = self.get_metrics()
        report_lines.extend([
            f"Total Logs: {metrics['total_logs']}",
            f"Abridged Count: {metrics['abridged_count']}",
            f"Errors Count: {metrics['errors_count']}",
            f"Runtime: {metrics['runtime_seconds']:.2f} seconds",
            f"Logs/Second: {metrics['logs_per_second']:.2f}",
            ""
        ])
        
        # Add session-specific info if provided
        if session_id:
            logs = self.get_session_logs(session_id)
            report_lines.extend([
                f"Session {session_id[:8]} Summary:",
                f"Total Events: {len(logs)}",
                ""
            ])
            
            # Group by event type
            event_counts = {}
            for log in logs:
                event = log.get("hook_event", "unknown")
                event_counts[event] = event_counts.get(event, 0) + 1
            
            report_lines.append("Events by Type:")
            for event, count in sorted(event_counts.items()):
                report_lines.append(f"  {event}: {count}")
        
        report_lines.extend(["", "=" * 80])
        return "\n".join(report_lines)
    
    # Backward compatibility methods
    def _find_existing_session_log(self, session_id: str) -> Optional[Path]:
        """Find existing log file for session (backward compatibility)."""
        logs = self.get_session_logs(session_id)
        if logs:
            # Return path to first log file found
            return Path(logs[0].get("__file_path__", ""))
        return None
    
    def get_session_log_path(self, session_id: str) -> Optional[Path]:
        """Get path to session log (backward compatibility)."""
        return self._find_existing_session_log(session_id)
    
    def list_sessions(self) -> Dict[str, list]:
        """List all sessions organized by date (backward compatibility)."""
        sessions_by_date = {}
        
        for event_dir in self.hooks_dir.iterdir():
            if not event_dir.is_dir():
                continue
            
            for date_dir in event_dir.iterdir():
                if not date_dir.is_dir() or not date_dir.name.count('-') == 2:
                    continue
                
                date_str = date_dir.name
                if date_str not in sessions_by_date:
                    sessions_by_date[date_str] = []
                
                for hour_dir in date_dir.iterdir():
                    if not hour_dir.is_dir():
                        continue
                    
                    for log_file in hour_dir.glob("session_*.jsonl"):
                        parts = log_file.stem.split('_')
                        if len(parts) >= 2:
                            session_id_short = parts[1]
                            sessions_by_date[date_str].append({
                                'time': hour_dir.name + ":00",
                                'session_id_short': session_id_short,
                                'event_type': event_dir.name,
                                'full_path': log_file
                            })
        
        return sessions_by_date


# Create singleton instance
logger = HookLogger()


# Decorator for easy function logging
def log_function_call(level=HookLogger.INFO):
    """Decorator to log function calls."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            func_data = {
                "hook_event_name": "function_call",
                "function": func.__name__,
                "args": logger._abridge_value(args),
                "kwargs": logger._abridge_value(kwargs)
            }
            
            try:
                result = func(*args, **kwargs)
                func_data["result"] = logger._abridge_value(result)
                func_data["duration"] = time.time() - start_time
                logger.log_hook_event(func_data, level)
                return result
            except Exception as e:
                func_data["error"] = str(e)
                func_data["traceback"] = traceback.format_exc()
                func_data["duration"] = time.time() - start_time
                logger.log_hook_event(func_data, HookLogger.ERROR)
                raise
        
        return wrapper
    return decorator