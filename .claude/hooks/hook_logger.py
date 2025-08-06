#!/usr/bin/env python3
"""
Simplified logger for UserPromptSubmit hooks.
Logs key events with minimal overhead and automatic cleanup.
"""

import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional
from collections import defaultdict
import time


class UserPromptLogger:
    """Simple logger focused on UserPromptSubmit hook events."""
    
    def __init__(self, base_dir: str = "/home/blake/simple-claude/.claude/logs/userprompt"):
        """Initialize the logger."""
        self.log_dir = Path(base_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = str(uuid.uuid4())
        # Rate limiting: track last occurrence of each error message
        self._error_last_logged = defaultdict(float)
        self._rate_limit_seconds = 30  # Rate limit to once per 30 seconds
        # Add test comment to verify PostToolUse feedback
    
    def _cleanup_old_logs(self):
        """Remove logs older than 7 days."""
        cutoff_date = datetime.now() - timedelta(days=7)
        
        for log_file in self.log_dir.glob("*.json"):
            if log_file.is_file():
                file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
                if file_time < cutoff_date:
                    log_file.unlink()
    
    def _get_log_filename(self) -> Path:
        """Get log filename for today."""
        date_str = datetime.now().strftime("%Y-%m-%d")
        return self.log_dir / f"userprompt_{date_str}.json"
    
    def log_event(self, event_data: Dict[str, Any]):
        """Log a UserPromptSubmit event."""
        try:
            # Clean up old logs
            self._cleanup_old_logs()
            
            # Create log entry
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "session_id": self.session_id,
                **event_data
            }
            
            # Write to log file
            log_file = self._get_log_filename()
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
                
        except Exception:
            # Silent failure - don't break the main process
            pass
    
    def log_gemini_request(self, user_prompt: str, request_payload: Dict[str, Any]):
        """Log Gemini API request."""
        self.log_event({
            "event_type": "gemini_request",
            "user_prompt_preview": user_prompt[:100],
            "user_prompt_length": len(user_prompt),
            "request_payload": request_payload
        })
    
    def log_gemini_response(self, response_data: Dict[str, Any], success: bool):
        """Log Gemini API response."""
        self.log_event({
            "event_type": "gemini_response", 
            "success": success,
            "response_data": response_data
        })
    
    def log_context_injection(self, success: bool, context: Optional[str] = None):
        """Log context injection result."""
        self.log_event({
            "event_type": "context_injection",
            "success": success,
            "context_length": len(context) if context else 0
        })
    
    def should_print_error(self, error_message: str) -> bool:
        """Check if an error should be printed based on rate limiting."""
        current_time = time.time()
        last_logged = self._error_last_logged[error_message]
        
        if current_time - last_logged >= self._rate_limit_seconds:
            self._error_last_logged[error_message] = current_time
            return True
        return False
    
    def log_error(self, error_message: str, error_details: Optional[Dict[str, Any]] = None):
        """Log an error with rate limiting (once per 30 seconds for the same error)."""
        if self.should_print_error(error_message):
            self.log_event({
                "event_type": "error",
                "error_message": error_message,
                "error_details": error_details or {}
            })
        # else: silently skip logging this error due to rate limiting
    
    def log_hook_call(self, data: Dict[str, Any]):
        """Compatibility method for hook_handler.py - only logs UserPromptSubmit events."""
        if data.get("hook_event_name") == "UserPromptSubmit":
            self.log_event({
                "event_type": "hook_call",
                "hook_data": data
            })


# Create singleton instance
logger = UserPromptLogger()