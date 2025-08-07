#!/usr/bin/env python3
"""
Security validation and sanitization module for hook handlers.
Implements OWASP security best practices for input validation.
"""

import re
import os
import sys
import hashlib
import time
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from functools import wraps
from collections import defaultdict
from datetime import datetime

# Security constants
MAX_PROMPT_LENGTH = 50000  # Maximum characters for user prompt
MAX_SESSION_ID_LENGTH = 128  # Maximum length for session ID
MAX_PATH_LENGTH = 4096  # Maximum path length
MAX_JSON_SIZE = 10 * 1024 * 1024  # 10MB max JSON size
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 30  # max requests per window

# Dangerous patterns for command injection
DANGEROUS_COMMAND_PATTERNS = [
    r"[;&|`$]",  # Command separators and substitution
    r"\$\(",  # Command substitution
    r"\$\{",  # Variable substitution
    r"\.\./",  # Directory traversal
    r"\\x[0-9a-fA-F]{2}",  # Hex encoding
    r"\\[0-7]{1,3}",  # Octal encoding
    r"<script",  # XSS attempts
    r"javascript:",  # XSS attempts
    r"on\w+\s*=",  # Event handlers
]

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    r"('\s*(OR|AND)\s*'?\w*'\s*=)",  # Basic SQL injection
    r"(--|\#|\/\*)",  # SQL comments
    r"(UNION\s+SELECT)",  # Union-based injection
    r"(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO)",  # Destructive SQL
    r"(EXEC\s*\(|EXECUTE\s*\()",  # Stored procedure execution
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\.[/\\]",  # Parent directory access
    r"\.\.%2[fF]",  # URL encoded traversal
    r"\.\.%5[cC]",  # URL encoded backslash
    r"/etc/passwd",  # Common target
    r"[cC]:\\",  # Windows absolute path
    r"file://",  # File protocol
]

# Rate limiter storage
_rate_limiter_storage = defaultdict(list)


class SecurityValidationError(Exception):
    """Raised when security validation fails."""

    pass


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""

    pass


def sanitize_string(
    value: str,
    max_length: int = 1000,
    allow_newlines: bool = True,
    allow_unicode: bool = True,
) -> str:
    """
    Sanitize a string input by removing dangerous characters and patterns.

    Args:
        value: Input string to sanitize
        max_length: Maximum allowed length
        allow_newlines: Whether to allow newline characters
        allow_unicode: Whether to allow unicode characters

    Returns:
        Sanitized string

    Raises:
        SecurityValidationError: If input contains malicious patterns
    """
    if not isinstance(value, str):
        raise SecurityValidationError(f"Expected string, got {type(value)}")

    # Check length
    if len(value) > max_length:
        raise SecurityValidationError(f"String exceeds maximum length of {max_length}")

    # Check for null bytes
    if "\x00" in value:
        raise SecurityValidationError("Null bytes not allowed in input")

    # Remove control characters (except newlines if allowed)
    if allow_newlines:
        value = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", value)
    else:
        value = re.sub(r"[\x00-\x1F\x7F]", "", value)

    # Remove or encode potentially dangerous HTML/JS
    value = value.replace("<", "&lt;").replace(">", "&gt;")
    value = value.replace('"', "&quot;").replace("'", "&#x27;")

    # If not allowing unicode, strip it
    if not allow_unicode:
        value = value.encode("ascii", "ignore").decode("ascii")

    return value.strip()


def validate_session_id(session_id: str) -> str:
    """
    Validate and sanitize session ID.
    Should be alphanumeric with hyphens/underscores only.

    Args:
        session_id: Session identifier to validate

    Returns:
        Validated session ID

    Raises:
        SecurityValidationError: If session ID is invalid
    """
    if not session_id:
        return ""  # Empty session ID is allowed

    if not isinstance(session_id, str):
        raise SecurityValidationError("Session ID must be a string")

    if len(session_id) > MAX_SESSION_ID_LENGTH:
        raise SecurityValidationError(
            f"Session ID exceeds {MAX_SESSION_ID_LENGTH} characters"
        )

    # Allow alphanumeric, hyphens, underscores only
    if not re.match(r"^[a-zA-Z0-9_-]+$", session_id):
        raise SecurityValidationError("Session ID contains invalid characters")

    return session_id


def validate_file_path(
    path: str,
    base_dir: Optional[str] = None,
    must_exist: bool = False,
    allow_symlinks: bool = False,
) -> Path:
    """
    Validate file path to prevent directory traversal attacks.

    Args:
        path: File path to validate
        base_dir: Base directory to restrict access to
        must_exist: Whether the path must exist
        allow_symlinks: Whether to allow symbolic links

    Returns:
        Validated Path object

    Raises:
        SecurityValidationError: If path is invalid or unsafe
    """
    if not isinstance(path, (str, Path)):
        raise SecurityValidationError("Path must be a string or Path object")

    # Convert to Path object
    path_obj = Path(path)

    # Check for path traversal attempts
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, str(path)):
            raise SecurityValidationError(f"Path traversal attempt detected: {path}")

    # Resolve to absolute path
    try:
        if allow_symlinks:
            resolved_path = path_obj.absolute()
        else:
            resolved_path = path_obj.resolve()
    except (OSError, RuntimeError) as e:
        raise SecurityValidationError(f"Invalid path: {e}")

    # Check if path is within base directory
    if base_dir:
        base_path = Path(base_dir).resolve()
        try:
            resolved_path.relative_to(base_path)
        except ValueError:
            raise SecurityValidationError(f"Path {path} is outside allowed directory")

    # Check if path exists if required
    if must_exist and not resolved_path.exists():
        raise SecurityValidationError(f"Path does not exist: {path}")

    # Check path length
    if len(str(resolved_path)) > MAX_PATH_LENGTH:
        raise SecurityValidationError(
            f"Path exceeds maximum length of {MAX_PATH_LENGTH}"
        )

    return resolved_path


def validate_json_input(data: Any, max_size: int = MAX_JSON_SIZE) -> Dict:
    """
    Validate JSON input for size and structure.

    Args:
        data: JSON data to validate
        max_size: Maximum allowed size in bytes

    Returns:
        Validated dictionary

    Raises:
        SecurityValidationError: If JSON is invalid or too large
    """
    if not isinstance(data, dict):
        raise SecurityValidationError("Input must be a dictionary")

    # Check size
    json_str = json.dumps(data)
    if len(json_str.encode("utf-8")) > max_size:
        raise SecurityValidationError(f"JSON exceeds maximum size of {max_size} bytes")

    # Validate no circular references (handled by json.dumps)

    return data


def validate_command_input(command: str) -> str:
    """
    Validate command input to prevent injection attacks.

    Args:
        command: Command string to validate

    Returns:
        Validated command

    Raises:
        SecurityValidationError: If command contains dangerous patterns
    """
    if not isinstance(command, str):
        raise SecurityValidationError("Command must be a string")

    # Check for dangerous command patterns
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, command):
            raise SecurityValidationError(
                f"Dangerous command pattern detected: {pattern}"
            )

    # Check for SQL injection attempts
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            raise SecurityValidationError("SQL injection pattern detected")

    return command


def check_rate_limit(
    identifier: str,
    max_requests: int = RATE_LIMIT_MAX_REQUESTS,
    window_seconds: int = RATE_LIMIT_WINDOW,
) -> None:
    """
    Check if rate limit has been exceeded for an identifier.

    Args:
        identifier: Unique identifier (e.g., session_id, IP address)
        max_requests: Maximum requests allowed in window
        window_seconds: Time window in seconds

    Raises:
        RateLimitExceeded: If rate limit is exceeded
    """
    current_time = time.time()

    # Clean old entries
    _rate_limiter_storage[identifier] = [
        timestamp
        for timestamp in _rate_limiter_storage[identifier]
        if current_time - timestamp < window_seconds
    ]

    # Check rate limit
    if len(_rate_limiter_storage[identifier]) >= max_requests:
        raise RateLimitExceeded(
            f"Rate limit exceeded: {max_requests} requests in {window_seconds} seconds"
        )

    # Add current request
    _rate_limiter_storage[identifier].append(current_time)


def rate_limit_decorator(
    max_requests: int = RATE_LIMIT_MAX_REQUESTS,
    window_seconds: int = RATE_LIMIT_WINDOW,
    identifier_func=None,
):
    """
    Decorator to apply rate limiting to functions.

    Args:
        max_requests: Maximum requests allowed
        window_seconds: Time window in seconds
        identifier_func: Function to extract identifier from arguments
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract identifier
            if identifier_func:
                identifier = identifier_func(*args, **kwargs)
            else:
                # Default to first argument or 'default'
                identifier = str(args[0]) if args else "default"

            # Check rate limit
            check_rate_limit(identifier, max_requests, window_seconds)

            # Call original function
            return func(*args, **kwargs)

        return wrapper

    return decorator


def validate_user_prompt(prompt: str) -> str:
    """
    Comprehensive validation for user prompts.

    Args:
        prompt: User input prompt

    Returns:
        Validated and sanitized prompt

    Raises:
        SecurityValidationError: If prompt is invalid
    """
    if not prompt:
        return ""

    # Basic type check
    if not isinstance(prompt, str):
        raise SecurityValidationError("Prompt must be a string")

    # Length check
    if len(prompt) > MAX_PROMPT_LENGTH:
        raise SecurityValidationError(
            f"Prompt exceeds maximum length of {MAX_PROMPT_LENGTH} characters"
        )

    # Check for command injection patterns
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, prompt):
            # Log potential attack
            print(
                "WARNING: Potential command injection attempt detected",
                file=sys.stderr,
            )
            # Sanitize instead of rejecting
            prompt = re.sub(pattern, "", prompt)

    # Check for SQL injection patterns
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, prompt, re.IGNORECASE):
            print("WARNING: Potential SQL injection attempt detected", file=sys.stderr)
            prompt = re.sub(pattern, "", prompt, flags=re.IGNORECASE)

    # Sanitize HTML/JS
    prompt = sanitize_string(
        prompt, max_length=MAX_PROMPT_LENGTH, allow_newlines=True, allow_unicode=True
    )

    return prompt


def create_security_context() -> Dict[str, Any]:
    """
    Create security context with headers and metadata.

    Returns:
        Dictionary with security headers and context
    """
    return {
        "headers": {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        },
        "timestamp": datetime.utcnow().isoformat(),
        "nonce": hashlib.sha256(os.urandom(32)).hexdigest(),
    }


def validate_subprocess_args(
    args: List[str], allowed_commands: Optional[List[str]] = None
) -> List[str]:
    """
    Validate subprocess arguments to prevent command injection.

    Args:
        args: List of command arguments
        allowed_commands: Whitelist of allowed commands

    Returns:
        Validated argument list

    Raises:
        SecurityValidationError: If arguments are unsafe
    """
    if not isinstance(args, list):
        raise SecurityValidationError("Subprocess args must be a list")

    if not args:
        raise SecurityValidationError("Empty command not allowed")

    # Check if command is in whitelist
    if allowed_commands and args[0] not in allowed_commands:
        raise SecurityValidationError(f"Command not allowed: {args[0]}")

    # Validate each argument
    validated_args = []
    for arg in args:
        if not isinstance(arg, str):
            raise SecurityValidationError(f"Argument must be string: {arg}")

        # Check for shell metacharacters
        if re.search(r"[;&|`$<>]", arg):
            raise SecurityValidationError(f"Shell metacharacters not allowed: {arg}")

        # Check for null bytes
        if "\x00" in arg:
            raise SecurityValidationError("Null bytes not allowed in arguments")

        validated_args.append(arg)

    return validated_args


def sanitize_error_message(error: Exception, include_type: bool = False) -> str:
    """
    Sanitize error messages to prevent information leakage.

    Args:
        error: Exception object
        include_type: Whether to include error type

    Returns:
        Sanitized error message
    """
    # Generic error messages for common issues
    error_map = {
        FileNotFoundError: "Requested resource not found",
        PermissionError: "Access denied",
        ValueError: "Invalid input provided",
        KeyError: "Required data not found",
        ConnectionError: "Connection failed",
        TimeoutError: "Operation timed out",
    }

    # Get generic message
    error_type = type(error)
    generic_message = error_map.get(error_type, "An error occurred")

    # Include type if requested (for logging)
    if include_type:
        return f"{error_type.__name__}: {generic_message}"

    return generic_message


# Export main validation functions
__all__ = [
    "SecurityValidationError",
    "RateLimitExceeded",
    "sanitize_string",
    "validate_session_id",
    "validate_file_path",
    "validate_json_input",
    "validate_command_input",
    "check_rate_limit",
    "rate_limit_decorator",
    "validate_user_prompt",
    "create_security_context",
    "validate_subprocess_args",
    "sanitize_error_message",
]
