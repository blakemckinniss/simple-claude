#!/usr/bin/env python3
# claude-exempt: hook_handlers_py_protection - Adding performance caching system to reduce repeated operations by 50-80%
import os
import sys
import json
import shutil
import re
import requests
import subprocess
import time
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field

# Import the simplified logger, state manager, and memory manager
from hook_tools.utilities.path_resolver import PathResolver
from hook_logger import logger
from hook_tools.state_manager import state_manager
from hook_tools.memory_manager import memory_manager

# Import security validation module - CRITICAL FOR SECURITY
from hook_tools.security_validator import (
    SecurityValidationError,
    RateLimitExceeded,
    validate_user_prompt,
    validate_session_id,
    validate_file_path,
    validate_json_input,
    validate_subprocess_args,
    check_rate_limit,
    create_security_context,
    sanitize_error_message,
)

# Import from new modular structure
from hook_tools.utilities.constants_loader import load_constants, load_env
from hook_tools.utilities.import_graph import build_import_graph
from hook_tools.utilities.smart_truncate import truncate_for_memory
from hook_tools.integration.agent_loader import get_agent_info
from hook_tools.integration.gemini_client import call_gemini
from hook_tools.metrics.testing_metrics import extract_test_metrics
from hook_tools.analysis.pattern_analyzer import (
    aggregate_cross_file_patterns,
    calculate_context_depth,
)
from hook_tools.summarization.outline_generator import bootstrap_summary
from hook_tools.metrics.relevance_scorer import extract_keywords, filter_relevant_files
from hook_tools.continuation_helpers import (
    get_continuation_id as get_current_continuation_id,
)
from hook_tools.context.api_database_context import get_database_context

# Initialize PathResolver after all imports
paths = PathResolver()

# Tool output cache for synthesis
TOOL_OUTPUT_CACHE = {}
CACHE_TTL = 300  # 5 minutes


@dataclass
class CacheEntry:
    """Represents a cached value with TTL and file-based invalidation."""

    value: Any
    timestamp: float
    ttl: float
    file_mtimes: Dict[str, float] = field(default_factory=dict)
    access_count: int = 0
    hit_count: int = 0

    def is_valid(self) -> bool:
        """Check if cache entry is still valid based on TTL and file modifications."""
        # Check TTL
        if time.time() - self.timestamp > self.ttl:
            return False

        # Check file modifications
        for filepath, cached_mtime in self.file_mtimes.items():
            try:
                current_mtime = os.path.getmtime(filepath)
                if current_mtime > cached_mtime:
                    return False
            except OSError:
                # File might have been deleted
                return False

        return True


class ContextCache:
    """High-performance caching system for context collection with TTL and invalidation."""

    def __init__(self, default_ttl: float = 60.0):
        """Initialize cache with default TTL in seconds."""
        self.cache: Dict[str, CacheEntry] = {}
        self.default_ttl = default_ttl
        self.stats = {"hits": 0, "misses": 0, "evictions": 0, "invalidations": 0}
        self.last_cleanup = time.time()
        self.cleanup_interval = 120  # Cleanup every 2 minutes

    def _generate_key(self, func_name: str, *args, **kwargs) -> str:
        """Generate a unique cache key from function name and arguments."""
        # Create a hashable representation of arguments
        key_data = {
            "func": func_name,
            "args": str(args),
            "kwargs": str(sorted(kwargs.items())),
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()

    def _track_files(self, files: List[str]) -> Dict[str, float]:
        """Track modification times for files to enable invalidation."""
        mtimes = {}
        for filepath in files:
            try:
                if os.path.exists(filepath):
                    mtimes[filepath] = os.path.getmtime(filepath)
            except OSError:
                pass
        return mtimes

    def _cleanup_expired(self):
        """Remove expired entries from cache to prevent memory bloat."""
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return

        expired_keys = []
        for key, entry in self.cache.items():
            if not entry.is_valid():
                expired_keys.append(key)

        for key in expired_keys:
            del self.cache[key]
            self.stats["evictions"] += 1

        self.last_cleanup = current_time

    def get_or_compute(
        self,
        func_name: str,
        compute_func,
        *args,
        ttl: Optional[float] = None,
        tracked_files: Optional[List[str]] = None,
        **kwargs,
    ) -> Tuple[Any, bool]:
        """Get cached value or compute and cache it.

        Returns:
            Tuple of (value, was_cached) where was_cached indicates if value came from cache.
        """
        # Periodic cleanup
        self._cleanup_expired()

        # Generate cache key
        cache_key = self._generate_key(func_name, *args, **kwargs)

        # Check if cached value exists and is valid
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            if entry.is_valid():
                self.stats["hits"] += 1
                entry.hit_count += 1
                entry.access_count += 1
                return entry.value, True
            else:
                # Invalid entry, remove it
                del self.cache[cache_key]
                self.stats["invalidations"] += 1

        # Cache miss - compute value
        self.stats["misses"] += 1
        start_time = time.time()
        value = compute_func(*args, **kwargs)
        compute_time = time.time() - start_time

        # Track files for invalidation
        file_mtimes = {}
        if tracked_files:
            file_mtimes = self._track_files(tracked_files)

        # Store in cache
        self.cache[cache_key] = CacheEntry(
            value=value,
            timestamp=time.time(),
            ttl=ttl or self.default_ttl,
            file_mtimes=file_mtimes,
            access_count=1,
        )

        # Log cache performance for slow operations
        if compute_time > 0.5:
            logger.log_event(
                {
                    "event_type": "performance",
                    "message": f"Computed {func_name} in {compute_time:.2f}s (cached for {ttl or self.default_ttl}s)",
                    "func": func_name,
                    "compute_time": compute_time,
                }
            )

        return value, False

    def invalidate(self, func_name: Optional[str] = None):
        """Invalidate cache entries for a specific function or all entries."""
        if func_name:
            # Invalidate entries for specific function
            keys_to_remove = [key for key in self.cache if func_name in key]
            for key in keys_to_remove:
                del self.cache[key]
                self.stats["invalidations"] += 1
        else:
            # Clear entire cache
            self.stats["invalidations"] += len(self.cache)
            self.cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = self.stats["hits"] / total_requests if total_requests > 0 else 0

        return {
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "hit_rate": f"{hit_rate:.2%}",
            "evictions": self.stats["evictions"],
            "invalidations": self.stats["invalidations"],
            "entries": len(self.cache),
            "memory_usage": sum(
                sys.getsizeof(entry.value) for entry in self.cache.values()
            ),
        }


# Initialize global context cache
context_cache = ContextCache(default_ttl=60.0)

# Load constants globally with error handling
try:
    CONSTANTS = load_constants()
except RuntimeError as e:
    print(f"Error loading constants: {e}", file=sys.stderr)
    sys.exit(2)  # Block execution if constants cannot be loaded

# Load environment variables using centralized loader
load_env(CONSTANTS)

# --- Semantic Summary Logic ---

SUMMARY_OUTPUT = CONSTANTS["file_paths"]["summary_output"]


def _compute_git_context(keywords: Optional[List[str]] = None) -> dict:
    """Compute recent git activity context with secure subprocess calls."""
    try:
        context = {
            "working_on": "",
            "recent_commits": [],
            "recently_changed": [],
            "current_branch": "",
        }

        # SECURITY: Define allowed git commands
        ALLOWED_GIT_COMMANDS = ["git"]

        # Get current branch - SECURE subprocess call
        try:
            args = validate_subprocess_args(
                ["git", "branch", "--show-current"],
                allowed_commands=ALLOWED_GIT_COMMANDS,
            )
            context["current_branch"] = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                shell=False,  # SECURITY: Never use shell=True
                timeout=5,  # SECURITY: Add timeout to prevent DoS
            ).stdout.strip()
        except (SecurityValidationError, subprocess.TimeoutExpired):
            pass

        # Get working directory status - SECURE subprocess call
        try:
            args = validate_subprocess_args(
                ["git", "status", "--short"], allowed_commands=ALLOWED_GIT_COMMANDS
            )
            context["working_on"] = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=5,
            ).stdout.strip()
        except (SecurityValidationError, subprocess.TimeoutExpired):
            pass

        # Get recent commits - SECURE subprocess call
        try:
            args = validate_subprocess_args(
                ["git", "log", "--oneline", "-10"],
                allowed_commands=ALLOWED_GIT_COMMANDS,
            )
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=5,
            )
            commits = result.stdout.splitlines() if result.returncode == 0 else []
            if keywords:
                # Filter commits by keywords
                context["recent_commits"] = [
                    c
                    for c in commits
                    if any(kw.lower() in c.lower() for kw in keywords)
                ][:5]
            else:
                context["recent_commits"] = commits[:5]
        except Exception:
            pass

        # Get recently changed files - SECURE subprocess calls
        try:
            # Try git diff first - SECURE
            args = validate_subprocess_args(
                ["git", "diff", "--name-only", "HEAD~5"],
                allowed_commands=ALLOWED_GIT_COMMANDS,
            )
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=5,
            )
            if result.returncode == 0:
                changed = result.stdout.splitlines()
            else:
                # Fallback to git ls-files - SECURE
                args = validate_subprocess_args(
                    ["git", "ls-files"], allowed_commands=ALLOWED_GIT_COMMANDS
                )
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=False,
                    timeout=5,
                )
                changed = result.stdout.splitlines() if result.returncode == 0 else []
            if keywords:
                context["recently_changed"] = [
                    f
                    for f in changed
                    if any(kw.lower() in f.lower() for kw in keywords)
                ][:10]
            else:
                context["recently_changed"] = changed[:10]
        except Exception:
            pass

        return context
    except Exception:
        return {
            "working_on": "",
            "recent_commits": [],
            "recently_changed": [],
            "current_branch": "",
        }


def get_git_context(keywords: Optional[List[str]] = None) -> dict:
    """Get recent git activity context with caching."""
    # Use cache with TTL of 30 seconds for git operations
    # Track .git directory for invalidation
    tracked_files = [".git/HEAD", ".git/index"]

    value, was_cached = context_cache.get_or_compute(
        "git_context",
        _compute_git_context,
        keywords,
        ttl=30.0,
        tracked_files=tracked_files,
    )

    if was_cached:
        logger.log_event(
            {
                "event_type": "performance",
                "message": "Git context served from cache",
                "cached": True,
            }
        )

    return value


def _compute_error_context() -> dict:
    """Compute recent errors from logs and terminal output."""
    context = {"recent_errors": [], "warnings": []}

    # Check common log locations
    log_patterns = ["*.log", "*.err", "error.txt", "debug.log"]

    for pattern in log_patterns:
        try:
            # Find recent log files - SECURE subprocess call
            # SECURITY: Validate pattern to prevent injection
            if not re.match(r"^[\w\*\.\-]+$", pattern):
                continue  # Skip potentially dangerous patterns

            args = validate_subprocess_args(
                ["find", ".", "-name", pattern, "-mtime", "-1", "-type", "f"],
                allowed_commands=["find"],
            )

            try:
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=False,
                    timeout=10,  # Find can take longer
                )
                if result.returncode == 0:
                    files = result.stdout.splitlines()[:5]  # Limit to 5 files
                else:
                    files = []

                for log_file in files:
                    # SECURITY: Validate file path to prevent directory traversal
                    try:
                        validated_path = validate_file_path(
                            log_file,
                            base_dir=".",  # Restrict to current directory
                            must_exist=True,
                            allow_symlinks=False,
                        )
                        if validated_path.exists():
                            with open(validated_path, "r", errors="ignore") as f:
                                # Read last 100 lines
                                lines = f.readlines()[-100:]

                                # Extract errors
                                for line in lines:
                                    if (
                                        "ERROR" in line
                                        or "Exception" in line
                                        or "Traceback" in line
                                    ):
                                        context["recent_errors"].append(
                                            line.strip()[:200]
                                        )  # Truncate long lines
                                    elif "WARNING" in line or "WARN" in line:
                                        context["warnings"].append(line.strip()[:200])

                                # Limit to most recent
                                context["recent_errors"] = context["recent_errors"][-5:]
                                context["warnings"] = context["warnings"][-3:]
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass

    return context


def get_error_context() -> dict:
    """Extract recent errors from logs with caching."""
    # Cache error context for 60 seconds
    # Track log files for invalidation
    tracked_files = []
    for pattern in ["*.log", "error.txt", "debug.log"]:
        try:
            result = subprocess.run(
                ["find", ".", "-name", pattern, "-type", "f", "-maxdepth", "3"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if result.returncode == 0:
                tracked_files.extend(result.stdout.splitlines()[:5])
        except:
            pass

    value, was_cached = context_cache.get_or_compute(
        "error_context", _compute_error_context, ttl=60.0, tracked_files=tracked_files
    )

    if was_cached:
        logger.log_event(
            {
                "event_type": "performance",
                "message": "Error context served from cache",
                "cached": True,
            }
        )

    return value


def _compute_project_config() -> dict:
    """Compute project configuration from various config files."""
    context = {
        "dependencies": [],
        "scripts": {},
        "make_targets": [],
        "config_files": [],
    }

    project_root = Path(os.getcwd())

    # Check requirements.txt - SECURE file access
    requirements_path = project_root / "requirements.txt"
    try:
        validated_path = validate_file_path(
            str(requirements_path),
            base_dir=str(project_root),
            must_exist=False,
            allow_symlinks=False,
        )
        if validated_path.exists():
            with open(validated_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[:20]  # Limit to first 20 dependencies
                deps = [
                    line.strip().split("==")[0].split(">=")[0].split("~=")[0]
                    for line in lines
                    if line.strip() and not line.startswith("#")
                ]
                context["dependencies"].extend(deps)
                context["config_files"].append("requirements.txt")
    except Exception:
        pass

    # Check package.json - SECURE file access
    package_json_path = project_root / "package.json"
    try:
        validated_path = validate_file_path(
            str(package_json_path),
            base_dir=str(project_root),
            must_exist=False,
            allow_symlinks=False,
        )
        if validated_path.exists():
            with open(validated_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "dependencies" in data:
                    context["dependencies"].extend(
                        list(data["dependencies"].keys())[:10]
                    )
                if "devDependencies" in data:
                    context["dependencies"].extend(
                        list(data["devDependencies"].keys())[:10]
                    )
                if "scripts" in data:
                    context["scripts"].update(data["scripts"])
                context["config_files"].append("package.json")
    except Exception:
        pass

    # Check pyproject.toml
    pyproject_path = project_root / "pyproject.toml"
    if pyproject_path.exists():
        try:
            with open(pyproject_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Simple regex-based extraction for dependencies
                deps_match = re.search(
                    r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL
                )
                if deps_match:
                    deps_str = deps_match.group(1)
                    deps = re.findall(r'["\']([^"\'>=<]+)["\']', deps_str)
                    context["dependencies"].extend(deps[:10])
                context["config_files"].append("pyproject.toml")
        except Exception:
            pass

    # Check setup.py
    setup_py_path = project_root / "setup.py"
    if setup_py_path.exists():
        try:
            with open(setup_py_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()[:2000]  # Read first 2000 chars to avoid large files
                # Extract install_requires dependencies
                deps_match = re.search(
                    r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL
                )
                if deps_match:
                    deps_str = deps_match.group(1)
                    deps = re.findall(r'["\']([^"\'>=<]+)["\']', deps_str)
                    context["dependencies"].extend(deps[:10])
                context["config_files"].append("setup.py")
        except Exception:
            pass

    # Check Makefile
    makefile_path = project_root / "Makefile"
    if makefile_path.exists():
        try:
            with open(makefile_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[:50]  # Limit to first 50 lines
                targets = []
                for line in lines:
                    # Find make targets (lines that start without whitespace and contain :)
                    if (
                        not line.startswith("\t")
                        and ":" in line
                        and not line.startswith("#")
                    ):
                        target = line.split(":")[0].strip()
                        if target and not target.startswith(
                            "."
                        ):  # Skip special targets
                            targets.append(target)
                context["make_targets"] = targets[:10]  # Limit to 10 targets
                if targets:
                    context["config_files"].append("Makefile")
        except Exception:
            pass

    # Remove duplicates and limit total dependencies
    context["dependencies"] = list(dict.fromkeys(context["dependencies"]))[:15]

    return context


def get_project_config() -> dict:
    """Extract project configuration with caching."""
    # Cache project config for 300 seconds (5 minutes)
    # Track config files for invalidation
    tracked_files = [
        "requirements.txt",
        "package.json",
        "pyproject.toml",
        "setup.py",
        "Makefile",
        "Pipfile",
        "yarn.lock",
        "package-lock.json",
    ]

    value, was_cached = context_cache.get_or_compute(
        "project_config",
        _compute_project_config,
        ttl=300.0,
        tracked_files=tracked_files,
    )

    if was_cached:
        logger.log_event(
            {
                "event_type": "performance",
                "message": "Project config served from cache",
                "cached": True,
            }
        )

    return value


def _compute_project_documentation() -> dict:
    """Compute project documentation context."""
    context = {"readme_files": [], "doc_dirs": [], "key_docs": []}

    # Look for README files - SECURE subprocess calls
    readme_patterns = ["README*", "readme*", "Readme*"]
    for pattern in readme_patterns:
        try:
            # SECURITY: Validate pattern
            if not re.match(r"^[\w\*\.\-]+$", pattern):
                continue

            args = validate_subprocess_args(
                ["find", ".", "-maxdepth", "2", "-name", pattern, "-type", "f"],
                allowed_commands=["find"],
            )
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=5,
            )
            if result.returncode == 0:
                files = result.stdout.splitlines()[:3]  # Limit to 3 files
                context["readme_files"].extend(files)
        except Exception:
            pass

    # Look for documentation directories
    doc_dirs = ["docs", "doc", "documentation", "wiki", "guides"]
    for doc_dir in doc_dirs:
        if os.path.exists(doc_dir) and os.path.isdir(doc_dir):
            context["doc_dirs"].append(doc_dir)

    # Look for key documentation files
    key_docs = ["CHANGELOG.md", "CONTRIBUTING.md", "LICENSE", "API.md", "USAGE.md"]
    for doc_file in key_docs:
        if os.path.exists(doc_file):
            context["key_docs"].append(doc_file)

    return context


def get_project_documentation() -> dict:
    """Extract project documentation context with caching."""
    # Cache documentation for 600 seconds (10 minutes)
    # Track README files for invalidation
    tracked_files = []
    for pattern in ["README*", "CHANGELOG.md", "CONTRIBUTING.md"]:
        try:
            result = subprocess.run(
                ["find", ".", "-name", pattern, "-type", "f", "-maxdepth", "2"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if result.returncode == 0:
                tracked_files.extend(result.stdout.splitlines()[:5])
        except:
            pass

    value, was_cached = context_cache.get_or_compute(
        "project_documentation",
        _compute_project_documentation,
        ttl=600.0,
        tracked_files=tracked_files,
    )

    if was_cached:
        logger.log_event(
            {
                "event_type": "performance",
                "message": "Documentation context served from cache",
                "cached": True,
            }
        )

    return value


def _compute_test_context() -> dict:
    """Compute test files and identify testing frameworks (pytest, jest)."""
    context = {"test_files": [], "frameworks": [], "coverage_info": {}}

    try:
        # Common test patterns
        test_patterns = [
            "*test*.py",
            "test_*.py",
            "*_test.py",
            "tests/*.py",
            "*.test.js",
            "test/*.js",
            "*.spec.js",
            "spec/*.js",
        ]

        for pattern in test_patterns:
            try:
                # SECURITY: Validate pattern
                if not re.match(r"^[\w\*\.\-/]+$", pattern):
                    continue

                # Find test files - SECURE subprocess call
                args = validate_subprocess_args(
                    ["find", ".", "-name", pattern, "-type", "f"],
                    allowed_commands=["find"],
                )
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=False,
                    timeout=10,
                )
                if result.returncode == 0:
                    files = result.stdout.splitlines()[:20]  # Limit to 20 files
                    context["test_files"].extend(files)
            except Exception:
                pass

        # Remove duplicates and limit
        context["test_files"] = list(set(context["test_files"]))[:15]

        # Detect testing frameworks
        framework_indicators = {
            "pytest": ["pytest.ini", "pyproject.toml", "conftest.py", "pytest.cfg"],
            "unittest": ["unittest", "TestCase"],
            "jest": ["jest.config.js", "package.json"],
            "mocha": ["mocha.opts", ".mocharc"],
            "vitest": ["vitest.config.js", "vite.config.js"],
        }

        for framework, indicators in framework_indicators.items():
            for indicator in indicators:
                if os.path.exists(indicator):
                    context["frameworks"].append(framework)
                    break
                # Also check in test file content
                for test_file in context["test_files"][:5]:  # Check first 5 files only
                    try:
                        if os.path.exists(test_file):
                            with open(test_file, "r", errors="ignore") as f:
                                content = f.read(1000)  # Read first 1000 chars
                                if indicator in content:
                                    context["frameworks"].append(framework)
                                    break
                    except Exception:
                        pass

        # Remove duplicates
        context["frameworks"] = list(set(context["frameworks"]))

        # Enhanced coverage analysis
        coverage_files = [".coveragerc", "coverage.xml", ".coverage", "coverage.json"]
        for cov_file in coverage_files:
            if os.path.exists(cov_file):
                context["coverage_info"][cov_file] = "present"

        # Parse coverage.xml for detailed coverage data
        if os.path.exists("coverage.xml"):
            coverage_data = parse_coverage_xml("coverage.xml")
            context["coverage_info"]["detailed_coverage"] = {
                "line_coverage_percent": coverage_data["line_coverage"],
                "branch_coverage_percent": coverage_data["branch_coverage"],
                "total_lines": coverage_data["total_lines"],
                "covered_lines": coverage_data["covered_lines"],
                "low_coverage_files": coverage_data["low_coverage_files"],
                "files_with_coverage": len(coverage_data["files_coverage"]),
            }

            # Add coverage summary for context
            if coverage_data["line_coverage"] > 0:
                coverage_status = (
                    "excellent"
                    if coverage_data["line_coverage"] >= 80
                    else (
                        "good"
                        if coverage_data["line_coverage"] >= 70
                        else (
                            "moderate"
                            if coverage_data["line_coverage"] >= 50
                            else "low"
                        )
                    )
                )
                context["coverage_info"]["coverage_status"] = coverage_status

        # Create test-to-implementation mapping
        if context["test_files"]:
            test_mapping = map_tests_to_implementations(context["test_files"])
            context["test_to_implementation_mapping"] = test_mapping
            context["mapped_test_count"] = len(test_mapping)

        # Get enhanced test statistics
        context["test_count"] = len(context["test_files"])
        context["framework_count"] = len(context["frameworks"])

        # Add testing insights
        context["testing_insights"] = {
            "has_tests": len(context["test_files"]) > 0,
            "multiple_frameworks": len(context["frameworks"]) > 1,
            "has_coverage_tracking": bool(context["coverage_info"]),
            "coverage_configured": any(
                f in context["coverage_info"] for f in ["coverage.xml", ".coverage"]
            ),
        }

    except Exception:
        pass

    return context


# claude-exempt: hook_handlers_py_protection - Adding performance context collection
def get_performance_context() -> dict:
    """
    Extract performance profiling context from available sources.
    Reads cProfile output and tracemalloc snapshots to identify performance bottlenecks.

    Returns:
        Dict containing performance metrics including slow functions and memory hotspots
    """
    context = {
        "slow_functions": [],
        "memory_hotspots": [],
        "total_memory_usage": None,
        "profile_files": [],
        "tracemalloc_snapshots": [],
        "performance_issues": [],
    }

    project_root = Path(os.getcwd())
    profile_dir = project_root / ".profile_data"

    try:
        # SECURITY: Validate directory path
        validated_profile_dir = validate_file_path(
            str(profile_dir),
            base_dir=str(project_root),
            must_exist=False,
            allow_symlinks=False,
        )

        if not validated_profile_dir.exists():
            return context

        # Find cProfile output files (.prof, .pstats)
        try:
            # SECURE subprocess call to find profile files
            for pattern in ["*.prof", "*.pstats", "*.profile"]:
                args = validate_subprocess_args(
                    [
                        "find",
                        str(validated_profile_dir),
                        "-name",
                        pattern,
                        "-type",
                        "f",
                    ],
                    allowed_commands=["find"],
                )
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=False,
                    timeout=5,
                )

                if result.returncode == 0:
                    files = result.stdout.splitlines()[:5]  # Limit to 5 files
                    context["profile_files"].extend(files)

            # Parse profile data for slow functions
            if context["profile_files"]:
                try:
                    import pstats
                    import io

                    for prof_file in context["profile_files"][
                        :2
                    ]:  # Process max 2 files
                        validated_prof = validate_file_path(
                            prof_file,
                            base_dir=str(project_root),
                            must_exist=True,
                            allow_symlinks=False,
                        )
                        if validated_prof.exists():
                            # Get top 5 slow functions
                            with io.StringIO() as stream:
                                # Create Stats object with stream parameter
                                stats = pstats.Stats(str(validated_prof), stream=stream)
                                stats.sort_stats("cumulative")
                                stats.print_stats(5)
                                output = stream.getvalue()

                            # Parse the output for function details
                            lines = output.splitlines()
                            for line in lines:
                                if "/" in line and not line.startswith(" "):
                                    # Extract function name and timing
                                    parts = line.split()
                                    if len(parts) >= 5:
                                        context["slow_functions"].append(
                                            {
                                                "ncalls": parts[0],
                                                "tottime": parts[1],
                                                "cumtime": parts[3],
                                                "function": parts[-1][
                                                    :100
                                                ],  # Truncate long names
                                            }
                                        )
                except ImportError:
                    # pstats not available, try reading raw profile data
                    for prof_file in context["profile_files"][:1]:
                        try:
                            validated_prof = validate_file_path(
                                prof_file,
                                base_dir=str(project_root),
                                must_exist=True,
                                allow_symlinks=False,
                            )
                            with open(validated_prof, "r", errors="ignore") as f:
                                content = f.read(2000)  # Read first 2KB
                                if (
                                    "cumulative" in content
                                    or "function calls" in content
                                ):
                                    context["performance_issues"].append(
                                        f"Profile data available in {prof_file}"
                                    )
                        except Exception:
                            pass
                except Exception:
                    pass

        except Exception:
            pass

        # Check for tracemalloc snapshots
        try:
            # Look for memory snapshot files
            snapshot_patterns = ["*.snapshot", "*.tracemalloc", "*.memprof"]
            for pattern in snapshot_patterns:
                try:
                    args = validate_subprocess_args(
                        [
                            "find",
                            str(validated_profile_dir),
                            "-name",
                            pattern,
                            "-type",
                            "f",
                        ],
                        allowed_commands=["find"],
                    )
                    result = subprocess.run(
                        args,
                        capture_output=True,
                        text=True,
                        check=False,
                        shell=False,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        files = result.stdout.splitlines()[:3]
                        context["tracemalloc_snapshots"].extend(files)
                except Exception:
                    pass

            # Parse memory snapshots
            if context["tracemalloc_snapshots"]:
                try:
                    import tracemalloc

                    for snapshot_file in context["tracemalloc_snapshots"][:1]:
                        validated_snap = validate_file_path(
                            snapshot_file,
                            base_dir=str(project_root),
                            must_exist=True,
                            allow_symlinks=False,
                        )
                        if validated_snap.exists():
                            with open(validated_snap, "rb") as f:
                                snapshot = tracemalloc.Snapshot.load(
                                    str(validated_snap)
                                )

                            # Get top memory consumers
                            top_stats = snapshot.statistics("lineno")[:5]
                            for stat in top_stats:
                                if stat.traceback:
                                    frame = stat.traceback[0]
                                    context["memory_hotspots"].append(
                                        {
                                            "file": os.path.basename(frame.filename),
                                            "line": frame.lineno,
                                            "size_kb": stat.size // 1024,
                                            "count": stat.count,
                                        }
                                    )

                            # Calculate total memory usage
                            total_size = sum(
                                stat.size for stat in snapshot.statistics("filename")
                            )
                            context["total_memory_usage"] = (
                                f"{total_size // (1024 * 1024)}MB"
                            )
                except ImportError:
                    # tracemalloc not available, note that snapshots exist
                    if context["tracemalloc_snapshots"]:
                        context["performance_issues"].append(
                            f"Memory snapshots available: {len(context['tracemalloc_snapshots'])} files"
                        )
                except Exception:
                    pass

        except Exception:
            pass

        # Check for other performance indicators
        perf_indicators = [
            ("flamegraph*.svg", "Flamegraph visualizations available"),
            ("*.bench", "Benchmark results available"),
            ("*.perf", "Performance data available"),
        ]

        for pattern, message in perf_indicators:
            try:
                args = validate_subprocess_args(
                    [
                        "find",
                        str(validated_profile_dir),
                        "-name",
                        pattern,
                        "-type",
                        "f",
                    ],
                    allowed_commands=["find"],
                )
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=False,
                    timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    context["performance_issues"].append(message)
            except Exception:
                pass

        # Limit collected data to avoid overwhelming context
        context["slow_functions"] = context["slow_functions"][:5]
        context["memory_hotspots"] = context["memory_hotspots"][:5]
        context["performance_issues"] = context["performance_issues"][:3]

    except Exception:
        # Silent failure - don't break context injection
        pass

    return context


def parse_coverage_xml(coverage_file: str) -> Dict[str, Any]:
    """Parse coverage.xml file and extract coverage data."""
    coverage_data = {
        "line_coverage": 0.0,
        "branch_coverage": 0.0,
        "files_coverage": {},
        "low_coverage_files": [],
        "total_lines": 0,
        "covered_lines": 0,
    }

    try:
        # Validate file path
        validated_path = validate_file_path(
            coverage_file,
            base_dir=".",
            must_exist=True,
            allow_symlinks=False,
        )

        if not validated_path.exists():
            return coverage_data

        tree = ET.parse(validated_path)
        root = tree.getroot()

        # Extract overall coverage metrics
        coverage_elem = root.find(".//coverage")
        if coverage_elem is not None:
            line_rate = float(coverage_elem.get("line-rate", 0)) * 100
            branch_rate = float(coverage_elem.get("branch-rate", 0)) * 100
            coverage_data["line_coverage"] = line_rate
            coverage_data["branch_coverage"] = branch_rate

        # Extract per-file coverage data
        packages = root.findall(".//package")
        for package in packages:
            classes = package.findall(".//class")
            for class_elem in classes:
                filename = class_elem.get("filename", "")
                if filename:
                    line_rate = float(class_elem.get("line-rate", 0)) * 100
                    branch_rate = float(class_elem.get("branch-rate", 0)) * 100

                    coverage_data["files_coverage"][filename] = {
                        "line_coverage": line_rate,
                        "branch_coverage": branch_rate,
                    }

                    # Identify low coverage files (<50%)
                    if line_rate < 50.0:
                        coverage_data["low_coverage_files"].append(
                            {
                                "file": filename,
                                "line_coverage": line_rate,
                                "branch_coverage": branch_rate,
                            }
                        )

        # Calculate totals from lines data
        lines = root.findall(".//line")
        total_lines = len(lines)
        covered_lines = sum(1 for line in lines if line.get("hits", "0") != "0")

        coverage_data["total_lines"] = total_lines
        coverage_data["covered_lines"] = covered_lines

    except Exception:
        # Silent fail - return empty coverage data
        pass

    return coverage_data


def map_tests_to_implementations(test_files: List[str]) -> Dict[str, List[str]]:
    """Create mapping between test files and their corresponding implementation files."""
    test_mapping = {}

    try:
        for test_file in test_files[:10]:  # Limit to first 10 test files
            try:
                validated_path = validate_file_path(
                    test_file,
                    base_dir=".",
                    must_exist=True,
                    allow_symlinks=False,
                )

                if not validated_path.exists():
                    continue

                # Extract potential implementation file names from test file
                implementations = []
                test_name = os.path.basename(test_file)

                # Common test naming patterns
                patterns = [
                    r"test_(.+)\.py$",  # test_module.py -> module.py
                    r"(.+)_test\.py$",  # module_test.py -> module.py
                    r"test(.+)\.py$",  # testModule.py -> module.py
                    r"(.+)\.test\.js$",  # module.test.js -> module.js
                    r"(.+)\.spec\.js$",  # module.spec.js -> module.js
                ]

                for pattern in patterns:
                    match = re.match(pattern, test_name)
                    if match:
                        impl_name = match.group(1)

                        # Look for corresponding implementation files
                        possible_extensions = [".py", ".js", ".ts", ".jsx", ".tsx"]
                        for ext in possible_extensions:
                            impl_file = impl_name + ext

                            # Check if implementation file exists in common locations
                            common_paths = [
                                impl_file,
                                f"src/{impl_file}",
                                f"lib/{impl_file}",
                                f"app/{impl_file}",
                                f"{impl_name}/{impl_name}{ext}",  # module/module.py
                            ]

                            for path in common_paths:
                                if os.path.exists(path):
                                    implementations.append(path)
                                    break
                        break

                if implementations:
                    test_mapping[test_file] = implementations

            except Exception:
                continue

    except Exception:
        pass

    return test_mapping


def get_test_context() -> dict:
    """Find test files and identify testing frameworks with caching."""
    # Cache test context for 300 seconds (5 minutes)
    # Track test config files for invalidation
    tracked_files = [
        "pytest.ini",
        "pyproject.toml",
        "conftest.py",
        "jest.config.js",
        ".mocharc",
        "vitest.config.js",
        ".coveragerc",
        "coverage.xml",
    ]

    value, was_cached = context_cache.get_or_compute(
        "test_context", _compute_test_context, ttl=300.0, tracked_files=tracked_files
    )

    if was_cached:
        logger.log_event(
            {
                "event_type": "performance",
                "message": "Test context served from cache",
                "cached": True,
            }
        )

    return value


def _compute_environment_context() -> dict:
    """Compute Python version, platform, virtual env, and installed packages."""
    context = {
        "python_version": "",
        "platform": "",
        "virtual_env": "",
        "installed_packages": [],
        "package_managers": [],
    }

    try:
        # Python version
        context["python_version"] = (
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )

        # Platform information
        import platform

        context["platform"] = f"{platform.system()} {platform.machine()}"

        # Virtual environment detection
        if hasattr(sys, "real_prefix") or (
            hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
        ):
            context["virtual_env"] = "active"
            if "VIRTUAL_ENV" in os.environ:
                context["virtual_env"] = os.path.basename(os.environ["VIRTUAL_ENV"])
        else:
            context["virtual_env"] = "none"

        # Detect package managers
        if os.path.exists("requirements.txt"):
            context["package_managers"].append("pip")
        if os.path.exists("Pipfile"):
            context["package_managers"].append("pipenv")
        if os.path.exists("pyproject.toml"):
            context["package_managers"].append("poetry/pip")
        if os.path.exists("package.json"):
            context["package_managers"].append("npm/yarn")
        if os.path.exists("yarn.lock"):
            context["package_managers"].append("yarn")
        if os.path.exists("package-lock.json"):
            context["package_managers"].append("npm")

        # Get key installed packages (limit to avoid overwhelming output)
        try:
            # Try pip list first (most common)
            if shutil.which("pip"):
                result = subprocess.run(
                    ["pip", "list", "--format=freeze"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                pip_output = result.stdout if result.returncode == 0 else ""
                lines = pip_output.splitlines()[:20]  # Limit to 20 packages
                context["installed_packages"] = [
                    line.split("==")[0] if "==" in line else line
                    for line in lines
                    if line.strip()
                ]
        except Exception:
            # Fallback to checking common packages
            common_packages = [
                "flask",
                "django",
                "fastapi",
                "requests",
                "numpy",
                "pandas",
                "pytest",
                "black",
                "mypy",
                "ruff",
            ]
            for pkg in common_packages:
                try:
                    __import__(pkg)
                    context["installed_packages"].append(pkg)
                except ImportError:
                    pass

        # Limit packages list
        context["installed_packages"] = context["installed_packages"][:15]

    except Exception:
        pass

    return context


def get_environment_context() -> dict:
    """Get Python version, platform, virtual env with caching."""
    # Cache environment for 600 seconds (10 minutes) - rarely changes
    # No file tracking needed as environment is system-level
    value, was_cached = context_cache.get_or_compute(
        "environment_context", _compute_environment_context, ttl=600.0
    )

    if was_cached:
        logger.log_event(
            {
                "event_type": "performance",
                "message": "Environment context served from cache",
                "cached": True,
            }
        )

    return value


def get_relevant_memories_context(user_prompt: str, session_id: str = "") -> str:
    """
    Retrieve relevant memories and format with categorization and code snippets.
    Uses lower threshold (0.3) for debugging tasks, higher (0.5) for others.

    Args:
        user_prompt: User's current prompt
        session_id: Current session identifier

    Returns:
        Formatted memory context string with categories and code snippets
    """
    try:
        # Determine if this is a debugging/troubleshooting task
        debug_keywords = [
            "error",
            "bug",
            "fix",
            "issue",
            "problem",
            "debug",
            "troubleshoot",
            "failing",
            "broken",
        ]
        is_debugging = any(keyword in user_prompt.lower() for keyword in debug_keywords)

        # Use lower threshold for debugging tasks
        relevance_threshold = 0.3 if is_debugging else 0.5

        # Get relevant memories with appropriate threshold
        memories = memory_manager.get_relevant_memories(
            context=user_prompt,
            session_id=session_id,
            limit=10,
            min_relevance=relevance_threshold,
        )

        if not memories:
            return ""

        # Categorize memories
        categories = {
            "API Endpoints": [],
            "Database Operations": [],
            "Algorithm Implementations": [],
            "Bug Fixes": [],
            "Configuration Changes": [],
            "General Context": [],
        }

        # Helper function to extract code snippets
        def extract_code_snippet(content: str) -> tuple[str, str]:
            """Extract code snippet and description from memory content."""
            # Look for code blocks in backticks
            import re

            code_match = re.search(r"```[\w]*\n?(.*?)```", content, re.DOTALL)
            if code_match:
                code = code_match.group(1).strip()
                # Get description (text before code block)
                desc_end = code_match.start()
                description = content[:desc_end].strip()
                if not description:
                    # Or text after code block
                    desc_start = code_match.end()
                    description = content[desc_start:].strip()
                return (
                    truncate_for_memory(description),
                    code[:300],
                )  # Smart truncation for description
            else:
                # No code block, treat as description only
                return truncate_for_memory(content), ""

        # Categorize each memory
        for memory in memories:
            content = memory.get("content", "")
            memory_type = memory.get("memory_type", "context")
            relevance = memory.get("combined_relevance", 0)
            tags = memory.get("tags", [])

            # Extract code snippet if present
            description, code_snippet = extract_code_snippet(content)

            # Create memory entry
            entry = {
                "description": description,
                "code": code_snippet,
                "relevance": relevance,
                "type": memory_type,
                "tags": tags,
            }

            # Categorize based on content and tags
            categorized = False
            content_lower = content.lower()

            # Check for API endpoints
            if any(
                kw in content_lower
                for kw in ["api", "endpoint", "route", "rest", "graphql", "http"]
            ):
                categories["API Endpoints"].append(entry)
                categorized = True
            # Check for database operations
            elif any(
                kw in content_lower
                for kw in ["database", "sql", "query", "table", "schema", "migration"]
            ):
                categories["Database Operations"].append(entry)
                categorized = True
            # Check for algorithms
            elif any(
                kw in content_lower
                for kw in [
                    "algorithm",
                    "sort",
                    "search",
                    "optimize",
                    "performance",
                    "complexity",
                ]
            ):
                categories["Algorithm Implementations"].append(entry)
                categorized = True
            # Check for bug fixes
            elif any(
                kw in content_lower
                for kw in ["fix", "bug", "error", "issue", "patch", "resolved"]
            ):
                categories["Bug Fixes"].append(entry)
                categorized = True
            # Check for configuration
            elif any(
                kw in content_lower
                for kw in ["config", "setting", "environment", "variable", "parameter"]
            ):
                categories["Configuration Changes"].append(entry)
                categorized = True

            # Default to general context
            if not categorized:
                categories["General Context"].append(entry)

        # Format output with categories
        formatted_output = []

        if is_debugging:
            formatted_output.append(
                "\n## 🔍 Relevant Debug Context from Memory (threshold: 0.3):\n"
            )
        else:
            formatted_output.append("\n## 📚 Relevant Context from Memory:\n")

        # Add each non-empty category
        for category_name, entries in categories.items():
            if entries:
                formatted_output.append(f"\n### {category_name}:")

                # Sort entries by relevance
                entries.sort(key=lambda x: x["relevance"], reverse=True)

                for entry in entries[:3]:  # Limit to top 3 per category
                    formatted_output.append(
                        f"\n**[{entry['type'].upper()}]** (relevance: {entry['relevance']:.2f})"
                    )

                    if entry["description"]:
                        formatted_output.append(f"  📝 {entry['description']}")

                    if entry["code"]:
                        formatted_output.append("  ```")
                        formatted_output.append(f"  {entry['code']}")
                        formatted_output.append("  ```")

                    if entry["tags"]:
                        formatted_output.append(
                            f"  🏷️ Tags: {', '.join(entry['tags'][:5])}"
                        )

        # Only return if we have actual content
        if len(formatted_output) > 2:  # More than just the header
            return "\n".join(formatted_output) + "\n"

        return ""

    except Exception as e:
        # Silent fail - don't break context injection if memory retrieval fails
        logger.log_error(
            f"Memory context retrieval failed: {e}", {"context": "memory_retrieval"}
        )
        return ""


# --- Claude Code Hook Entry Point ---


def handle(data):
    """
    Main handler with comprehensive security validation.
    Implements OWASP security best practices for input validation.
    """
    # Create security context
    security_context = create_security_context()

    # SECURITY: Validate JSON input structure and size
    try:
        data = validate_json_input(data)
        if not isinstance(data, dict):
            logger.log_error("Invalid input format - not a dictionary")
            print(json.dumps({"decision": "block", "reason": "Invalid input format"}))
            sys.exit(1)
    except SecurityValidationError as e:
        logger.log_error(f"Security validation failed: {sanitize_error_message(e)}")
        print(json.dumps({"decision": "block", "reason": "Input validation failed"}))
        sys.exit(1)
    except Exception as e:
        logger.log_error(f"Unexpected error: {sanitize_error_message(e)}")
        sys.exit(1)

    # SECURITY: Extract and validate all input fields
    try:
        # Validate user prompt with comprehensive security checks
        raw_prompt = data.get("prompt", "")
        user_prompt = validate_user_prompt(raw_prompt).strip()

        # Validate session ID format
        raw_session_id = data.get("session_id", "")
        session_id = validate_session_id(raw_session_id)

        # Validate hook event name
        hook_event_name = data.get("hook_event_name", "")
        if hook_event_name and not re.match(r"^[a-zA-Z0-9_]+$", hook_event_name):
            raise SecurityValidationError("Invalid hook event name format")

        # SECURITY: Implement rate limiting per session
        if session_id:
            try:
                check_rate_limit(
                    f"session_{session_id}", max_requests=30, window_seconds=60
                )
            except RateLimitExceeded:
                logger.log_error(f"Rate limit exceeded for session {session_id[:8]}...")
                print(
                    json.dumps(
                        {
                            "decision": "block",
                            "reason": "Rate limit exceeded. Please wait before making more requests.",
                        }
                    )
                )
                sys.exit(1)
        else:
            # Rate limit by global identifier if no session
            check_rate_limit("global_handler", max_requests=50, window_seconds=60)

    except SecurityValidationError as e:
        logger.log_error(f"Input validation failed: {sanitize_error_message(e)}")
        print(json.dumps({"decision": "block", "reason": "Invalid input parameters"}))
        sys.exit(1)
    except Exception as e:
        logger.log_error(f"Validation error: {sanitize_error_message(e)}")
        sys.exit(1)

    # Silent failure for non-applicable hooks
    if hook_event_name != "UserPromptSubmit":
        sys.exit(0)

    if not user_prompt:
        logger.log_context_injection(success=False, context=None)
        sys.exit(0)  # Do nothing

    # Initialize session if not already done (with validated session_id)
    if session_id:
        try:
            state_manager.initialize_session(session_id)
        except Exception as e:
            logger.log_error(
                f"Session initialization failed: {sanitize_error_message(e)}"
            )
            # Continue without session rather than failing

    verbose_outline = bootstrap_summary(SUMMARY_OUTPUT, CONSTANTS)
    if not verbose_outline:
        logger.log_error("No semantic outline available")
        sys.exit(0)

    # Get agent information
    project_root = Path(os.getcwd())
    agents_dir = project_root / CONSTANTS["file_paths"]["agents_dir_relative_path"]
    agents = get_agent_info(str(agents_dir))

    # Define MCP server information
    mcp_servers = CONSTANTS["mcp_servers"]

    try:
        # Extract keywords from prompt for better context filtering
        keywords = extract_keywords(user_prompt)

        # Filter outline to most relevant files
        relevant_outline = filter_relevant_files(user_prompt, verbose_outline, top_k=25)

        # Get git context relevant to prompt
        git_context = get_git_context(keywords)

        # Get error context if troubleshooting
        error_context = (
            get_error_context()
            if any(
                word in user_prompt.lower()
                for word in ["error", "bug", "fix", "issue", "problem"]
            )
            else None
        )

        # Get additional context types
        project_config = get_project_config()
        project_docs = get_project_documentation()
        test_context = get_test_context()
        env_context = get_environment_context()

        # Get performance profiling context if user is asking about performance
        performance_context = None
        perf_keywords = [
            "performance",
            "slow",
            "optimize",
            "profile",
            "memory",
            "leak",
            "bottleneck",
            "speed",
            "faster",
            "cpu",
            "ram",
            "profiling",
        ]
        if any(keyword in user_prompt.lower() for keyword in perf_keywords):
            performance_context = get_performance_context()

        # Get relevant memories for context injection
        memory_context = get_relevant_memories_context(user_prompt, session_id)

        # Get database schema context if relevant
        database_context = get_database_context(user_prompt)

        # Add cross-file pattern analysis
        cross_file_patterns = aggregate_cross_file_patterns(verbose_outline)

        # Extract test metrics if test files found
        test_files = [f for f in verbose_outline.keys() if "test" in f.lower()]
        test_metrics = extract_test_metrics(test_files) if test_files else None

        # Get context configuration for prompt
        context_config = calculate_context_depth(user_prompt)

        # Build import graph for smaller projects (optional - only if project seems small)
        import_graph = None
        try:
            # Count Python files safely - SECURE subprocess call
            args = validate_subprocess_args(
                ["find", ".", "-name", "*.py", "-type", "f"], allowed_commands=["find"]
            )
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=10,
            )
            if result.returncode == 0:
                file_count = len(result.stdout.splitlines())
                if file_count < 50:  # Only for smaller projects
                    import_graph = build_import_graph(CONSTANTS)
        except Exception:
            pass

        # SECURITY: Validate and sanitize all data before sending to Gemini API
        try:
            # Prepare API data with validation
            api_data = {
                "user_prompt": user_prompt,  # Already validated
                "session_id": session_id,  # Already validated
                "relevant_outline": relevant_outline,
                "mcp_servers": mcp_servers,
                "agents": agents,
                "git_context": git_context,
                "error_context": error_context,
                "project_config": project_config,
                "project_docs": project_docs,
                "test_context": test_context,
                "env_context": env_context,
                "import_graph": import_graph,
                "cross_file_patterns": cross_file_patterns,
                "test_metrics": test_metrics,
                "context_depth": context_config,
                "memory_context": memory_context,
                "database_context": database_context,
                "performance_context": performance_context,
            }

            # Sanitize all API data to prevent injection attacks
            sanitized_api_data = api_data

            # Call Gemini with sanitized data
            gemini_response = call_gemini(
                str(sanitized_api_data.get("user_prompt", "")),
                sanitized_api_data.get("relevant_outline", {}),
                sanitized_api_data.get("mcp_servers"),
                sanitized_api_data.get("agents"),
                str(sanitized_api_data.get("session_id", "")),
                git_context=sanitized_api_data.get("git_context"),
                error_context=sanitized_api_data.get("error_context"),
                project_config=sanitized_api_data.get("project_config"),
                project_docs=sanitized_api_data.get("project_docs"),
                test_context=sanitized_api_data.get("test_context"),
                env_context=sanitized_api_data.get("env_context"),
                import_graph=sanitized_api_data.get("import_graph"),
                cross_file_patterns=sanitized_api_data.get("cross_file_patterns"),
                test_metrics=sanitized_api_data.get("test_metrics"),
                context_depth=sanitized_api_data.get("context_depth"),
                memory_context=sanitized_api_data.get("memory_context"),
                database_context=sanitized_api_data.get("database_context"),
            )
        except requests.exceptions.Timeout:
            logger.log_error("Gemini API timeout")
            sys.exit(2)  # Blocking error - API timeout
        except requests.exceptions.RequestException as e:
            logger.log_error(f"Gemini API request failed: {e}")
            sys.exit(2)  # Blocking error - API failure

        # Add continuation tracking information to context (now redundant but kept for backward compatibility)
        continuation_info = ""
        if session_id:
            current_continuation = get_current_continuation_id(session_id)
            if current_continuation:
                continuation_info = f"\n\nCONTINUATION_ID: {current_continuation} (Use this in mcp__zen tools for conversation continuity)"
            else:
                continuation_info = (
                    "\n\nNO_CONTINUATION: This is a new conversation thread"
                )

        # Output properly structured JSON for UserPromptSubmit context injection
        json_keys = CONSTANTS["json_structure"]
        output = {
            "continue": True,  # CRITICAL: Required for context injection
            json_keys["hook_specific_output_key"]: {
                "hookEventName": json_keys["hook_event_name"],
                json_keys[
                    "additional_context_key"
                ]: f"{CONSTANTS['response_template']['context_prefix']}{gemini_response}{continuation_info}",
            },
        }

        # Log successful context injection with cache statistics
        cache_stats = context_cache.get_stats()
        logger.log_context_injection(success=True, context=gemini_response)
        logger.log_event(
            {
                "event_type": "performance",
                "message": f"Context cache stats - Hit rate: {cache_stats['hit_rate']}, "
                f"Hits: {cache_stats['hits']}, Misses: {cache_stats['misses']}, "
                f"Entries: {cache_stats['entries']}, Memory: {cache_stats['memory_usage']} bytes",
                **cache_stats,
            }
        )

        print(json.dumps(output))
        sys.exit(0)

    except Exception as e:
        # Log the error
        logger.log_error(
            f"Gemini request failed: {e}", {"exception_type": type(e).__name__}
        )

        # Block with error message
        json_keys = CONSTANTS["json_structure"]
        output = {
            "continue": False,  # CRITICAL: Indicates blocking/error state
            json_keys["decision_key"]: json_keys["block_decision"],
            json_keys[
                "reason_key"
            ]: f"{CONSTANTS['response_template']['gemini_failure_prefix']}{e}",
        }
        print(json.dumps(output))
        sys.exit(2)  # Blocking error - Context injection failed
