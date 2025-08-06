#!/usr/bin/env python3
import os
import sys
import json
import shutil
import re
import requests
import ast
from pathlib import Path
from subprocess import check_output
from typing import List, Optional

# Import the simplified logger, state manager, and memory manager
from hook_tools.utilities.path_resolver import PathResolver

paths = PathResolver()
from hook_logger import logger
from hook_tools.state_manager import state_manager
from hook_tools.memory_manager import memory_manager

# Import from new modular structure
from hook_tools.utilities.constants_loader import load_constants, load_env
from hook_tools.utilities.import_graph import build_import_graph
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

# Tool output cache for synthesis
TOOL_OUTPUT_CACHE = {}
CACHE_TTL = 300  # 5 minutes

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


def get_git_context(keywords: Optional[List[str]] = None) -> dict:
    """Get recent git activity context."""
    try:
        context = {
            "working_on": "",
            "recent_commits": [],
            "recently_changed": [],
            "current_branch": "",
        }

        # Get current branch
        try:
            context["current_branch"] = check_output(
                "git branch --show-current", shell=True, text=True
            ).strip()
        except Exception:
            pass

        # Get working directory status
        try:
            context["working_on"] = check_output(
                "git status --short", shell=True, text=True
            ).strip()
        except Exception:
            pass

        # Get recent commits
        try:
            commits = check_output(
                "git log --oneline -10", shell=True, text=True
            ).splitlines()
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

        # Get recently changed files
        try:
            changed = check_output(
                "git diff --name-only HEAD~5 2>/dev/null || git ls-files",
                shell=True,
                text=True,
            ).splitlines()
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


def get_error_context() -> dict:
    """Extract recent errors from logs and terminal output."""
    context = {"recent_errors": [], "warnings": []}

    # Check common log locations
    log_patterns = ["*.log", "*.err", "error.txt", "debug.log"]

    for pattern in log_patterns:
        try:
            # Find recent log files
            files = check_output(
                f"find . -name '{pattern}' -mtime -1 2>/dev/null | head -5",
                shell=True,
                text=True,
            ).splitlines()

            for log_file in files:
                if os.path.exists(log_file):
                    try:
                        with open(log_file, "r", errors="ignore") as f:
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

    return context


def get_project_config() -> dict:
    """Extract project configuration from various config files."""
    context = {
        "dependencies": [],
        "scripts": {},
        "make_targets": [],
        "config_files": [],
    }

    project_root = Path(os.getcwd())

    # Check requirements.txt
    requirements_path = project_root / "requirements.txt"
    if requirements_path.exists():
        try:
            with open(requirements_path, "r", encoding="utf-8", errors="ignore") as f:
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

    # Check package.json
    package_json_path = project_root / "package.json"
    if package_json_path.exists():
        try:
            with open(package_json_path, "r", encoding="utf-8") as f:
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


def get_project_documentation() -> dict:
    """Extract project documentation context."""
    context = {"readme_files": [], "doc_dirs": [], "key_docs": []}

    # Look for README files
    readme_patterns = ["README*", "readme*", "Readme*"]
    for pattern in readme_patterns:
        try:
            files = check_output(
                f"find . -maxdepth 2 -name '{pattern}' 2>/dev/null | head -3",
                shell=True,
                text=True,
            ).splitlines()
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


def get_test_context() -> dict:
    """Find test files and identify testing frameworks (pytest, jest)."""
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
                # Find test files
                files = check_output(
                    f"find . -name '{pattern}' -type f 2>/dev/null | head -20",
                    shell=True,
                    text=True,
                ).splitlines()
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

        # Check for coverage configuration
        coverage_files = [".coveragerc", "coverage.xml", ".coverage", "coverage.json"]
        for cov_file in coverage_files:
            if os.path.exists(cov_file):
                context["coverage_info"][cov_file] = "present"

        # Get basic test statistics
        context["test_count"] = len(context["test_files"])
        context["framework_count"] = len(context["frameworks"])

    except Exception:
        pass

    return context


def get_environment_context() -> dict:
    """Get Python version, platform, virtual env, and installed packages."""
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
                pip_output = check_output(
                    "pip list --format=freeze 2>/dev/null", shell=True, text=True
                )
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


def get_relevant_memories_context(user_prompt: str, session_id: str = "") -> str:
    """
    Retrieve relevant memories and format as concise context hints.
    Only inject highly relevant memories (score > 0.5).

    Args:
        user_prompt: User's current prompt
        session_id: Current session identifier

    Returns:
        Formatted memory context string or empty string
    """
    try:
        # Get relevant memories with high threshold
        memories = memory_manager.get_relevant_memories(
            context=user_prompt, session_id=session_id, limit=5, min_relevance=0.5
        )

        if not memories:
            return ""

        # Format as concise context hints
        memory_hints = []
        for memory in memories:
            content = memory.get("content", "")[:150]  # Truncate long content
            memory_type = memory.get("memory_type", "context")
            relevance = memory.get("combined_relevance", 0)

            hint = f"[{memory_type.upper()}] {content} (relevance: {relevance:.2f})"
            memory_hints.append(hint)

        if memory_hints:
            return (
                f"\n## Relevant Context from Memory:\n"
                + "\n".join(f"- {hint}" for hint in memory_hints)
                + "\n"
            )

        return ""

    except Exception:
        # Silent fail - don't break context injection if memory retrieval fails
        return ""


# --- Claude Code Hook Entry Point ---


def handle(data):
    # HOOK_CONTRACT: Validate JSON input per security requirements
    try:
        if not isinstance(data, dict):
            print("Error: Invalid input format", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Error: Input validation failed: {e}", file=sys.stderr)
        sys.exit(1)

    # HOOK_CONTRACT: Validate expected fields exist
    user_prompt = data.get("prompt", "").strip()
    session_id = data.get("session_id", "")
    hook_event_name = data.get("hook_event_name", "")

    # Silent failure for non-applicable hooks
    if hook_event_name != "UserPromptSubmit":
        sys.exit(0)

    if not user_prompt:
        logger.log_context_injection(success=False, context=None)
        sys.exit(0)  # Do nothing

    # Initialize session if not already done
    if session_id:
        state_manager.initialize_session(session_id)

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

        # Get relevant memories for context injection
        memory_context = get_relevant_memories_context(user_prompt, session_id)

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
            file_count = len(
                check_output(
                    "find . -name '*.py' | wc -l", shell=True, text=True
                ).strip()
            )
            if int(file_count) < 50:  # Only for smaller projects
                import_graph = build_import_graph(CONSTANTS)
        except Exception:
            pass

        # Pass enhanced context to Gemini with error handling
        try:
            gemini_response = call_gemini(
                user_prompt,
                relevant_outline,
                mcp_servers,
                agents,
                session_id,
                git_context=git_context,
                error_context=error_context,
                project_config=project_config,
                project_docs=project_docs,
                test_context=test_context,
                env_context=env_context,
                import_graph=import_graph,
                cross_file_patterns=cross_file_patterns,
                test_metrics=test_metrics,
                context_depth=context_config,
                memory_context=memory_context,
            )
        except requests.exceptions.Timeout:
            logger.log_error("Gemini API timeout")
            sys.exit(0)  # Silent failure
        except requests.exceptions.RequestException as e:
            logger.log_error(f"Gemini API request failed: {e}")
            sys.exit(0)  # Silent failure

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
            json_keys["hook_specific_output_key"]: {
                "hookEventName": json_keys["hook_event_name"],
                json_keys[
                    "additional_context_key"
                ]: f"{CONSTANTS['response_template']['context_prefix']}{gemini_response}{continuation_info}",
            }
        }

        # Log successful context injection
        logger.log_context_injection(success=True, context=gemini_response)

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
            json_keys["decision_key"]: json_keys["block_decision"],
            json_keys[
                "reason_key"
            ]: f"{CONSTANTS['response_template']['gemini_failure_prefix']}{e}",
        }
        print(json.dumps(output))
        sys.exit(0)
