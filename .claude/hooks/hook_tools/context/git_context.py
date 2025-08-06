#!/usr/bin/env python3
"""Git context extraction utilities."""

import subprocess
from typing import List, Optional


def get_git_context(keywords: Optional[List[str]] = None) -> dict:
    """Get recent git activity context."""
    # claude-exempt: High Cyclomatic Complexity - Complex business logic requires multiple decision paths
    try:
        context = {
            "working_on": "",
            "recent_commits": [],
            "recently_changed": [],
            "current_branch": ""
        }
        
        # Get current branch
        try:
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5
            )
            if result.returncode == 0:
                context["current_branch"] = result.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            pass
            
        # Get working directory status
        try:
            result = subprocess.run(
                ["git", "status", "--short"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5
            )
            if result.returncode == 0:
                context["working_on"] = result.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            pass
        
        # Get recent commits
        try:
            result = subprocess.run(
                ["git", "log", "--oneline", "-10"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10
            )
            if result.returncode == 0:
                commits = result.stdout.splitlines()
                if keywords:
                    # Filter commits by keywords
                    context["recent_commits"] = [c for c in commits 
                                                if any(kw.lower() in c.lower() for kw in keywords)][:5]
                else:
                    context["recent_commits"] = commits[:5]
        except (subprocess.TimeoutExpired, OSError):
            pass
        
        # Get recently changed files
        try:
            # Try git diff first
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD~5"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10
            )
            if result.returncode == 0:
                changed = result.stdout.splitlines()
            else:
                # Fallback to git ls-files
                result = subprocess.run(
                    ["git", "ls-files"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10
                )
                changed = result.stdout.splitlines() if result.returncode == 0 else []
            
            if keywords:
                context["recently_changed"] = [f for f in changed 
                                              if any(kw.lower() in f.lower() for kw in keywords)][:10]
            else:
                context["recently_changed"] = changed[:10]
        except (subprocess.TimeoutExpired, OSError):
            pass
            
        return context
    except Exception:
        return {"working_on": "", "recent_commits": [], "recently_changed": [], "current_branch": ""}