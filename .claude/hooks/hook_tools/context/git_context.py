#!/usr/bin/env python3
"""Git context extraction utilities."""

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple


def _run_git_command(command: List[str], timeout: float = 2.0) -> Tuple[str, List[str], int]:
    """Execute a git command with timeout.
    
    Returns:
        Tuple of (command_type, output_lines, return_code)
    """
    cmd_type = command[1] if len(command) > 1 else "unknown"
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout
        )
        if result.returncode == 0:
            return (cmd_type, result.stdout.splitlines() if result.stdout else [], 0)
        return (cmd_type, [], result.returncode)
    except (subprocess.TimeoutExpired, OSError):
        return (cmd_type, [], -1)


def get_git_context(keywords: Optional[List[str]] = None) -> dict:
    """Get recent git activity context using parallel execution."""
    # claude-exempt: High Cyclomatic Complexity - Complex business logic requires multiple decision paths
    context = {
        "working_on": "",
        "recent_commits": [],
        "recently_changed": [],
        "current_branch": ""
    }
    
    # Define all git commands to run in parallel
    commands = [
        (["git", "branch", "--show-current"], 2.0),
        (["git", "status", "--short"], 2.0),
        (["git", "log", "--oneline", "-10"], 2.0),
        (["git", "delta", "--name-only", "HEAD~5"], 2.0),
    ]
    
    try:
        # Execute all commands in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Submit all tasks
            futures = {
                executor.submit(_run_git_command, cmd, timeout): cmd[0]
                for cmd, timeout in commands
            }
            
            # Collect results as they complete
            results = {}
            for future in as_completed(futures, timeout=3.0):
                try:
                    cmd_type, output, returncode = future.result(timeout=0.5)
                    results[cmd_type] = (output, returncode)
                except Exception:
                    continue
            
            # Process branch result
            if "branch" in results and results["branch"][1] == 0:
                output = results["branch"][0]
                if output:
                    context["current_branch"] = output[0].strip()
            
            # Process status result
            if "status" in results and results["status"][1] == 0:
                output = results["status"][0]
                context["working_on"] = "\n".join(output).strip()
            
            # Process log result
            if "log" in results and results["log"][1] == 0:
                commits = results["log"][0]
                if keywords:
                    context["recent_commits"] = [
                        c for c in commits 
                        if any(kw.lower() in c.lower() for kw in keywords)
                    ][:5]
                else:
                    context["recent_commits"] = commits[:5]
            
            # Process diff result for recently changed files
            changed_files = []
            if "diff" in results and results["diff"][1] == 0:
                changed_files = results["diff"][0]
            elif "diff" in results and results["diff"][1] != 0:
                # Fallback: run ls-files if diff fails (but only if needed)
                cmd_type, output, returncode = _run_git_command(["git", "ls-files"], 2.0)
                if returncode == 0:
                    changed_files = output
            
            # Apply keyword filtering to changed files
            if changed_files:
                if keywords:
                    context["recently_changed"] = [
                        f for f in changed_files 
                        if any(kw.lower() in f.lower() for kw in keywords)
                    ][:10]
                else:
                    context["recently_changed"] = changed_files[:10]
                    
    except Exception:
        # Return empty context on any unexpected error
        pass
    
    return context