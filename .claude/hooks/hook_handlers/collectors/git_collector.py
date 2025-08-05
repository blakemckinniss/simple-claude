"""
Optimized git collector - fast basic git info.
"""

import subprocess
import os
from typing import Dict, Any, Optional


class GitCollector:
    """Fast git information collector."""
    
    def __init__(self, cwd: str):
        self.cwd = cwd
    
    def _run_fast(self, args: list) -> Optional[str]:
        """Run git command with minimal timeout."""
        try:
            result = subprocess.run(
                ['git'] + args, cwd=self.cwd, capture_output=True, 
                text=True, timeout=0.3
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except:
            return None
    
    def collect(self) -> Dict[str, Any]:
        """Fast git collection - essential info only."""
        if not os.path.exists(os.path.join(self.cwd, '.git')):
            return {"is_git_repo": False}
        
        git_data = {"is_git_repo": True}
        
        # Current branch (fast)
        branch = self._run_fast(['branch', '--show-current'])
        if branch:
            git_data["current_branch"] = branch
        
        # Basic status count only
        status = self._run_fast(['status', '--porcelain'])
        if status:
            lines = [l for l in status.split('\n') if l.strip()]
            git_data["changes"] = len(lines)
        
        return git_data