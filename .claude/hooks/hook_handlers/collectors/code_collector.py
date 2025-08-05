"""
Optimized code collector using fast commands.
"""

import subprocess
import os
from typing import Dict, Any, Optional


class CodeCollector:
    """Fast code statistics collector."""
    
    def __init__(self, cwd: str):
        self.cwd = cwd
    
    def _run_fast(self, command: list) -> Optional[str]:
        """Run command with minimal timeout."""
        try:
            result = subprocess.run(
                command, cwd=self.cwd, capture_output=True, 
                text=True, timeout=0.4
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except:
            return None
    
    def collect(self) -> Dict[str, Any]:
        """Fast code collection using fd and basic stats."""
        code_data = {}
        
        # Use fd for fast file counting (much faster than find)
        fd_output = self._run_fast(['fd', '.', '--type', 'f'])
        if fd_output:
            files = fd_output.split('\n')
            code_data["file_count"] = len(files)
            
            # Get extensions from sample of files
            extensions = {}
            for f in files[:30]:  # Sample first 30 files
                ext = os.path.splitext(f)[1]
                if ext:
                    extensions[ext] = extensions.get(ext, 0) + 1
            
            if extensions:
                # Top 5 extensions only
                sorted_ext = sorted(extensions.items(), key=lambda x: x[1], reverse=True)
                code_data["file_extensions"] = dict(sorted_ext[:5])
        else:
            # Fallback to basic directory listing if fd not available
            try:
                items = os.listdir(self.cwd)
                files = [f for f in items if os.path.isfile(os.path.join(self.cwd, f))]
                code_data["file_count"] = len(files)
            except:
                code_data["file_count"] = 0
        
        return code_data