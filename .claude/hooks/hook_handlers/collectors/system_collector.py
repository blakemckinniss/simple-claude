"""
Optimized system collector - minimal essential info.
"""

import os
from typing import Dict, Any, List


class SystemCollector:
    """Fast system information collector."""
    
    def __init__(self, cwd: str):
        self.cwd = cwd
    
    def _detect_project_type(self) -> List[str]:
        """Fast project type detection using file existence."""
        project_types = []
        
        # Fast file existence checks
        files_to_check = {
            'python': ['requirements.txt', 'setup.py', 'pyproject.toml'],
            'javascript': ['package.json'],
            'typescript': ['tsconfig.json'],
            'rust': ['Cargo.toml'],
            'go': ['go.mod'],
            'docker': ['Dockerfile']
        }
        
        for project_type, files in files_to_check.items():
            for file in files:
                if os.path.exists(os.path.join(self.cwd, file)):
                    project_types.append(project_type)
                    break
        
        return project_types
    
    def collect(self) -> Dict[str, Any]:
        """Fast system collection - essential info only."""
        system_data = {}
        
        # Fast directory count
        try:
            items = os.listdir(self.cwd)
            dirs = [i for i in items if os.path.isdir(os.path.join(self.cwd, i)) and not i.startswith('.')]
            files = [i for i in items if os.path.isfile(os.path.join(self.cwd, i))]
            
            system_data["directory_info"] = {
                "directory_count": len(dirs),
                "file_count": len(files)
            }
        except:
            system_data["directory_info"] = {"directory_count": 0, "file_count": 0}
        
        # Fast project type detection
        project_types = self._detect_project_type()
        if project_types:
            system_data["project_types"] = project_types
        
        return system_data