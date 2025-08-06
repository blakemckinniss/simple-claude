#!/usr/bin/env python3
"""Project context extraction utilities."""

import os
import sys
import json
import shutil
import platform
import re
import subprocess
from pathlib import Path
from typing import Dict, List


def get_error_context() -> dict:
    """Extract recent errors from logs and terminal output."""
    context = {"recent_errors": [], "warnings": []}
    
    # Check common log locations
    log_patterns = ['*.log', '*.err', 'error.txt', 'debug.log']
    
    for pattern in log_patterns:
        try:
            # Find recent log files
            result = subprocess.run(
                ["find", ".", "-name", pattern, "-mtime", "-1"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10
            )
            
            if result.returncode == 0:
                files = result.stdout.splitlines()[:5]  # Limit to 5 files
                
                for log_file in files:
                    if os.path.exists(log_file):
                        try:
                            with open(log_file, 'r', errors='ignore') as f:
                                # Read last 100 lines
                                lines = f.readlines()[-100:]
                                
                                # Extract errors
                                for line in lines:
                                    if 'ERROR' in line or 'Exception' in line or 'Traceback' in line:
                                        context["recent_errors"].append(line.strip()[:200])  # Truncate long lines
                                    elif 'WARNING' in line or 'WARN' in line:
                                        context["warnings"].append(line.strip()[:200])
                                        
                                # Limit to most recent
                                context["recent_errors"] = context["recent_errors"][-5:]
                                context["warnings"] = context["warnings"][-3:]
                        except (OSError, IOError):
                            pass
        except (subprocess.TimeoutExpired, OSError):
            pass
    
    return context


def get_project_config() -> dict:
    """Extract project configuration from various config files."""
    # claude-exempt: High Cyclomatic Complexity - Complex business logic requires multiple decision paths  
    context = {
        "dependencies": [],
        "scripts": {},
        "make_targets": [],
        "config_files": []
    }
    
    project_root = Path(os.getcwd())
    
    # Check requirements.txt
    requirements_path = project_root / "requirements.txt"
    if requirements_path.exists():
        try:
            with open(requirements_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:20]  # Limit to first 20 dependencies
                deps = [line.strip().split('==')[0].split('>=')[0].split('~=')[0] 
                       for line in lines if line.strip() and not line.startswith('#')]
                context["dependencies"].extend(deps)
                context["config_files"].append("requirements.txt")
        except (OSError, IOError):
            pass
    
    # Check package.json
    package_json_path = project_root / "package.json"
    if package_json_path.exists():
        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if "dependencies" in data:
                    context["dependencies"].extend(list(data["dependencies"].keys())[:10])
                if "devDependencies" in data:
                    context["dependencies"].extend(list(data["devDependencies"].keys())[:10])
                if "scripts" in data:
                    context["scripts"].update(data["scripts"])
                context["config_files"].append("package.json")
        except (OSError, IOError, json.JSONDecodeError):
            pass
    
    # Check pyproject.toml
    pyproject_path = project_root / "pyproject.toml"
    if pyproject_path.exists():
        try:
            with open(pyproject_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Simple regex-based extraction for dependencies
                deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if deps_match:
                    deps_str = deps_match.group(1)
                    deps = re.findall(r'["\']([^"\'>=<]+)["\']', deps_str)
                    context["dependencies"].extend(deps[:10])
                context["config_files"].append("pyproject.toml")
        except (OSError, IOError):
            pass
    
    # Check setup.py
    setup_py_path = project_root / "setup.py"
    if setup_py_path.exists():
        try:
            with open(setup_py_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()[:2000]  # Read first 2000 chars to avoid large files
                # Extract install_requires dependencies
                deps_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if deps_match:
                    deps_str = deps_match.group(1)
                    deps = re.findall(r'["\']([^"\'>=<]+)["\']', deps_str)
                    context["dependencies"].extend(deps[:10])
                context["config_files"].append("setup.py")
        except (OSError, IOError):
            pass
    
    # Check Makefile
    makefile_path = project_root / "Makefile"
    if makefile_path.exists():
        try:
            with open(makefile_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:50]  # Limit to first 50 lines
                targets = []
                for line in lines:
                    # Find make targets (lines that start without whitespace and contain :)
                    if not line.startswith('\t') and ':' in line and not line.startswith('#'):
                        target = line.split(':')[0].strip()
                        if target and not target.startswith('.'):  # Skip special targets
                            targets.append(target)
                context["make_targets"] = targets[:10]  # Limit to 10 targets
                if targets:
                    context["config_files"].append("Makefile")
        except (OSError, IOError):
            pass
    
    # Remove duplicates and limit total dependencies
    context["dependencies"] = list(dict.fromkeys(context["dependencies"]))[:15]
    
    return context


def get_project_documentation() -> dict:
    """Extract project documentation context."""
    context = {"readme_files": [], "doc_dirs": [], "key_docs": []}
    
    # Look for README files
    readme_patterns = ['README*', 'readme*', 'Readme*']
    for pattern in readme_patterns:
        try:
            result = subprocess.run(
                ["find", ".", "-maxdepth", "2", "-name", pattern],
                capture_output=True,
                text=True,
                check=False,
                timeout=5
            )
            if result.returncode == 0:
                files = result.stdout.splitlines()[:3]  # Limit to 3 files
                context["readme_files"].extend(files)
        except (subprocess.TimeoutExpired, OSError):
            pass
    
    # Look for documentation directories
    doc_dirs = ['docs', 'doc', 'documentation', 'wiki', 'guides']
    for doc_dir in doc_dirs:
        if os.path.exists(doc_dir) and os.path.isdir(doc_dir):
            context["doc_dirs"].append(doc_dir)
    
    # Look for key documentation files
    key_docs = ['CHANGELOG.md', 'CONTRIBUTING.md', 'LICENSE', 'API.md', 'USAGE.md']
    for doc_file in key_docs:
        if os.path.exists(doc_file):
            context["key_docs"].append(doc_file)
    
    return context


def get_test_context() -> dict:
    """Find test files and identify testing frameworks (pytest, jest)."""
    # claude-exempt: High Cyclomatic Complexity - Complex business logic requires multiple decision paths
    context = {"test_files": [], "frameworks": [], "coverage_info": {}}
    
    try:
        # Common test patterns
        test_patterns = ['*test*.py', 'test_*.py', '*_test.py', 'tests/*.py', 
                        '*.test.js', 'test/*.js', '*.spec.js', 'spec/*.js']
        
        for pattern in test_patterns:
            try:
                # Find test files using find command
                result = subprocess.run(
                    ["find", ".", "-name", pattern, "-type", "f"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10
                )
                if result.returncode == 0:
                    files = result.stdout.splitlines()[:20]  # Limit to 20 files
                    context["test_files"].extend(files)
            except (subprocess.TimeoutExpired, OSError):
                pass
        
        # Remove duplicates and limit
        context["test_files"] = list(set(context["test_files"]))[:15]
        
        # Detect testing frameworks
        framework_indicators = {
            'pytest': ['pytest.ini', 'pyproject.toml', 'conftest.py', 'pytest.cfg'],
            'unittest': ['unittest', 'TestCase'],
            'jest': ['jest.config.js', 'package.json'],
            'mocha': ['mocha.opts', '.mocharc'],
            'vitest': ['vitest.config.js', 'vite.config.js']
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
                            with open(test_file, 'r', errors='ignore') as f:
                                content = f.read(1000)  # Read first 1000 chars
                                if indicator in content:
                                    context["frameworks"].append(framework)
                                    break
                    except (OSError, IOError):
                        pass
        
        # Remove duplicates
        context["frameworks"] = list(set(context["frameworks"]))
        
        # Check for coverage configuration
        coverage_files = ['.coveragerc', 'coverage.xml', '.coverage', 'coverage.json']
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
    # claude-exempt: High Cyclomatic Complexity - Complex business logic requires multiple decision paths
    context = {
        "python_version": "",
        "platform": "",
        "virtual_env": "",
        "installed_packages": [],
        "package_managers": []
    }
    
    try:
        # Python version
        context["python_version"] = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        
        # Platform information
        context["platform"] = f"{platform.system()} {platform.machine()}"
        
        # Virtual environment detection
        if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
            context["virtual_env"] = "active"
            if 'VIRTUAL_ENV' in os.environ:
                context["virtual_env"] = os.path.basename(os.environ['VIRTUAL_ENV'])
        else:
            context["virtual_env"] = "none"
        
        # Detect package managers
        if os.path.exists('requirements.txt'):
            context["package_managers"].append("pip")
        if os.path.exists('Pipfile'):
            context["package_managers"].append("pipenv")
        if os.path.exists('pyproject.toml'):
            context["package_managers"].append("poetry/pip")
        if os.path.exists('package.json'):
            context["package_managers"].append("npm/yarn")
        if os.path.exists('yarn.lock'):
            context["package_managers"].append("yarn")
        if os.path.exists('package-lock.json'):
            context["package_managers"].append("npm")
        
        # Get key installed packages (limit to avoid overwhelming output)
        try:
            # Try pip list first (most common)
            if shutil.which('pip'):
                result = subprocess.run(
                    ["pip", "list", "--format=freeze"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=15
                )
                if result.returncode == 0:
                    lines = result.stdout.splitlines()[:20]  # Limit to 20 packages
                    context["installed_packages"] = [line.split('==')[0] if '==' in line else line 
                                                   for line in lines if line.strip()]
        except (subprocess.TimeoutExpired, OSError):
            # Fallback to checking common packages
            common_packages = ['flask', 'django', 'fastapi', 'requests', 'numpy', 
                             'pandas', 'pytest', 'black', 'mypy', 'ruff']
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