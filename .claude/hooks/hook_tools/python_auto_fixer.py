#!/usr/bin/env python3
"""
Optimized Python Auto-Fixer - Modular Architecture
Single-pass processing with strategy pattern for maintainable code fixing

Features:
- Custom fixers for common Python syntax issues
- Ruff integration for fast linting and auto-fixing (optional)
- Black integration for consistent code formatting (optional)
- docformatter integration for automatic docstring formatting (optional)
- flynt integration for automatic f-string conversion (optional)
- Project configuration auto-detection (.ruff.toml, pyproject.toml)
- Graceful fallback to autopep8 if modern tools not available
- Performance-focused with proper error handling and logging
- Optimal tool execution order for best results
"""

import os
import re
import sys
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import List, Tuple, Dict, Set, Any
from dataclasses import dataclass
from enum import Enum

# Optional imports with graceful fallback
try:
    import parso  # type: ignore
    HAS_PARSO = True
except ImportError:
    HAS_PARSO = False
    parso = None

try:
    import autopep8  # type: ignore
    HAS_AUTOPEP8 = True
except ImportError:
    HAS_AUTOPEP8 = False
    autopep8 = None

try:
    import subprocess
    HAS_SUBPROCESS = True
except ImportError:
    HAS_SUBPROCESS = False
    subprocess = None  # type: ignore


class FixResult(Enum):
    UNCHANGED = "unchanged"
    FIXED = "fixed"
    ERROR = "error"


@dataclass
class FixReport:
    result: FixResult
    changes_made: List[str]
    errors: List[str]
    lines_processed: int


class BaseFixer(ABC):
    """Base class for all Python fixers using strategy pattern"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Override to compile regex patterns once"""
        pass
    
    @abstractmethod
    def can_fix_line(self, line: str, line_num: int, context: Dict) -> bool:
        """Check if this fixer can handle the given line"""
        pass
    
    @abstractmethod
    def fix_line(self, line: str, line_num: int, context: Dict) -> Tuple[str, bool]:
        """Fix the line, return (fixed_line, was_changed)"""
        pass
    
    def get_dependencies(self) -> Set[str]:
        """Return set of import statements this fixer might need"""
        return set()


class ColonFixer(BaseFixer):
    """Fix missing colons in control structures"""
    
    def _compile_patterns(self):
        self.keywords = {
            'def ', 'class ', 'if ', 'elif ', 'else', 'for ', 'while ',
            'try:', 'try ', 'except', 'finally', 'with ', 'match ', 'case ',
            'async def ', 'async for ', 'async with '
        }
    
    def can_fix_line(self, line: str, line_num: int, context: Dict) -> bool:
        stripped = line.strip()
        return (any(stripped.startswith(kw) for kw in self.keywords) and 
                not stripped.endswith(':') and ':' not in stripped)
    
    def fix_line(self, line: str, line_num: int, context: Dict) -> Tuple[str, bool]:
        if '#' in line:
            pos = line.find('#')
            return line[:pos].rstrip() + ':  ' + line[pos:], True
        return line.rstrip() + ':\n', True


class PrintFixer(BaseFixer):
    """Fix Python 2 style print statements"""
    
    def _compile_patterns(self):
        self.print_pattern = re.compile(r'^(\s*)print\s+(.+)$')
    
    def can_fix_line(self, line: str, line_num: int, context: Dict) -> bool:
        return ('print ' in line and 
                not line.strip().startswith('#') and
                bool(self.print_pattern.match(line.rstrip())))
    
    def fix_line(self, line: str, line_num: int, context: Dict) -> Tuple[str, bool]:
        match = self.print_pattern.match(line.rstrip())
        if match:
            indent, args = match.groups()
            return f"{indent}print({args})\n", True
        return line, False


class StringFixer(BaseFixer):
    """Fix unclosed strings"""
    
    def can_fix_line(self, line: str, line_num: int, context: Dict) -> bool:
        return (line.count('"') % 2 != 0 and 
                not line.rstrip().endswith('"') and
                not line.strip().startswith('#'))
    
    def fix_line(self, line: str, line_num: int, context: Dict) -> Tuple[str, bool]:
        return line.rstrip() + '"\n', True


class ParenthesesFixer(BaseFixer):
    """Fix unmatched parentheses"""
    
    def can_fix_line(self, line: str, line_num: int, context: Dict) -> bool:
        return (line.count('(') > line.count(')') and 
                not line.strip().endswith((',', '\\')))
    
    def fix_line(self, line: str, line_num: int, context: Dict) -> Tuple[str, bool]:
        diff = line.count('(') - line.count(')')
        return line.rstrip() + ')' * diff + '\n', True


class BooleanFixer(BaseFixer):
    """Fix JavaScript-style booleans and null values"""
    
    def _compile_patterns(self):
        self.replacements = {
            re.compile(r'\btrue\b'): 'True',
            re.compile(r'\bfalse\b'): 'False',
            re.compile(r'\bnull\b'): 'None',
            re.compile(r'\bundefined\b'): 'None',
        }
    
    def can_fix_line(self, line: str, line_num: int, context: Dict) -> bool:
        if line.strip().startswith('#'):
            return False
        return any(pattern.search(line) for pattern in self.replacements)
    
    def fix_line(self, line: str, line_num: int, context: Dict) -> Tuple[str, bool]:
        original = line
        for pattern, replacement in self.replacements.items():
            line = pattern.sub(replacement, line)
        return line, line != original


class ImportFixer(BaseFixer):
    """Add missing imports based on usage patterns"""
    
    def _compile_patterns(self):
        self.patterns = {
            re.compile(r'\bos\.'): 'import os',
            re.compile(r'\bsys\.'): 'import sys',
            re.compile(r'\bjson\.'): 'import json',
            re.compile(r'\btime\.'): 'import time',
            re.compile(r'\bPath\('): 'from pathlib import Path',
        }
        self.typing_pattern = re.compile(r'\b(List|Dict|Optional|Union)\[')
    
    def can_fix_line(self, line: str, line_num: int, context: Dict) -> bool:
        return (any(bool(pattern.search(line)) for pattern in self.patterns) or
                bool(self.typing_pattern.search(line)))
    
    def fix_line(self, line: str, line_num: int, context: Dict) -> Tuple[str, bool]:
        # This fixer works at file level, not line level
        return line, False
    
    def get_dependencies(self) -> Set[str]:
        return {'from typing import List, Dict, Optional, Union, Any'}


class IndentationFixer(BaseFixer):
    """Fix mixed tabs/spaces indentation"""
    
    def can_fix_line(self, line: str, line_num: int, context: Dict) -> bool:
        if not line.strip():
            return False
        indent = line[:len(line) - len(line.lstrip())]
        return '\t' in indent and ' ' in indent
    
    def fix_line(self, line: str, line_num: int, context: Dict) -> Tuple[str, bool]:
        indent = line[:len(line) - len(line.lstrip())]
        content = line[len(indent):]
        
        # Use project preference from context
        use_spaces = context.get('use_spaces', True)
        if use_spaces:
            fixed_indent = indent.expandtabs(4)
        else:
            fixed_indent = re.sub(r'    ', '\t', indent)
            fixed_indent = fixed_indent.replace(' ', '')
        
        return fixed_indent + content, True


class ExceptionFixer(BaseFixer):
    """Fix Python 2 style exception syntax"""
    
    def _compile_patterns(self):
        self.except_pattern = re.compile(r'except\s+(\w+),\s*(\w+):')
        self.raise_pattern = re.compile(r'raise\s+(\w+),\s*(["\'].*?["\'])')
    
    def can_fix_line(self, line: str, line_num: int, context: Dict) -> bool:
        return (bool(self.except_pattern.search(line)) or 
                bool(self.raise_pattern.search(line)))
    
    def fix_line(self, line: str, line_num: int, context: Dict) -> Tuple[str, bool]:
        original = line
        line = self.except_pattern.sub(r'except \1 as \2:', line)
        line = self.raise_pattern.sub(r'raise \1(\2)', line)
        return line, line != original


class PassFixer(BaseFixer):
    """Add pass to empty blocks"""
    
    def can_fix_line(self, line: str, line_num: int, context: Dict) -> bool:
        return line.strip().endswith(':')
    
    def fix_line(self, line: str, line_num: int, context: Dict) -> Tuple[str, bool]:
        # This needs file-level context to check next line
        # Will be handled by the processor
        return line, False


class OptimizedPythonFixer:
    """Main fixer class using strategy pattern with single-pass processing"""
    
    def __init__(self, log_file: str = "/tmp/python_fixer.log"):
        self.log_file = log_file
        self.fixers = self._initialize_fixers()
        self.stats = {'files_processed': 0, 'total_fixes': 0}
        self._check_external_tools()
    
    def _initialize_fixers(self) -> List[BaseFixer]:
        """Initialize all fixer strategies"""
        return [
            ColonFixer(),
            PrintFixer(),
            StringFixer(),
            ParenthesesFixer(),
            BooleanFixer(),
            ImportFixer(),
            IndentationFixer(),
            ExceptionFixer(),
            PassFixer(),
        ]
    
    def _log(self, message: str, level: str = "INFO"):
        """Safe logging with error handling"""
        try:
            timestamp = time.strftime("%H:%M:%S")
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {level}: {message}\n")
        except Exception as e:
            # Fallback to stderr if file logging fails
            print(f"Log error: {e}", file=sys.stderr)
    
    @contextmanager
    def _atomic_write(self, filepath: str):
        """Atomic file operations with proper error handling"""
        backup = f"{filepath}.bak"
        try:
            # Create backup
            if os.path.exists(filepath):
                with open(filepath, 'rb') as src, open(backup, 'wb') as dst:
                    dst.write(src.read())
            yield
        except Exception as e:
            # Restore on error
            if os.path.exists(backup):
                try:
                    os.replace(backup, filepath)
                    self._log(f"Restored backup for {filepath}")
                except Exception as restore_error:
                    self._log(f"Failed to restore backup: {restore_error}", "ERROR")
            raise e
        finally:
            # Cleanup backup
            if os.path.exists(backup):
                try:
                    os.remove(backup)
                except Exception:
                    pass  # Non-critical
    
    def _has_syntax_error(self, content: str) -> Tuple[bool, str]:
        """Check syntax with detailed error reporting"""
        if HAS_PARSO and parso:
            try:
                module = parso.parse(content)
                errors = list(module.get_error_node_list())
                if errors:
                    error_msgs = [f"Line {err.start_pos[0]}: {err.get_message()}" 
                                 for err in errors[:3]]
                    return True, "; ".join(error_msgs)
                return False, ""
            except Exception as e:
                self._log(f"Parso parsing failed: {e}", "WARNING")
        
        # Fallback to compile
        try:
            compile(content, '<string>', 'exec')
            return False, ""
        except SyntaxError as e:
            return True, f"Line {e.lineno}: {e.msg}" if e.lineno else str(e)
    
    def _detect_project_style(self, lines: List[str]) -> Dict[str, Any]:
        """Detect project coding style preferences"""
        space_lines = sum(1 for line in lines if line.startswith('    '))
        tab_lines = sum(1 for line in lines if line.startswith('\t'))
        
        return {
            'use_spaces': space_lines >= tab_lines,
            'indent_size': 4,
            'total_lines': len(lines)
        }
    
    def _process_single_pass(self, lines: List[str]) -> Tuple[List[str], FixReport]:
        """Single-pass processing through all lines"""
        context = self._detect_project_style(lines)
        changes_made = []
        errors = []
        
        # Process each line once with all applicable fixers
        for i, line in enumerate(lines):
            original_line = line
            
            for fixer in self.fixers:
                try:
                    if fixer.can_fix_line(line, i, context):
                        fixed_line, changed = fixer.fix_line(line, i, context)
                        if changed:
                            line = fixed_line
                            changes_made.append(f"{fixer.name} at line {i+1}")
                            self._log(f"{fixer.name}: {original_line.strip()} -> {line.strip()}")
                except Exception as e:
                    error_msg = f"{fixer.name} failed at line {i+1}: {e}"
                    errors.append(error_msg)
                    self._log(error_msg, "ERROR")
            
            lines[i] = line
        
        # Handle special cases that need file-level context
        lines = self._handle_file_level_fixes(lines, context, changes_made)
        
        result = FixResult.FIXED if changes_made else FixResult.UNCHANGED
        if errors:
            result = FixResult.ERROR
        
        return lines, FixReport(result, changes_made, errors, len(lines))
    
    def _handle_file_level_fixes(self, lines: List[str], context: Dict, changes_made: List[str]) -> List[str]:
        """Handle fixes that require file-level context"""
        # Add missing pass statements
        i = 0
        while i < len(lines):
            if lines[i].strip().endswith(':'):
                indent_level = len(lines[i]) - len(lines[i].lstrip())
                
                # Check if next line needs pass
                if (i + 1 >= len(lines) or 
                    not lines[i + 1].strip() or
                    len(lines[i + 1]) - len(lines[i + 1].lstrip()) <= indent_level):
                    
                    pass_line = ' ' * (indent_level + 4) + 'pass\n'
                    if i + 1 < len(lines):
                        lines.insert(i + 1, pass_line)
                    else:
                        lines.append(pass_line)
                    changes_made.append(f"PassFixer at line {i+2}")
                    i += 1  # Skip inserted line
            i += 1
        
        # Add missing imports
        self._add_missing_imports(lines, changes_made)
        
        return lines
    
    def _add_missing_imports(self, lines: List[str], changes_made: List[str]):
        """Add missing imports based on usage patterns"""
        content = ''.join(lines)
        imports_needed = []
        
        # Collect all dependencies from fixers
        for fixer in self.fixers:
            imports_needed.extend(fixer.get_dependencies())
        
        # Check for typing imports
        if any(word in content for word in ['List[', 'Dict[', 'Optional[', 'Union[']):
            if 'from typing import' not in content:
                imports_needed.append('from typing import List, Dict, Optional, Union, Any')
        
        # Add imports if needed
        if imports_needed:
            insert_idx = self._find_import_insertion_point(lines)
            for imp in sorted(set(imports_needed)):
                if imp.strip() not in content:
                    lines.insert(insert_idx, imp + '\n')
                    changes_made.append(f"ImportFixer: {imp}")
                    insert_idx += 1
    
    def _find_import_insertion_point(self, lines: List[str]) -> int:
        """Find the best place to insert imports"""
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(('import ', 'from ')):
                continue
            elif stripped and not stripped.startswith('#'):
                return i
        return 0
    
    def _check_external_tools(self):
        """Check availability of external tools"""
        self.has_ruff = False
        self.has_black = False
        self.has_docformatter = False
        self.has_flynt = False
        self._detect_config_files()
        
        if HAS_SUBPROCESS and subprocess is not None:
            try:
                # Check for Ruff
                result = subprocess.run(['ruff', '--version'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.has_ruff = True
                    self._log(f"Ruff available: {result.stdout.strip()}")
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
                self._log(f"Ruff not available: {e}", "DEBUG")
            
            try:
                # Check for Black
                result = subprocess.run(['black', '--version'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.has_black = True
                    self._log(f"Black available: {result.stdout.strip()}")
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
                self._log(f"Black not available: {e}", "DEBUG")
            
            try:
                # Check for docformatter
                result = subprocess.run(['docformatter', '--version'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.has_docformatter = True
                    self._log(f"docformatter available: {result.stdout.strip()}")
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
                self._log(f"docformatter not available: {e}", "DEBUG")
            
            try:
                # Check for flynt
                result = subprocess.run(['flynt', '--version'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.has_flynt = True
                    self._log(f"flynt available: {result.stdout.strip()}")
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
                self._log(f"flynt not available: {e}", "DEBUG")
    
    def _detect_config_files(self):
        """Detect project configuration files"""
        self.project_configs: Dict[str, Any] = {
            'ruff_config': None,
            'black_config': None,
            'pyproject_toml': None
        }
        
        # Start from current directory and walk up
        current_dir = os.getcwd()
        while current_dir != os.path.dirname(current_dir):  # Stop at root
            # Check for ruff.toml
            ruff_toml = os.path.join(current_dir, 'ruff.toml')
            if os.path.exists(ruff_toml):
                self.project_configs['ruff_config'] = ruff_toml
            
            # Check for pyproject.toml
            pyproject = os.path.join(current_dir, 'pyproject.toml')
            if os.path.exists(pyproject):
                self.project_configs['pyproject_toml'] = pyproject
                # Check if it contains ruff or black config
                try:
                    with open(pyproject, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if '[tool.ruff' in content:
                            self.project_configs['ruff_config'] = pyproject
                        if '[tool.black' in content:
                            self.project_configs['black_config'] = pyproject
                except Exception:
                    pass
            
            current_dir = os.path.dirname(current_dir)
        
        configs_found = [k for k, v in self.project_configs.items() if v]
        if configs_found:
            self._log(f"Project configs found: {configs_found}")
    
    def _run_ruff(self, filepath: str) -> Tuple[bool, List[str]]:
        """Run Ruff linter and auto-fixer with detailed results"""
        if not self.has_ruff or not HAS_SUBPROCESS or subprocess is None:
            return False, []
        
        changes_made = []
        try:
            # Store original content to detect changes
            with open(filepath, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # Run Ruff check with fix and import sorting
            cmd = ['ruff', 'check', '--fix', '--unsafe-fixes']
            
            # Add config file if found
            if self.project_configs['ruff_config']:
                cmd.extend(['--config', self.project_configs['ruff_config']])
            
            cmd.append(filepath)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Check if content changed
            with open(filepath, 'r', encoding='utf-8') as f:
                new_content = f.read()
            
            if new_content != original_content:
                changes_made.append("ruff-fix")
                self._log(f"Ruff fixed issues in {filepath}")
            
            # Run Ruff format (equivalent to isort + other formatting)
            format_cmd = ['ruff', 'format', '-q']
            if self.project_configs['ruff_config']:
                format_cmd.extend(['--config', self.project_configs['ruff_config']])
            format_cmd.append(filepath)
            
            format_result = subprocess.run(format_cmd, capture_output=True, text=True, timeout=30)
            
            # Check if formatting changed anything
            with open(filepath, 'r', encoding='utf-8') as f:
                formatted_content = f.read()
            
            if formatted_content != new_content:
                changes_made.append("ruff-format")
                self._log(f"Ruff formatted {filepath}")
            
            # Log any output from ruff check
            if result.stdout.strip():
                self._log(f"Ruff check output: {result.stdout.strip()}")
            if result.stderr.strip():
                self._log(f"Ruff check stderr: {result.stderr.strip()}")
            
            # Ruff returns 0 if no issues or all fixed, 1 if unfixable issues remain
            success = result.returncode in [0, 1] and format_result.returncode == 0
            return success, changes_made
                
        except subprocess.TimeoutExpired:
            self._log("Ruff timed out", "WARNING")
            return False, []
        except Exception as e:
            self._log(f"Ruff execution failed: {e}", "WARNING")
            return False, []
    
    def _run_black(self, filepath: str) -> Tuple[bool, List[str]]:
        """Run Black code formatter with detailed results"""
        if not self.has_black or not HAS_SUBPROCESS or subprocess is None:
            return False, []
        
        changes_made = []
        try:
            # Store original content to detect changes
            with open(filepath, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # Build Black command
            cmd = ['black', '--quiet', '--diff', '--color']
            
            # Add config if available, otherwise use sensible defaults
            if self.project_configs['black_config'] or self.project_configs['pyproject_toml']:
                # Black will automatically find pyproject.toml
                pass
            else:
                # Use sensible defaults if no config found
                cmd.extend(['--line-length', '100'])
            
            cmd.append(filepath)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Check if content changed
            with open(filepath, 'r', encoding='utf-8') as f:
                new_content = f.read()
            
            if new_content != original_content:
                changes_made.append("black-format")
                self._log(f"Black formatted {filepath}")
                
                # Log the diff if available
                if result.stdout.strip():
                    self._log(f"Black diff:\n{result.stdout}")
            
            if result.returncode == 0:
                return True, changes_made
            else:
                self._log(f"Black failed with code {result.returncode}: {result.stderr}", "WARNING")
                return False, []
                
        except subprocess.TimeoutExpired:
            self._log("Black timed out", "WARNING")
            return False, []
        except Exception as e:
            self._log(f"Black execution failed: {e}", "WARNING")
            return False, []
    
    def _run_docformatter(self, filepath: str) -> Tuple[bool, List[str]]:
        """Run docformatter for automatic docstring formatting"""
        if not self.has_docformatter or not HAS_SUBPROCESS or subprocess is None:
            return False, []
        
        changes_made = []
        try:
            # Store original content to detect changes
            with open(filepath, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # Build docformatter command with sensible defaults
            cmd = [
                'docformatter',
                '--in-place',  # Modify files in place
                '--wrap-summaries=88',  # Match Black's default line length
                '--wrap-descriptions=88',
                '--make-summary-multi-line',  # Improve readability
                '--close-quotes-on-newline',  # Better formatting
                '--pre-summary-newline',  # Add newline before summary
                filepath
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Check if content changed
            with open(filepath, 'r', encoding='utf-8') as f:
                new_content = f.read()
            
            if new_content != original_content:
                changes_made.append("docformatter")
                self._log(f"docformatter formatted docstrings in {filepath}")
            
            if result.returncode == 0:
                return True, changes_made
            else:
                self._log(f"docformatter failed with code {result.returncode}: {result.stderr}", "WARNING")
                return False, []
                
        except subprocess.TimeoutExpired:
            self._log("docformatter timed out", "WARNING")
            return False, []
        except Exception as e:
            self._log(f"docformatter execution failed: {e}", "WARNING")
            return False, []
    
    def _run_flynt(self, filepath: str) -> Tuple[bool, List[str]]:
        """Run flynt for automatic f-string conversion"""
        if not self.has_flynt or not HAS_SUBPROCESS or subprocess is None:
            return False, []
        
        changes_made = []
        try:
            # Store original content to detect changes
            with open(filepath, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # Build flynt command
            cmd = [
                'flynt',
                '--line-length=88',  # Match Black's default
                '--transform-concats',  # Also convert string concatenations
                '--fail-on-change',  # Return exit code 1 if changes made
                filepath
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Check if content changed
            with open(filepath, 'r', encoding='utf-8') as f:
                new_content = f.read()
            
            if new_content != original_content:
                changes_made.append("flynt")
                self._log(f"flynt converted strings to f-strings in {filepath}")
                
                # Log flynt output if available
                if result.stdout.strip():
                    self._log(f"flynt output: {result.stdout.strip()}")
            
            # flynt returns 1 when changes are made (due to --fail-on-change), 0 when no changes
            if result.returncode in [0, 1]:
                return True, changes_made
            else:
                self._log(f"flynt failed with code {result.returncode}: {result.stderr}", "WARNING")
                return False, []
                
        except subprocess.TimeoutExpired:
            self._log("flynt timed out", "WARNING")
            return False, []
        except Exception as e:
            self._log(f"flynt execution failed: {e}", "WARNING")
            return False, []
    
    def _run_external_formatters(self, filepath: str) -> List[str]:
        """Run external formatters with proper error handling in optimal order"""
        all_results = []
        
        # Order of operations:
        # 1. Ruff (linting/fixing)
        # 2. Ruff format OR Black (code formatting)
        # 3. docformatter (docstring formatting)
        # 4. flynt (f-string conversion)
        # 5. autopep8 (fallback)
        
        # 1. Run Ruff first (fast linting, auto-fixing, and formatting)
        ruff_success, ruff_changes = self._run_ruff(filepath)
        if ruff_success and ruff_changes:
            all_results.extend(ruff_changes)
            self._log(f"Ruff applied: {', '.join(ruff_changes)}")
        
        # 2. Only run Black if Ruff formatting wasn't applied
        if not any('ruff-format' in change for change in ruff_changes):
            black_success, black_changes = self._run_black(filepath)
            if black_success and black_changes:
                all_results.extend(black_changes)
                self._log(f"Black applied: {', '.join(black_changes)}")
        else:
            self._log("Skipped Black (Ruff format was used)")
        
        # 3. Run docformatter for docstring formatting (after code formatting)
        docformatter_success, docformatter_changes = self._run_docformatter(filepath)
        if docformatter_success and docformatter_changes:
            all_results.extend(docformatter_changes)
            self._log(f"docformatter applied: {', '.join(docformatter_changes)}")
        
        # 4. Run flynt for f-string conversion (after docstring formatting)
        flynt_success, flynt_changes = self._run_flynt(filepath)
        if flynt_success and flynt_changes:
            all_results.extend(flynt_changes)
            self._log(f"flynt applied: {', '.join(flynt_changes)}")
        
        # 5. Run autopep8 as fallback if no modern tools are available
        if not self.has_ruff and not self.has_black and HAS_AUTOPEP8 and autopep8:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    original_content = f.read()
                
                fixed = autopep8.fix_code(original_content, options={
                    'aggressive': 1,
                    'max_line_length': 100,
                    'ignore': ['E501']
                })
                
                if fixed != original_content:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(fixed)
                    all_results.append("autopep8-fallback")
                    self._log(f"autopep8 formatted {filepath} (fallback)")
            except Exception as e:
                self._log(f"autopep8 fallback failed: {e}", "ERROR")
        
        return all_results
    
    def fix_file(self, filepath: str) -> FixReport:
        """Main file fixing method with comprehensive error handling"""
        try:
            self.stats['files_processed'] += 1
            
            with self._atomic_write(filepath):
                # Read file
                with open(filepath, 'r', encoding='utf-8') as f:
                    original_content = f.read()
                
                # Quick health check
                has_error, error_msg = self._has_syntax_error(original_content)
                if has_error:
                    self._log(f"Syntax error in {filepath}: {error_msg}")
                
                # Process with single-pass algorithm
                lines = original_content.splitlines(keepends=True)
                fixed_lines, report = self._process_single_pass(lines)
                
                # Write if changed
                if report.result == FixResult.FIXED:
                    fixed_content = ''.join(fixed_lines)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(fixed_content)
                    
                    self.stats['total_fixes'] += len(report.changes_made)
                    self._log(f"Fixed {filepath}: {len(report.changes_made)} changes")
                
                # Run external formatters (Ruff, Black, autopep8)
                formatter_results = self._run_external_formatters(filepath)
                if formatter_results:
                    report.changes_made.extend(f"External tool: {fmt}" for fmt in formatter_results)
                    self._log(f"External formatters applied: {', '.join(formatter_results)}")
                
                return report
                
        except Exception as e:
            error_msg = f"Failed to fix {filepath}: {e}"
            self._log(error_msg, "ERROR")
            return FixReport(FixResult.ERROR, [], [error_msg], 0)


def should_process_file(tool_name: str, tool_input: dict, file_path: str) -> bool:
    """Determine if file should be processed with proper validation"""
    if not file_path.endswith('.py'):
        return False
    
    # Check tool name
    valid_tools = {'Write', 'Edit', 'MultiEdit', 'write_to_file', 'apply_diff', 'write_file', 'edit_file'}
    if tool_name not in valid_tools:
        return False
    
    # Skip test files, hooks, and certain patterns
    skip_patterns = ['test', '__pycache__', '.pyc', 'python_auto_fixer', 'hook']
    if any(pattern in file_path.lower() for pattern in skip_patterns):
        return False
    
    # Additional safety: don't process if content indicates it's a test or special file
    if 'content' in tool_input:
        content = str(tool_input['content']).lower()
        if any(pattern in content[:200] for pattern in ['pytest', 'unittest', 'test_']):
            return False
    
    return True


def run_auto_fixer(tool_name: str, tool_input: dict, cwd: str) -> None:
    """Hook entry point with proper error handling (no subprocess)"""
    fixer = OptimizedPythonFixer()
    file_paths = []
    
    # Extract file paths with validation
    for key in ['path', 'file_path']:
        if key in tool_input and isinstance(tool_input[key], str):
            file_paths.append(tool_input[key])
    
    if 'edits' in tool_input:
        for edit in tool_input['edits']:
            if isinstance(edit, dict) and 'path' in edit:
                file_paths.append(edit['path'])
    
    # Process files directly (no dangerous subprocess)
    for file_path in file_paths:
        try:
            if not os.path.isabs(file_path):
                file_path = os.path.join(cwd, file_path)
            
            if should_process_file(tool_name, tool_input, file_path) and os.path.exists(file_path):
                report = fixer.fix_file(file_path)
                if report.result == FixResult.ERROR:
                    fixer._log(f"Errors in {file_path}: {report.errors}", "ERROR")
                    
        except Exception as e:
            fixer._log(f"Failed to process {file_path}: {e}", "ERROR")
    
    # Log final stats
    fixer._log(f"Session complete: {fixer.stats['files_processed']} files, {fixer.stats['total_fixes']} total fixes")


if __name__ == "__main__":
    # Direct execution for testing
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        if os.path.exists(filepath):
            fixer = OptimizedPythonFixer()
            report = fixer.fix_file(filepath)
            print(f"Result: {report.result.value}")
            print(f"Changes: {len(report.changes_made)}")
            if report.errors:
                print(f"Errors: {report.errors}")