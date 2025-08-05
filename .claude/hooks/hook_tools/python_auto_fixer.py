#!/usr/bin/env python3
"""
Optimized Python Auto-Fixer - Modular Architecture
Single-pass processing with strategy pattern for maintainable code fixing
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
    
    def _run_external_formatters(self, filepath: str) -> List[str]:
        """Run external formatters with proper error handling"""
        results = []
        
        # Run autopep8 if available
        if HAS_AUTOPEP8 and autopep8:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    original = f.read()
                
                fixed = autopep8.fix_code(original, options={
                    'aggressive': 1,
                    'max_line_length': 100,
                    'ignore': ['E501']
                })
                
                if fixed != original:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(fixed)
                    results.append("autopep8")
            except Exception as e:
                self._log(f"autopep8 failed: {e}", "ERROR")
        
        return results
    
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
                
                # Run external formatters
                formatter_results = self._run_external_formatters(filepath)
                if formatter_results:
                    report.changes_made.extend(f"Formatter: {fmt}" for fmt in formatter_results)
                
                return report
                
        except Exception as e:
            error_msg = f"Failed to fix {filepath}: {e}"
            self._log(error_msg, "ERROR")
            return FixReport(FixResult.ERROR, [], [error_msg], 0)


def should_process_file(tool_name: str, _tool_input: dict, file_path: str) -> bool:
    """Determine if file should be processed with proper validation"""
    if not file_path.endswith('.py'):
        return False
    
    if tool_name not in ['Write', 'Edit', 'MultiEdit', 'write_to_file', 'apply_diff']:
        return False
    
    # Skip test files and hooks
    skip_patterns = ['test', '__pycache__', '.pyc', 'python_auto_fixer', 'hook']
    return not any(pattern in file_path.lower() for pattern in skip_patterns)


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