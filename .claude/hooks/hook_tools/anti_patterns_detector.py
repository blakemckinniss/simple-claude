#!/usr/bin/env python3
"""
Anti-patterns and Technical Debt Detection Module
Provides comprehensive detection of code anti-patterns for file creation blocking.
"""

import re
import os
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Severity levels for detected anti-patterns."""
    CRITICAL = "critical"  # Block file creation
    HIGH = "high"         # Strongly discourage
    MEDIUM = "medium"     # Warn and suggest alternatives
    LOW = "low"          # Information only


@dataclass
class AntiPattern:
    """Represents a detected anti-pattern."""
    category: str
    pattern_name: str
    severity: Severity
    description: str
    file_path: str
    line_number: Optional[int] = None
    suggestion: Optional[str] = None
    regex_pattern: Optional[str] = None


class AntiPatternDetector:
    """Comprehensive anti-pattern detection for file creation blocking."""
    
    def __init__(self):
        """Initialize detector with pattern definitions."""
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize all anti-pattern definitions."""
        return {
            "file_structure": self._get_file_structure_patterns(),
            "security": self._get_security_patterns(),
            "architecture": self._get_architecture_patterns(),
            "code_quality": self._get_code_quality_patterns()
        }
    
    def _get_file_structure_patterns(self) -> List[Dict[str, Any]]:
        """File and directory structure anti-patterns."""
        return [
            {
                "name": "deep_nesting",
                "detect": lambda path: len(Path(path).parts) > 6,
                "severity": Severity.HIGH,
                "description": "Directory nesting exceeds 4 levels",
                "suggestion": "Flatten directory structure or use domain-based organization"
            },
            {
                "name": "god_file",
                "detect": lambda path, content: len(content.splitlines()) > 500,
                "severity": Severity.HIGH,
                "description": "File exceeds 500 lines (God object anti-pattern)",
                "suggestion": "Split into smaller, focused modules"
            },
            {
                "name": "duplicate_functionality",
                "regex": r"(utils?|helpers?|common|shared|misc|stuff|temp|old|backup|copy\d*)\.(py|js|ts)$",
                "severity": Severity.MEDIUM,
                "description": "Filename suggests duplicate or unfocused functionality",
                "suggestion": "Use existing utilities or create domain-specific modules"
            },
            {
                "name": "non_standard_location",
                "patterns": [
                    (r"src/.*/tests/.*\.py$", "Tests should be in dedicated test directory"),
                    (r"tests/.*/src/.*\.py$", "Source code should not be in test directory"),
                    (r".*/config/.*\.(py|js)$", "Configuration mixed with source code"),
                    (r".*/models/.*controller\.(py|js)$", "Controller in models directory"),
                    (r".*/views/.*model\.(py|js)$", "Model in views directory")
                ],
                "severity": Severity.HIGH,
                "description": "File in non-standard location violating separation of concerns"
            },
            {
                "name": "circular_dependency_risk",
                "regex": r"from\s+\.\.\.\.\s+import|import\s+\.\.\.\.",
                "severity": Severity.CRITICAL,
                "description": "Complex relative imports suggesting circular dependencies",
                "suggestion": "Use absolute imports and dependency injection"
            },
            {
                "name": "abandoned_patterns",
                "regex": r"(deprecated|obsolete|do_not_use|legacy|old_|_old|_bak|\.bak$|~$|\.swp$)",
                "severity": Severity.HIGH,
                "description": "File appears to be deprecated or abandoned",
                "suggestion": "Remove deprecated code or document migration path"
            }
        ]
    
    def _get_security_patterns(self) -> List[Dict[str, Any]]:
        """Security-related anti-patterns."""
        return [
            {
                "name": "hardcoded_credentials",
                "regex": r"""(?i)(
                    (api[_\-]?key|apikey)\s*[:=]\s*['"]\w{20,}['"]|
                    (secret[_\-]?key|secretkey)\s*[:=]\s*['"]\w{20,}['"]|
                    (password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]|
                    (token|auth[_\-]?token)\s*[:=]\s*['"]\w{20,}['"]|
                    aws[_\-]?access[_\-]?key[_\-]?id\s*[:=]\s*['"]AK[A-Z0-9]{16,}['"]|
                    (private[_\-]?key|priv[_\-]?key)\s*[:=]\s*['"]-----BEGIN
                )""",
                "severity": Severity.CRITICAL,
                "description": "Hardcoded credentials detected",
                "suggestion": "Use environment variables or secure credential storage"
            },
            {
                "name": "debug_code",
                "regex": r"""(?i)(
                    console\.(log|debug|info)|
                    print\s*\([^)]*password[^)]*\)|
                    debug\s*=\s*True|
                    DEBUG\s*=\s*1|
                    \#\s*TODO:\s*remove\s*(this|before\s*production)|
                    \#\s*FIXME:\s*security|
                    \#\s*HACK:|
                    debugger;?|
                    pdb\.set_trace\(\)|
                    import\s+pdb
                )""",
                "severity": Severity.HIGH,
                "description": "Debug code or sensitive logging detected",
                "suggestion": "Remove debug statements and use proper logging levels"
            },
            {
                "name": "sensitive_data_exposure",
                "regex": r"""(?i)(
                    (ssn|social[_\-]?security)\s*[:=]|
                    (credit[_\-]?card|cc[_\-]?number)\s*[:=]|
                    (bank[_\-]?account)\s*[:=]|
                    (routing[_\-]?number)\s*[:=]|
                    email\s*[:=]\s*['"][^@]+@[^'"]+['"]|
                    phone\s*[:=]\s*['"][\d\-\(\)\+\s]{10,}['"]
                )""",
                "severity": Severity.CRITICAL,
                "description": "Potential sensitive data exposure",
                "suggestion": "Encrypt sensitive data and use proper data masking"
            },
            {
                "name": "unsafe_permissions",
                "regex": r"""(
                    chmod\s+777|
                    chmod\s+666|
                    permissions?\s*[:=]\s*0?777|
                    permissions?\s*[:=]\s*0?666|
                    mode\s*[:=]\s*['"]?0?777['"]?
                )""",
                "severity": Severity.CRITICAL,
                "description": "Unsafe file permissions detected",
                "suggestion": "Use restrictive permissions (e.g., 644 for files, 755 for directories)"
            },
            {
                "name": "sql_injection_risk",
                "regex": r"""(
                    f["'].*SELECT.*WHERE.*{|
                    \+\s*["'].*SELECT.*WHERE|
                    %\s*\(.*SELECT.*WHERE|
                    format\(.*SELECT.*WHERE
                )""",
                "severity": Severity.CRITICAL,
                "description": "Potential SQL injection vulnerability",
                "suggestion": "Use parameterized queries or ORM"
            },
            {
                "name": "command_injection_risk",
                "regex": r"""(
                    os\.system\s*\(|
                    subprocess\.(call|run|Popen)\s*\([^,)]*\+|
                    eval\s*\(|
                    exec\s*\(|
                    shell\s*=\s*True
                )""",
                "severity": Severity.CRITICAL,
                "description": "Potential command injection vulnerability",
                "suggestion": "Avoid shell=True and validate/sanitize all inputs"
            }
        ]
    
    def _get_architecture_patterns(self) -> List[Dict[str, Any]]:
        """Architecture-related anti-patterns."""
        return [
            {
                "name": "business_logic_in_wrong_layer",
                "patterns": [
                    (r".*/controllers?/.*\b(calculate|compute|process|validate|transform)\w*\s*\(", 
                     "Business logic in controller layer"),
                    (r".*/views?/.*\b(save|delete|update|create|query)\w*\s*\(",
                     "Data persistence in view layer"),
                    (r".*/models?/.*\b(render|display|format_html|template)\w*\s*\(",
                     "Presentation logic in model layer")
                ],
                "severity": Severity.HIGH,
                "description": "Business logic in wrong architectural layer"
            },
            {
                "name": "database_access_violation",
                "regex": r"""(
                    \b(
                        SELECT\s+.*FROM|
                        INSERT\s+INTO|
                        UPDATE\s+.*SET|
                        DELETE\s+FROM|
                        connection\.execute|
                        cursor\.execute|
                        db\.(query|execute)|
                        session\.(query|add|delete|commit)
                    )
                )""",
                "severity": Severity.HIGH,
                "description": "Database access detected (review if in appropriate layer)",
                "suggestion": "Move database operations to repository/DAO layer if not already there"
            },
            {
                "name": "cross_module_violation",
                "patterns": [
                    (r"from\s+app\.auth.*import.*app\.payment", "Auth importing payment"),
                    (r"from\s+app\.payment.*import.*app\.auth", "Payment importing auth"),
                    (r"from\s+domain\..*import.*infrastructure", "Domain importing infrastructure"),
                    (r"from\s+presentation.*import.*domain", "Presentation importing domain directly")
                ],
                "severity": Severity.HIGH,
                "description": "Cross-module boundary violation",
                "suggestion": "Use dependency injection or events for module communication"
            },
            {
                "name": "configuration_in_code",
                "regex": r"""(
                    (host|hostname)\s*=\s*['"][\w\.\-]+['"]|
                    (port)\s*=\s*\d{2,5}(?!\d)|
                    (database|db)[_\-]?name\s*=\s*['"][\w\-]+['"]|
                    (url|uri|endpoint)\s*=\s*['"]https?://|
                    MAX_\w+\s*=\s*\d+|
                    TIMEOUT\s*=\s*\d+
                )""",
                "severity": Severity.MEDIUM,
                "description": "Configuration hardcoded in source",
                "suggestion": "Move to configuration files or environment variables"
            },
            {
                "name": "anemic_domain_model",
                "detect": lambda content: self._detect_anemic_model(content),
                "severity": Severity.MEDIUM,
                "description": "Domain model with only getters/setters (anemic model)",
                "suggestion": "Add business logic to domain models"
            }
        ]
    
    def _get_code_quality_patterns(self) -> List[Dict[str, Any]]:
        """Code quality anti-patterns."""
        return [
            {
                "name": "too_many_responsibilities",
                "detect": lambda content: self._count_class_methods(content) > 20,
                "severity": Severity.HIGH,
                "description": "Class has too many methods (>20), violating SRP",
                "suggestion": "Split into smaller, focused classes"
            },
            {
                "name": "temporary_code",
                "regex": r"""(?i)(
                    \b(temp|tmp|test|experiment|poc|prototype|draft|wip)\b|
                    \#\s*(TEMP|TMP|TEMPORARY|REMOVE|DELETE\s*ME)|
                    //\s*(TEMP|TMP|TEMPORARY|REMOVE|DELETE\s*ME)
                )""",
                "severity": Severity.HIGH,
                "description": "Temporary or experimental code detected",
                "suggestion": "Remove temporary code or move to proper location"
            },
            {
                "name": "missing_init_py",
                "detect": lambda path: self._check_missing_init(path),
                "severity": Severity.MEDIUM,
                "description": "Python package missing __init__.py",
                "suggestion": "Add __init__.py for proper package structure"
            },
            {
                "name": "inconsistent_naming",
                "patterns": [
                    (r"class\s+[a-z]", "Class name not in PascalCase"),
                    (r"def\s+[A-Z]", "Function name not in snake_case"),
                    (r"^[A-Z][a-z]+\.py$", "Python file not in snake_case"),
                    (r"const\s+[a-z_]+\s*=", "Constant not in UPPER_CASE")
                ],
                "severity": Severity.MEDIUM,
                "description": "Inconsistent naming convention"
            },
            {
                "name": "magic_numbers",
                "regex": r"""(?x)
                    (?<![\w\.])
                    (?!(?:0x[\da-fA-F]+|0b[01]+|0o[0-7]+))  # Not hex/binary/octal
                    (?!(?:[012]|10|100|1000|1024|60|24|7|365))  # Not common values
                    \b\d{2,}\b  # Numbers with 2+ digits
                    (?!\s*(?:[)\],;]|$))  # Not at end of expression
                """,
                "severity": Severity.LOW,
                "description": "Magic numbers without named constants",
                "suggestion": "Define named constants for magic numbers"
            },
            {
                "name": "commented_code",
                "regex": r"""(?x)
                    ^\s*\#\s*(if|for|while|def|class|import|from|return|yield)\s|
                    ^\s*//\s*(if|for|while|function|class|import|return|const|let|var)\s|
                    /\*[\s\S]*?(if|for|while|function|class)[\s\S]*?\*/
                """,
                "severity": Severity.MEDIUM,
                "description": "Commented-out code detected",
                "suggestion": "Remove commented code (use version control for history)"
            },
            {
                "name": "long_parameter_list",
                "regex": r"def\s+\w+\s*\([^)]{100,}\)",
                "severity": Severity.MEDIUM,
                "description": "Function has too many parameters",
                "suggestion": "Use parameter objects or builder pattern"
            }
        ]
    
    def _detect_anemic_model(self, content: str) -> bool:
        """Detect anemic domain model anti-pattern."""
        # Count getters/setters vs business methods
        getter_setter_pattern = r"(def\s+(get|set)_\w+\s*\(|@property|\.setter)"
        business_method_pattern = r"def\s+(?!(__init__|get_|set_|_))\w+\s*\("
        
        getters_setters = len(re.findall(getter_setter_pattern, content))
        business_methods = len(re.findall(business_method_pattern, content))
        
        # If >80% are getters/setters, it's likely anemic
        if getters_setters > 0:
            ratio = getters_setters / (getters_setters + business_methods + 1)
            return ratio > 0.8
        return False
    
    def _count_class_methods(self, content: str) -> int:
        """Count number of methods in a class."""
        return len(re.findall(r"def\s+\w+\s*\(", content))
    
    def _check_missing_init(self, path: str) -> bool:
        """Check if Python package is missing __init__.py."""
        if path.endswith('.py') and '/' in path:
            dir_path = os.path.dirname(path)
            init_path = os.path.join(dir_path, '__init__.py')
            return not os.path.exists(init_path)
        return False
    
    def detect_anti_patterns(self, file_path: str, content: Optional[str] = None) -> List[AntiPattern]:
        """
        Detect all anti-patterns in a file.
        
        Args:
            file_path: Path to the file being checked
            content: File content (optional, will be read if not provided)
            
        Returns:
            List of detected anti-patterns
        """
        detected = []
        
        # Read content if not provided
        if content is None:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except Exception:
                    content = ""
            else:
                content = ""
        
        # Check each category
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if self._check_pattern(pattern, file_path, content):
                    detected.append(self._create_anti_pattern(
                        category, pattern, file_path, content
                    ))
        
        return detected
    
    def _check_pattern(self, pattern: Dict[str, Any], file_path: str, content: str) -> bool:
        """Check if a pattern matches."""
        if "regex" in pattern and content:
            return bool(re.search(pattern["regex"], content, re.MULTILINE | re.VERBOSE))
        
        if "detect" in pattern:
            try:
                # Check if detect function expects content
                if pattern["detect"].__code__.co_argcount == 2:
                    return pattern["detect"](file_path, content)
                else:
                    return pattern["detect"](file_path)
            except Exception:
                return False
        
        if "patterns" in pattern and content:
            for regex, _ in pattern["patterns"]:
                if re.search(regex, content):
                    return True
        
        return False
    
    def _create_anti_pattern(self, category: str, pattern: Dict[str, Any], 
                            file_path: str, content: str) -> AntiPattern:
        """Create an AntiPattern instance."""
        # Find line number if possible
        line_number = None
        if "regex" in pattern and content:
            match = re.search(pattern["regex"], content, re.MULTILINE | re.VERBOSE)
            if match:
                line_number = content[:match.start()].count('\n') + 1
        
        return AntiPattern(
            category=category,
            pattern_name=pattern["name"],
            severity=pattern.get("severity", Severity.MEDIUM),
            description=pattern.get("description", "Anti-pattern detected"),
            file_path=file_path,
            line_number=line_number,
            suggestion=pattern.get("suggestion"),
            regex_pattern=pattern.get("regex")
        )
    
    def should_block_file_creation(self, file_path: str, content: Optional[str] = None) -> Tuple[bool, List[AntiPattern]]:
        """
        Determine if file creation should be blocked.
        
        Args:
            file_path: Path to the file being created
            content: File content
            
        Returns:
            Tuple of (should_block, list_of_critical_patterns)
        """
        patterns = self.detect_anti_patterns(file_path, content)
        critical_patterns = [p for p in patterns if p.severity == Severity.CRITICAL]
        
        return len(critical_patterns) > 0, critical_patterns
    
    def get_severity_summary(self, patterns: List[AntiPattern]) -> Dict[str, int]:
        """Get count of patterns by severity."""
        summary = {s.value: 0 for s in Severity}
        for pattern in patterns:
            summary[pattern.severity.value] += 1
        return summary
    
    def format_report(self, patterns: List[AntiPattern]) -> str:
        """Format anti-patterns into a readable report."""
        if not patterns:
            return "✅ No anti-patterns detected"
        
        report = ["🚨 Anti-patterns Detected:\n"]
        
        # Group by severity
        by_severity = {}
        for pattern in patterns:
            if pattern.severity not in by_severity:
                by_severity[pattern.severity] = []
            by_severity[pattern.severity].append(pattern)
        
        # Sort by severity (critical first)
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        
        for severity in severity_order:
            if severity in by_severity:
                report.append(f"\n{severity.value.upper()} ({len(by_severity[severity])} issues):")
                for pattern in by_severity[severity]:
                    report.append(f"  - {pattern.pattern_name}: {pattern.description}")
                    report.append(f"    File: {pattern.file_path}")
                    if pattern.line_number:
                        report.append(f"    Line: {pattern.line_number}")
                    if pattern.suggestion:
                        report.append(f"    💡 {pattern.suggestion}")
        
        return "\n".join(report)


# Usage example and testing
if __name__ == "__main__":
    detector = AntiPatternDetector()
    
    # Test with sample content
    test_content = '''
    PASSWORD = "super_secret_123"
    API_KEY = "sk-proj-abcdef123456789"
    
    class UserController:
        def calculate_tax(self, amount):  # Business logic in controller
            return amount * 0.1
    
    def process_payment():
        os.system(f"curl {user_input}")  # Command injection risk
    '''
    
    patterns = detector.detect_anti_patterns("test.py", test_content)
    print(detector.format_report(patterns))
    
    should_block, critical = detector.should_block_file_creation("test.py", test_content)
    if should_block:
        print(f"\n❌ File creation should be BLOCKED due to {len(critical)} critical issues")