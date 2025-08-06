#!/usr/bin/env python3
"""
File Blocker Configuration System for Claude Hooks Framework.

Provides a flexible, configuration-driven system for blocking file creation
based on extensions and directory patterns. Integrates with the existing
exemption system from PreToolUse.py.
"""

import os
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, NamedTuple
from dataclasses import dataclass, field
import fnmatch
import logging


class BlockingResult(NamedTuple):
    """Result of a file blocking check."""
    is_blocked: bool
    rule_name: Optional[str] = None
    reason: Optional[str] = None
    severity: str = "HIGH"


@dataclass
class BlockingRule:
    """Represents a file blocking rule."""
    name: str
    path_patterns: List[str]
    blocked_extensions: List[str]
    description: str
    severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    enabled: bool = True
    _compiled_patterns: Optional[List[str]] = field(default=None, init=False, repr=False)


class FileBlockerConfig:
    """Configuration manager for file blocking rules."""
    
    # Master block configuration - blocks ALL .claude directory operations
    MASTER_BLOCK_ENV_VAR = "CLAUDE_MASTER_BLOCK"
    MASTER_BLOCK_CONFIG_KEY = "master_block_enabled"
    CLAUDE_DIR_PATTERNS = [
        "*/.claude/*",
        "*/.claude/**/*",
        "/home/blake/simple-claude/.claude/*",
        "/home/blake/simple-claude/.claude/**/*"
    ]
    
    # Default blocking rules - can be overridden by configuration file
    DEFAULT_RULES = {
        "hook_handlers_py_protection": BlockingRule(
            name="hook_handlers_py_protection",
            path_patterns=[
                "*/hooks/hook_handlers/*",
                "*/.claude/hooks/hook_handlers/*",
                "/home/blake/simple-claude/.claude/hooks/hook_handlers/*"
            ],
            blocked_extensions=[".py", ".pyc", ".pyo"],
            description="Protect hook handler directory from Python file creation to prevent system modification",
            severity="CRITICAL"
        ),
        "sensitive_config_protection": BlockingRule(
            name="sensitive_config_protection",
            path_patterns=[
                "*/config/secrets/*",
                "*/.env*", 
                "*/credentials/*",
                "*/.claude/hooks/state/*"
            ],
            blocked_extensions=["*"],  # Block all files
            description="Protect sensitive configuration and state directories",
            severity="CRITICAL"
        ),
        "temporary_file_protection": BlockingRule(
            name="temporary_file_protection",
            path_patterns=["*"],
            blocked_extensions=[".tmp", ".temp", ".bak", ".swp", "~"],
            description="Block creation of temporary/backup files in project",
            severity="MEDIUM"
        ),
        "documentation_restriction": BlockingRule(
            name="documentation_restriction",
            path_patterns=[
                "*",  # All paths except designated doc areas
            ],
            blocked_extensions=[".md", ".rst", ".txt"],
            description="Restrict documentation files to designated areas",
            severity="HIGH",
            enabled=False  # Disabled by default - existing PreToolUse logic handles this
        )
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration.
        
        Args:
            config_file: Path to JSON configuration file. If None, uses default location.
        """
        self.project_root = os.environ.get("CLAUDE_PROJECT_DIR", "/home/blake/simple-claude")
        self.config_file = config_file or os.path.join(
            self.project_root, ".claude", "file_blocker_config.json"
        )
        self._master_block_enabled = None  # Cache for master block status
        self.rules = self._load_rules()
    
    def _load_rules(self) -> Dict[str, BlockingRule]:
        """Load rules from configuration file or use defaults."""
        rules = dict(self.DEFAULT_RULES)  # Start with defaults
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Override defaults with config file data
                for rule_name, rule_data in config_data.get("rules", {}).items():
                    rules[rule_name] = BlockingRule(
                        name=rule_data["name"],
                        path_patterns=rule_data["path_patterns"],
                        blocked_extensions=rule_data["blocked_extensions"],
                        description=rule_data["description"],
                        severity=rule_data.get("severity", "HIGH"),
                        enabled=rule_data.get("enabled", True)
                    )
                
                # Add any new rules from config
                for rule_name, rule_data in config_data.get("custom_rules", {}).items():
                    rules[rule_name] = BlockingRule(
                        name=rule_data["name"],
                        path_patterns=rule_data["path_patterns"], 
                        blocked_extensions=rule_data["blocked_extensions"],
                        description=rule_data["description"],
                        severity=rule_data.get("severity", "HIGH"),
                        enabled=rule_data.get("enabled", True)
                    )
                        
            except (json.JSONDecodeError, KeyError, IOError) as e:
                # Log warning but continue with defaults
                print(f"Warning: Failed to load file blocker config: {e}. Using defaults.", 
                      file=sys.stderr)
        
        return rules
    
    def save_config(self):
        """Save current configuration to file."""
        config_data = {
            "rules": {},
            "custom_rules": {}
        }
        
        for rule_name, rule in self.rules.items():
            rule_dict = {
                "name": rule.name,
                "path_patterns": rule.path_patterns,
                "blocked_extensions": rule.blocked_extensions,
                "description": rule.description,
                "severity": rule.severity,
                "enabled": rule.enabled
            }
            
            if rule_name in self.DEFAULT_RULES:
                config_data["rules"][rule_name] = rule_dict
            else:
                config_data["custom_rules"][rule_name] = rule_dict
        
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
    
    def add_rule(self, rule: BlockingRule):
        """Add a new blocking rule."""
        self.rules[rule.name] = rule
    
    def remove_rule(self, rule_name: str):
        """Remove a blocking rule."""
        if rule_name in self.rules:
            del self.rules[rule_name]
    
    def get_enabled_rules(self) -> Dict[str, BlockingRule]:
        """Get only enabled rules."""
        return {name: rule for name, rule in self.rules.items() if rule.enabled}
    
    def is_master_block_enabled(self) -> bool:
        """Check if master block is enabled via environment or config."""
        if self._master_block_enabled is not None:
            return self._master_block_enabled
        
        # Check environment variable first (highest priority)
        env_value = os.environ.get(self.MASTER_BLOCK_ENV_VAR, "").lower()
        if env_value in ("true", "1", "yes", "on"):
            self._master_block_enabled = True
            return True
        elif env_value in ("false", "0", "no", "off"):
            self._master_block_enabled = False
            return False
        
        # Check configuration file
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                self._master_block_enabled = config_data.get(self.MASTER_BLOCK_CONFIG_KEY, False)
                return self._master_block_enabled
            except (json.JSONDecodeError, IOError):
                pass
        
        # Default to False
        self._master_block_enabled = False
        return False
    
    def enable_master_block(self, save_to_config: bool = True):
        """Enable master block for all .claude directory operations.
        
        Args:
            save_to_config: If True, saves setting to configuration file
        """
        self._master_block_enabled = True
        if save_to_config:
            self._save_master_block_setting(True)
    
    def disable_master_block(self, save_to_config: bool = True):
        """Disable master block for .claude directory operations.
        
        Args:
            save_to_config: If True, saves setting to configuration file
        """
        self._master_block_enabled = False
        if save_to_config:
            self._save_master_block_setting(False)
    
    def _save_master_block_setting(self, enabled: bool):
        """Save master block setting to configuration file."""
        config_data = {}
        
        # Load existing config if it exists
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        
        # Update master block setting
        config_data[self.MASTER_BLOCK_CONFIG_KEY] = enabled
        
        # Save configuration
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(config_data, f, indent=2)


class FileBlocker:
    """Main file blocker engine."""
    
    def __init__(self, config: Optional[FileBlockerConfig] = None):
        """Initialize file blocker.
        
        Args:
            config: Configuration instance. If None, creates default config.
        """
        self.config = config or FileBlockerConfig()
        self.logger = self._setup_logging()
        self._compile_patterns()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for file blocker."""
        logger = logging.getLogger('file_blocker')
        logger.setLevel(logging.INFO)
        
        # Only add handler if none exists
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _compile_patterns(self):
        """Pre-compile patterns for performance."""
        for rule in self.config.rules.values():
            if rule.enabled:
                rule._compiled_patterns = [
                    self._normalize_pattern(pattern) for pattern in rule.path_patterns
                ]
    
    def _normalize_pattern(self, pattern: str) -> str:
        """Normalize path pattern for consistent matching."""
        # Convert to forward slashes for consistent matching
        pattern = pattern.replace('\\', '/')
        # Resolve absolute paths
        if pattern.startswith('/'):
            return pattern
        # Handle relative patterns
        if not pattern.startswith('*'):
            pattern = '*/' + pattern
        return pattern
    
    def _normalize_file_path(self, file_path: str) -> tuple[str, str]:
        """Normalize file path and return absolute and relative versions."""
        # Handle symlinks by resolving them
        if os.path.islink(file_path):
            file_path = os.path.realpath(file_path)
        
        # Get absolute path
        abs_path = os.path.abspath(file_path).replace('\\', '/')
        
        # Get relative path from project root
        try:
            rel_path = os.path.relpath(abs_path, self.config.project_root).replace('\\', '/')
        except ValueError:
            # Different drives on Windows
            rel_path = abs_path
        
        return abs_path, rel_path
    
    def _matches_path_patterns(self, file_path: str, compiled_patterns: List[str]) -> bool:
        """Check if file path matches any of the compiled patterns."""
        abs_path, rel_path = self._normalize_file_path(file_path)
        
        for pattern in compiled_patterns:
            # Check absolute pattern match
            if pattern.startswith('/') and fnmatch.fnmatch(abs_path, pattern):
                return True
            
            # Check relative pattern matches
            if (fnmatch.fnmatch(rel_path, pattern) or 
                fnmatch.fnmatch('/' + rel_path, pattern) or
                fnmatch.fnmatch(abs_path, pattern)):
                return True
            
            # Check if file is within the pattern directory
            if pattern.endswith('/*'):
                pattern_dir = pattern[:-2]
                if (abs_path.startswith(pattern_dir.lstrip('*')) or
                    rel_path.startswith(pattern_dir.lstrip('*/'))):
                    return True
        
        return False
    
    def _matches_extension_patterns(self, file_path: str, extension_patterns: List[str]) -> bool:
        """Check if file matches extension patterns."""
        path_obj = Path(file_path)
        filename = path_obj.name.lower()
        extension = path_obj.suffix.lower()
        
        for pattern in extension_patterns:
            pattern = pattern.lower()
            
            # Handle wildcard for all files
            if pattern == "*":
                return True
            
            # Handle filename patterns (e.g., "test_*.py")
            if '*' in pattern and not pattern.startswith('.'):
                if fnmatch.fnmatch(filename, pattern):
                    return True
            
            # Handle extension patterns (e.g., ".py", ".pyc")
            elif pattern.startswith('.'):
                if extension == pattern:
                    return True
            
            # Handle exact filename matches
            elif filename == pattern:
                return True
        
        return False
    
    def _is_claude_directory_operation(self, file_path: str) -> bool:
        """Check if file operation is within .claude directory."""
        abs_path, rel_path = self._normalize_file_path(file_path)
        
        # Check against .claude directory patterns
        for pattern in self.config.CLAUDE_DIR_PATTERNS:
            compiled_pattern = self._normalize_pattern(pattern)
            if self._matches_path_patterns(file_path, [compiled_pattern]):
                return True
        
        # Additional direct checks for common cases
        claude_indicators = [
            "/.claude/",
            "\\.claude\\",
            ".claude" + os.sep,
            os.sep + ".claude" + os.sep
        ]
        
        for indicator in claude_indicators:
            if indicator in abs_path or indicator in rel_path:
                return True
        
        return False
    
    def is_blocked(self, file_path: str) -> BlockingResult:
        """Check if file creation should be blocked.
        
        Args:
            file_path: Path to the file being created
            
        Returns:
            BlockingResult with blocking decision and details
        """
        # MASTER BLOCK CHECK - Highest priority, blocks ALL .claude operations
        if self.config.is_master_block_enabled():
            if self._is_claude_directory_operation(file_path):
                abs_path, rel_path = self._normalize_file_path(file_path)
                reason = (
                    f"MASTER BLOCK ACTIVE: All operations in .claude directory are blocked. "
                    f"Attempted operation: {rel_path}. "
                    f"Disable with: CLAUDE_MASTER_BLOCK=false or config file setting."
                )
                
                self.logger.critical(reason)
                
                return BlockingResult(
                    is_blocked=True,
                    rule_name="MASTER_BLOCK",
                    reason=reason,
                    severity="CRITICAL"
                )
        
        enabled_rules = self.config.get_enabled_rules()
        
        for rule_name, rule in enabled_rules.items():
            # Ensure patterns are compiled
            if rule._compiled_patterns is None:
                rule._compiled_patterns = [
                    self._normalize_pattern(pattern) for pattern in rule.path_patterns
                ]
            
            # Check if path matches rule patterns
            if self._matches_path_patterns(file_path, rule._compiled_patterns):
                # Check if file extension matches blocked extensions
                if self._matches_extension_patterns(file_path, rule.blocked_extensions):
                    abs_path, rel_path = self._normalize_file_path(file_path)
                    
                    reason = (
                        f"File creation blocked by rule '{rule_name}': {rule.description}. "
                        f"Attempted to create: {rel_path}"
                    )
                    
                    self.logger.warning(reason)
                    
                    return BlockingResult(
                        is_blocked=True,
                        rule_name=rule_name,
                        reason=reason,
                        severity=rule.severity
                    )
        
        return BlockingResult(is_blocked=False)
    
    def check_file_creation(self, file_path: str, raise_on_block: bool = True) -> bool:
        """Check if file creation is allowed.
        
        Args:
            file_path: Path to the file being created
            raise_on_block: If True, raises SystemExit on blocking. If False, returns boolean.
            
        Returns:
            True if allowed, False if blocked (only when raise_on_block=False)
            
        Raises:
            SystemExit: If file creation is blocked and raise_on_block=True
        """
        result = self.is_blocked(file_path)
        
        if result.is_blocked:
            if raise_on_block:
                severity_prefix = {
                    "CRITICAL": "[CRITICAL]",
                    "HIGH": "[HIGH]",
                    "MEDIUM": "[MEDIUM]",
                    "LOW": "[LOW]"
                }.get(result.severity, "[HIGH]")
                
                print(f"\n{severity_prefix} FILE CREATION BLOCKED:", file=sys.stderr)
                print(f"   {result.reason}", file=sys.stderr)
                print("\nTo bypass this restriction:", file=sys.stderr)
                print("   - Add exemption in .claude/exemptions.json", file=sys.stderr)
                print("   - Use CLAUDE_FORCE_CREATE=true (not recommended)", file=sys.stderr)
                print(f"   - Add inline exemption: # claude-exempt: {result.rule_name} - <justification>", file=sys.stderr)
                
                sys.exit(2)
            else:
                return False
        
        return True


# Convenience functions for PreToolUse.py integration
def is_file_blocked(file_path: str) -> tuple[bool, str]:
    """Simple interface to check if file creation should be blocked.
    
    Args:
        file_path: Path to the file being created
        
    Returns:
        Tuple of (is_blocked, reason). Empty reason string if not blocked.
    """
    blocker = FileBlocker()
    result = blocker.is_blocked(file_path)
    return result.is_blocked, result.reason or ""


def check_file_creation_simple(file_path: str) -> bool:
    """Check if file creation should be allowed (simple boolean interface).
    
    Args:
        file_path: Path to the file being created
        
    Returns:
        True if allowed, False if blocked
    """
    blocker = FileBlocker()
    return blocker.check_file_creation(file_path, raise_on_block=False)


def block_file_creation_if_restricted(file_path: str):
    """Check and block file creation if restricted by rules.
    
    Args:
        file_path: Path to the file being created
        
    Raises:
        SystemExit: If file creation is blocked
    """
    blocker = FileBlocker()
    blocker.check_file_creation(file_path, raise_on_block=True)


# Master block convenience functions
def enable_master_block(save_to_config: bool = True):
    """Enable master block for all .claude directory operations.
    
    Args:
        save_to_config: If True, saves setting to configuration file
    """
    config = FileBlockerConfig()
    config.enable_master_block(save_to_config)
    print("Master block ENABLED - All .claude directory operations are blocked")


def disable_master_block(save_to_config: bool = True):
    """Disable master block for .claude directory operations.
    
    Args:
        save_to_config: If True, saves setting to configuration file
    """
    config = FileBlockerConfig()
    config.disable_master_block(save_to_config)
    print("Master block DISABLED - .claude directory operations are allowed")


def get_master_block_status() -> bool:
    """Get current master block status.
    
    Returns:
        True if master block is enabled, False otherwise
    """
    config = FileBlockerConfig()
    return config.is_master_block_enabled()


# Example configuration creation
def create_example_config_file():
    """Create an example configuration file."""
    config = FileBlockerConfig()
    config.save_config()
    print(f"Example configuration created at: {config.config_file}")


# Testing and utility functions
def load_blocking_rules() -> Dict[str, BlockingRule]:
    """Load and return current blocking rules for inspection."""
    config = FileBlockerConfig()
    return config.rules


def test_file_path(file_path: str, verbose: bool = True) -> BlockingResult:
    """Test a file path against current blocking rules.
    
    Args:
        file_path: Path to test
        verbose: If True, prints detailed results
        
    Returns:
        BlockingResult with the test results
    """
    blocker = FileBlocker()
    result = blocker.is_blocked(file_path)
    
    if verbose:
        if result.is_blocked:
            print(f"❌ BLOCKED: {file_path}")
            print(f"   Rule: {result.rule_name}")
            print(f"   Reason: {result.reason}")
            print(f"   Severity: {result.severity}")
        else:
            print(f"✅ ALLOWED: {file_path}")
    
    return result


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="File Blocker Configuration Tool")
    parser.add_argument("--test", help="Test a file path against current rules")
    parser.add_argument("--create-config", action="store_true", 
                       help="Create example configuration file")
    parser.add_argument("--list-rules", action="store_true",
                       help="List current blocking rules")
    parser.add_argument("--master-block-status", action="store_true",
                       help="Show master block status")
    parser.add_argument("--enable-master-block", action="store_true",
                       help="Enable master block (blocks ALL .claude operations)")
    parser.add_argument("--disable-master-block", action="store_true",
                       help="Disable master block")
    
    args = parser.parse_args()
    
    if args.create_config:
        create_example_config_file()
    elif args.test:
        test_file_path(args.test)
    elif args.list_rules:
        # Show master block status first
        status = get_master_block_status()
        master_status = "🔒 ENABLED" if status else "🔓 DISABLED"
        print(f"Master Block Status: {master_status}")
        if status:
            print("  ⚠️  ALL .claude directory operations are blocked")
        print()
        
        rules = load_blocking_rules()
        print("Current blocking rules:")
        for name, rule in rules.items():
            rule_status = "✅ ENABLED" if rule.enabled else "❌ DISABLED"
            print(f"\n{name} ({rule_status})")
            print(f"  Severity: {rule.severity}")
            print(f"  Description: {rule.description}")
            print(f"  Path patterns: {rule.path_patterns}")
            print(f"  Blocked extensions: {rule.blocked_extensions}")
    elif args.master_block_status:
        status = get_master_block_status()
        master_status = "ENABLED" if status else "DISABLED"
        print(f"Master Block Status: {master_status}")
        if status:
            print("⚠️  All operations in .claude directory are blocked")
            print("To disable: --disable-master-block or set CLAUDE_MASTER_BLOCK=false")
        else:
            print("✅ .claude directory operations are allowed")
            print("To enable: --enable-master-block or set CLAUDE_MASTER_BLOCK=true")
    elif args.enable_master_block:
        enable_master_block()
    elif args.disable_master_block:
        disable_master_block()
    else:
        parser.print_help()