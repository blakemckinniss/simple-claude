#!/usr/bin/env python3
"""
Agent loader module extracted from UserPromptSubmit.py
Handles reading and parsing of agent configuration files.
"""
import os
import sys
import json
from typing import List, Tuple

from hook_tools.utilities.path_resolver import PathResolver

# Initialize path resolver for consistent path handling
paths = PathResolver()


def load_constants():
    """Load configuration constants from JSON file using PathResolver."""
    constants_path = paths.claude_dir / "json" / "constants.json"
    try:
        with open(constants_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Constants file not found: {constants_path}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in constants file: {e}")


# Load constants globally with error handling
try:
    CONSTANTS = load_constants()
except RuntimeError as e:
    print(f"Error loading constants: {e}", file=sys.stderr)
    sys.exit(2)  # Block execution if constants cannot be loaded


def get_agent_info(agents_dir: str) -> List[Tuple[str, str, str]]:
    """Read agent files and extract name, description, and model from YAML frontmatter.
    
    Scans the specified directory for markdown files containing agent definitions
    with YAML frontmatter. Extracts agent metadata including name, description,
    and model information.
    
    Args:
        agents_dir: Path to directory containing agent markdown files
        
    Returns:
        List of (name, description, model) tuples for each valid agent found
        
    Example:
        >>> agents = get_agent_info("/path/to/agents")
        >>> for name, desc, model in agents:
        ...     print(f"{name} ({model}): {desc}")
    """
    agents = []
    if not os.path.exists(agents_dir):
        return agents
    
    for filename in os.listdir(agents_dir):
        if filename.endswith(CONSTANTS["file_extensions"]["markdown"]):
            filepath = os.path.join(agents_dir, filename)
            try:
                with open(filepath, 'r', encoding=CONSTANTS["file_encoding"]["default"]) as f:
                    content = f.read()
                    
                # Extract YAML frontmatter
                delimiter = CONSTANTS["yaml_frontmatter"]["delimiter"]
                if content.startswith(delimiter):
                    end_index = content.find(delimiter, 3)
                    if end_index != -1:
                        frontmatter = content[3:end_index].strip()
                        
                        # Parse YAML-like frontmatter manually
                        name = ""
                        description = ""
                        model = ""
                        
                        yaml_keys = CONSTANTS["yaml_frontmatter"]
                        for line in frontmatter.split('\n'):
                            line = line.strip()
                            if line.startswith(yaml_keys["name_key"]):
                                name = line.split(':', 1)[1].strip()
                            elif line.startswith(yaml_keys["description_key"]):
                                description = line.split(':', 1)[1].strip()
                            elif line.startswith(yaml_keys["model_key"]):
                                model = line.split(':', 1)[1].strip()
                        
                        if name and description:
                            agents.append((name, description, model))
            except Exception:
                continue
    
    return agents