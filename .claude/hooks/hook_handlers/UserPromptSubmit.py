#!/usr/bin/env python3
import os
import sys
import ast
import json
import requests
import re
from pathlib import Path
from subprocess import check_output
from typing import List, Tuple, Dict, Any

# Import the simplified logger and state manager
sys.path.insert(0, str(Path(__file__).parent.parent))
from hook_logger import logger
from state_manager import state_manager

# Load constants from JSON file
def load_constants() -> Dict[str, Any]:
    """Load configuration constants from JSON file."""
    constants_path = Path(__file__).parent.parent.parent / "json" / "constants.json"
    try:
        with open(constants_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Constants file not found: {constants_path}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in constants file: {e}")

# Load constants globally
CONSTANTS = load_constants()

# Load environment variables from .env file
def load_env():
    env_path = Path(__file__).parent.parent.parent.parent / CONSTANTS["file_paths"]["env_file_relative_path"]
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value

load_env()

# --- Semantic Summary Logic ---

SUMMARY_OUTPUT = CONSTANTS["file_paths"]["summary_output"]

def summarize_python_file(filepath):
    try:
        with open(filepath, 'r', encoding=CONSTANTS["file_encoding"]["default"], 
                  errors=CONSTANTS["file_encoding"]["error_handling"]) as f:
            source = f.read()
        tree = ast.parse(source)
    except Exception:
        return {"description": CONSTANTS["file_summary"]["unreadable_python"]}

    summary = {"functions": [], "classes": [], "docstring": ""}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            args = [arg.arg for arg in node.args.args]
            summary["functions"].append(f"{node.name}({', '.join(args)})")
        elif isinstance(node, ast.ClassDef):
            summary["classes"].append(node.name)

    summary["docstring"] = ast.get_docstring(tree) or ""
    if summary["functions"] or summary["classes"]:
        summary["description"] = CONSTANTS["file_summary"]["classes_functions_template"].format(
            classes_count=len(summary['classes']), 
            functions_count=len(summary['functions'])
        )
    else:
        summary["description"] = CONSTANTS["file_summary"]["module_level_fallback"]

    return summary

def summarize_text_file(filepath):
    try:
        with open(filepath, 'r', encoding=CONSTANTS["file_encoding"]["default"], 
                  errors=CONSTANTS["file_encoding"]["error_handling"]) as f:
            for line in f:
                line = line.strip()
                if line:
                    truncate_len = CONSTANTS["text_limits"]["description_truncate_length"]
                    suffix = CONSTANTS["text_limits"]["truncate_suffix"]
                    return {
                        "description": line[:truncate_len] + (suffix if len(line) > truncate_len else ""),
                        "docstring": line
                    }
    except:
        return {"description": CONSTANTS["file_summary"]["unreadable_text"]}
    return {"description": CONSTANTS["file_summary"]["empty_text"]}

def summarize_json_file(filepath):
    try:
        with open(filepath, 'r', encoding=CONSTANTS["file_encoding"]["default"]) as f:
            data = json.load(f)
        if isinstance(data, dict):
            max_keys = CONSTANTS["text_limits"]["max_json_keys_display"]
            return {"description": CONSTANTS["file_summary"]["json_config"], 
                   "keys": list(data.keys())[:max_keys]}
        return {"description": CONSTANTS["file_summary"]["json_non_dict"]}
    except:
        return {"description": CONSTANTS["file_summary"]["unreadable_json"]}

def summarize_file(filepath):
    ext = Path(filepath).suffix.lower()
    exts = CONSTANTS["file_extensions"]
    if ext == exts["python"]:
        return summarize_python_file(filepath)
    elif ext == exts["json"]:
        return summarize_json_file(filepath)
    elif ext in [exts["markdown"], exts["text"]]:
        return summarize_text_file(filepath)
    else:
        return {"description": CONSTANTS["file_summary"]["skipped_file_prefix"] + filepath}

def generate_outline(file_list):
    outline = {}
    for path in file_list:
        if os.path.exists(path):
            outline[path] = summarize_file(path)
    return outline

def bootstrap_summary(json_path=SUMMARY_OUTPUT):
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                return json.load(f)
        except:
            pass

    try:
        file_list = check_output(CONSTANTS["git_commands"]["list_files"], text=True).splitlines()
    except Exception as e:
        print(f"Error: Cannot list files from git: {e}")
        return {}

    outline = generate_outline(file_list)
    try:
        os.makedirs(os.path.dirname(json_path), exist_ok=True)
        with open(json_path, 'w', encoding=CONSTANTS["file_encoding"]["default"]) as f:
            json.dump(outline, f, indent=CONSTANTS["json_formatting"]["indent"])
    except Exception as e:
        print(f"Warning: Failed to write summary cache: {e}")

    return outline

# --- Agent Information Extraction ---

def get_agent_info(agents_dir: str) -> List[Tuple[str, str, str]]:
    """Read agent files and extract name, description, and model from YAML frontmatter.
    
    Returns:
        List of (name, description, model) tuples
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

# --- Gemini API Integration ---

OPENROUTER_API_KEY = os.getenv(CONSTANTS["environment_variables"]["openrouter_api_key"])
GEMINI_MODEL = CONSTANTS["api"]["gemini_model"]
ENDPOINT = CONSTANTS["api"]["endpoint"]

def format_outline(outline):
    lines = []
    for file, info in outline.items():
        lines.append(f"## {file}")
        for key, value in info.items():
            if isinstance(value, list):
                lines.append(f"- {key}:")
                lines.extend([f"  - {v}" for v in value])
            else:
                lines.append(f"- {key}: {value}")
        lines.append("")
    return "\n".join(lines)

def call_gemini(user_prompt, verbose_outline, mcp_servers=None, agents=None, session_id=None):
    if not OPENROUTER_API_KEY:
        raise RuntimeError(f"Missing {CONSTANTS['environment_variables']['openrouter_api_key']}")

    outline_text = format_outline(verbose_outline)
    
    # Format MCP server information if provided
    mcp_text = ""
    if mcp_servers:
        mcp_text = CONSTANTS["gemini_prompt_template"]["mcp_tools_header"]
        for server in mcp_servers:
            mcp_text += f"- {server['name']}: {server['description']}\n"
        mcp_text += "\n"
    
    # Format agent information if provided
    agent_text = ""
    if agents:
        agent_text = CONSTANTS["gemini_prompt_template"]["agents_header"]
        for name, description, model in agents:
            agent_text += f"- {name} ({model}): {description}\n"
        agent_text += "\n"
    
    # Add ZEN continuation prompt based on session state
    zen_prompt = ""
    if session_id:
        current_continuation = get_current_continuation_id(session_id)
        if current_continuation:
            # Active continuation - remind to use existing thread
            zen_prompt = f"\n\n**CRITICAL CONTEXT - ACTIVE ZEN THREAD**: {current_continuation}\nThe user has an active ZEN conversation thread. When using mcp__zen tools, ALWAYS include continuation_id: '{current_continuation}' to maintain conversation continuity and context across tool calls.\n"
        else:
            # No continuation - strong initiation for first message
            zen_prompt = "\n\n**CRITICAL: Start with ZEN Analysis**\nFor complex tasks, ALWAYS begin by using mcp__zen tools (thinkdeep, debug, analyze, etc.) for systematic investigation. These tools provide enhanced reasoning capabilities and should be your first choice for any non-trivial work. The continuation_id from the first ZEN call will be tracked for this session.\n"
    
    template = CONSTANTS["gemini_prompt_template"]
    full_text = f"""{template["user_prompt_header"]}
{user_prompt}
{zen_prompt}
{template["outline_header"]}
{outline_text}
{mcp_text}{agent_text}{template["analysis_request"]}

{template["relevant_files_section"]}

{template["mcp_tools_section"]}

{template["agents_section"]}

{template["format_header"]}
{template["relevant_files_format"]}

{template["mcp_tools_format"]}

{template["agents_format"]}
"""

    payload = {
        "model": GEMINI_MODEL,
        "messages": [{
            "role": "user",
            "content": [{"type": "text", "text": full_text}]
        }]
    }

    headers = {
        "Content-Type": CONSTANTS["http_headers"]["content_type"],
        "Authorization": f"{CONSTANTS['http_headers']['authorization_prefix']}{OPENROUTER_API_KEY}"
    }

    # Log the Gemini API request
    logger.log_gemini_request(user_prompt, payload)

    try:
        response = requests.post(ENDPOINT, headers=headers, json=payload)
        response.raise_for_status()
        response_data = response.json()
        content = response_data["choices"][0]["message"]["content"].strip()
        
        # Log successful response
        logger.log_gemini_response(response_data, success=True)
        return content
        
    except Exception as e:
        # Log failed response
        logger.log_gemini_response({"error": str(e)}, success=False)
        raise

# --- Continuation Management Helpers ---

def get_current_continuation_id(session_id: str) -> str:
    """Get current continuation_id for session, or empty string if none."""
    continuation_id = state_manager.get_continuation_id(session_id)
    return continuation_id or ""

def set_continuation_id(session_id: str, continuation_id: str) -> None:
    """Set continuation_id for current session."""
    state_manager.set_continuation_id(session_id, continuation_id)

def has_active_continuation(session_id: str) -> bool:
    """Check if session has an active continuation."""
    return state_manager.has_continuation(session_id)

# --- Claude Code Hook Entry Point ---

def handle(data):
    user_prompt = data.get("prompt", "").strip()
    session_id = data.get("session_id", "")
    
    if not user_prompt:
        logger.log_context_injection(success=False, context=None)
        sys.exit(0)  # Do nothing
    
    # Initialize session if not already done
    if session_id:
        state_manager.initialize_session(session_id)

    verbose_outline = bootstrap_summary()
    if not verbose_outline:
        logger.log_error("No semantic outline available")
        sys.exit(0)
    
    # Get agent information
    project_root = Path(os.getcwd())
    agents_dir = project_root / CONSTANTS["file_paths"]["agents_dir_relative_path"]
    agents = get_agent_info(str(agents_dir))

    # Define MCP server information
    mcp_servers = CONSTANTS["mcp_servers"]

    try:
        gemini_response = call_gemini(user_prompt, verbose_outline, mcp_servers, agents, session_id)
        
        # Add continuation tracking information to context (now redundant but kept for backward compatibility)
        continuation_info = ""
        if session_id:
            current_continuation = get_current_continuation_id(session_id)
            if current_continuation:
                continuation_info = f"\n\nCONTINUATION_ID: {current_continuation} (Use this in mcp__zen tools for conversation continuity)"
            else:
                continuation_info = "\n\nNO_CONTINUATION: This is a new conversation thread"
        
        # Output properly structured JSON for UserPromptSubmit context injection
        json_keys = CONSTANTS["json_structure"]
        output = {
            json_keys["hook_specific_output_key"]: {
                "hookEventName": json_keys["hook_event_name"],
                json_keys["additional_context_key"]: f"{CONSTANTS['response_template']['context_prefix']}{gemini_response}{continuation_info}"
            }
        }
        
        # Log successful context injection
        logger.log_context_injection(success=True, context=gemini_response)
        
        print(json.dumps(output))
        sys.exit(0)
        
    except Exception as e:
        # Log the error
        logger.log_error(f"Gemini request failed: {e}", {"exception_type": type(e).__name__})
        
        # Block with error message
        json_keys = CONSTANTS["json_structure"]
        output = {
            json_keys["decision_key"]: json_keys["block_decision"],
            json_keys["reason_key"]: f"{CONSTANTS['response_template']['gemini_failure_prefix']}{e}"
        }
        print(json.dumps(output))
        sys.exit(0)
