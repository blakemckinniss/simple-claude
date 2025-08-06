#!/usr/bin/env python3
"""
Gemini API client module extracted from UserPromptSubmit.py
Handles Gemini API integration for context-aware responses.
"""
import os
import requests
from typing import Dict, Any, List, Optional, Tuple

# Import shared dependencies using centralized path resolver
from utilities.path_resolver import paths
from hook_logger import logger
from continuation_helpers import get_continuation_id as get_current_continuation_id

# Load constants and environment using path resolver
CONSTANTS = paths.load_constants()
paths.load_env(CONSTANTS)

# API Configuration Constants
OPENROUTER_API_KEY = os.getenv(CONSTANTS["environment_variables"]["openrouter_api_key"])
GEMINI_MODEL = CONSTANTS["api"]["gemini_model"]
ENDPOINT = CONSTANTS["api"]["endpoint"]


def format_outline(outline: Dict[str, Any]) -> str:
    """Format outline data into readable text format.
    
    Args:
        outline: Dictionary containing file paths and their analysis data
        
    Returns:
        Formatted string representation of the outline
    """
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


def call_gemini(user_prompt: str, verbose_outline: Dict[str, Any], mcp_servers: Optional[List[Dict]] = None, 
               agents: Optional[List[Tuple[str, str, str]]] = None, session_id: Optional[str] = None, 
               git_context: Optional[Dict] = None, error_context: Optional[Dict] = None, 
               project_config: Optional[Dict] = None, project_docs: Optional[Dict] = None, 
               test_context: Optional[Dict] = None, env_context: Optional[Dict] = None, 
               import_graph: Optional[Dict] = None, cross_file_patterns: Optional[Dict] = None, 
               test_metrics: Optional[Dict] = None, context_depth: Optional[Dict] = None, 
               memory_context: Optional[str] = None) -> str:
    """Call Gemini API with comprehensive context for enhanced responses.
    
    Args:
        user_prompt: The user's input prompt
        verbose_outline: Analyzed file structure and content
        mcp_servers: Available MCP server information
        agents: Available agent information (name, description, model tuples)
        session_id: Session identifier for continuation tracking
        git_context: Git repository context (branches, commits, changes)
        error_context: Recent errors and warnings from logs
        project_config: Project configuration context (dependencies, scripts)
        project_docs: Documentation context (README files, doc directories)
        test_context: Testing context (test files, frameworks)
        env_context: Environment context (Python version, platform, packages)
        import_graph: Import dependency graph for the project
        cross_file_patterns: Cross-file pattern analysis results
        test_metrics: Test coverage and quality metrics
        context_depth: Context configuration for analysis depth
        memory_context: Relevant context from memory system
        
    Returns:
        Gemini API response content
        
    Raises:
        requests.exceptions.Timeout: If API request times out
        requests.exceptions.RequestException: For other API request failures
        ValueError: If API response structure is invalid
    """
    if not OPENROUTER_API_KEY:
        logger.log_error(f"Missing {CONSTANTS['environment_variables']['openrouter_api_key']}")
        return "Error: API key not configured"

    outline_text = format_outline(verbose_outline)
    
    # Add performance and quality insights
    quality_insights = ""
    if cross_file_patterns:
        quality_insights += "\n\n## Project-Wide Patterns:\n"
        if cross_file_patterns.get('architectural_patterns'):
            quality_insights += f"Architecture: {', '.join(cross_file_patterns['architectural_patterns'])}\n"
        if cross_file_patterns.get('common_issues'):
            quality_insights += f"Common Issues: {list(cross_file_patterns['common_issues'].keys())}\n"
        if cross_file_patterns.get('repeated_patterns'):
            # Show top 5 most imported modules
            top_imports = sorted(cross_file_patterns['repeated_patterns'].items(), key=lambda x: x[1], reverse=True)[:5]
            quality_insights += f"Top Imports: {', '.join([f'{imp}({count})' for imp, count in top_imports])}\n"
    
    if test_metrics:
        quality_insights += "\n## Test Metrics:\n"
        quality_insights += f"Test Count: {test_metrics['test_count']}\n"
        quality_insights += f"Assertion Density: {test_metrics['assertion_density']:.2f}\n"
        quality_insights += f"Mock Usage: {test_metrics['mock_usage']}\n"
    
    if context_depth:
        quality_insights += "\n## Context Configuration:\n"
        quality_insights += f"Depth: {context_depth['depth']}\n"
        quality_insights += f"Files Analyzed: {context_depth['top_k']}\n"
        if context_depth.get('focus'):
            quality_insights += f"Focus: {context_depth['focus']}\n"
    
    # Format git context if provided
    git_text = ""
    if git_context:
        git_text = f"""\n## Git Context
- Current Branch: {git_context.get('current_branch', 'unknown')}
- Working On: {git_context.get('working_on', 'No changes') or 'No changes'}
- Recent Commits: {'; '.join(git_context.get('recent_commits', [])[:3]) or 'None'}
- Recently Changed: {', '.join(git_context.get('recently_changed', [])[:5]) or 'None'}\n"""
    
    # Format error context if provided
    error_text = ""
    if error_context and (error_context.get('recent_errors') or error_context.get('warnings')):
        error_text = f"""\n## Runtime Context
- Recent Errors: {'; '.join(error_context.get('recent_errors', [])[:3]) or 'None'}
- Warnings: {'; '.join(error_context.get('warnings', [])[:2]) or 'None'}\n"""
    
    # Format project config context
    config_text = ""
    if project_config and project_config.get('config_files'):
        config_text = f"""\n## Project Configuration
- Config Files: {', '.join(project_config.get('config_files', [])[:5])}
- Dependencies: {', '.join(project_config.get('dependencies', [])[:5]) or 'None'}\n"""
    
    # Format documentation context
    docs_text = ""
    if project_docs and (project_docs.get('readme_files') or project_docs.get('doc_dirs')):
        docs_text = f"""\n## Project Documentation
- README Files: {', '.join(project_docs.get('readme_files', [])[:3]) or 'None'}
- Doc Directories: {', '.join(project_docs.get('doc_dirs', [])[:3]) or 'None'}
- Key Docs: {', '.join(project_docs.get('key_docs', [])[:3]) or 'None'}\n"""
    
    # Format test context
    test_text = ""
    if test_context and (test_context.get('test_dirs') or test_context.get('test_files')):
        test_text = f"""\n## Testing Context
- Test Directories: {', '.join(test_context.get('test_dirs', [])[:3]) or 'None'}
- Test Files: {', '.join([os.path.basename(f) for f in test_context.get('test_files', [])][:3]) or 'None'}
- Frameworks: {', '.join(test_context.get('test_frameworks', [])[:3]) or 'None'}\n"""
    
    # Format environment context
    env_text = ""
    if env_context and (env_context.get('env_files') or env_context.get('containers') or env_context.get('ci_cd')):
        env_text = f"""\n## Environment & Deployment
- Environment Files: {', '.join(env_context.get('env_files', [])[:3]) or 'None'}
- Containers: {', '.join(env_context.get('containers', [])[:3]) or 'None'}
- CI/CD: {', '.join([os.path.basename(f) for f in env_context.get('ci_cd', [])][:3]) or 'None'}\n"""
    
    # Format import graph context (only for smaller projects)
    import_text = ""
    if import_graph and import_graph.get('import_map'):
        external_deps = ', '.join(import_graph.get('external_deps', [])[:5]) or 'None'
        import_text = f"""\n## Import Dependencies
- External Dependencies: {external_deps}
- Local Modules: {len(import_graph.get('import_map', {}))} files analyzed\n"""
    
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
    
    # Format memory context if provided
    memory_text = ""
    if memory_context:
        memory_text = f"\n{memory_context}"
    
    template = CONSTANTS["gemini_prompt_template"]
    full_text = f"""{template["user_prompt_header"]}
{user_prompt}
{zen_prompt}
{template["outline_header"]}
{outline_text}{quality_insights}{git_text}{error_text}{config_text}{docs_text}{test_text}{env_text}{import_text}{memory_text}
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
        # Add timeout for API calls
        response = requests.post(ENDPOINT, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        response_data = response.json()
        
        # Validate response structure
        if "choices" not in response_data or not response_data["choices"]:
            raise ValueError("Invalid API response structure")
        
        content = response_data["choices"][0]["message"]["content"].strip()
        
        # Log successful response
        logger.log_gemini_response(response_data, success=True)
        return content
        
    except requests.exceptions.Timeout:
        logger.log_gemini_response({"error": "Request timeout"}, success=False)
        raise
    except Exception as e:
        # Log failed response
        logger.log_gemini_response({"error": str(e)}, success=False)
        raise