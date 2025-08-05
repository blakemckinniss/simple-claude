#!/usr/bin/env python3
"""
UserPromptSubmit hook handler compliant with HOOK_CONTRACT.md.
This hook is called before a user prompt is submitted to Claude.
"""

import json
import sys
import os
from typing import Dict, Any
from openai import OpenAI


def load_env_file(env_path: str) -> None:
    """Load environment variables from .env file."""
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()


def sanitize_input(input_data: Dict[str, Any]) -> bool:
    """
    Sanitize and validate input data according to security requirements.
    
    Args:
        input_data: Hook event data
        
    Returns:
        True if input is safe, False otherwise
    """
    # Check for required fields
    required_fields = ["session_id", "transcript_path", "cwd", "hook_event_name"]
    for field in required_fields:
        if field not in input_data:
            return False
    
    # Validate paths for traversal attacks
    transcript_path = input_data.get("transcript_path", "")
    cwd = input_data.get("cwd", "")
    
    if ".." in transcript_path or ".." in cwd:
        print("Security: Path traversal blocked", file=sys.stderr)
        return False
    
    # Skip if no prompt provided
    if not input_data.get("prompt", ""):
        return False
        
    return True


def enhance_prompt_with_gemini(user_prompt: str, context_data: Dict[str, Any]) -> str:
    """
    Send user prompt to OpenRouter Gemini for enhancement.
    
    Args:
        user_prompt: Original user prompt
        context_data: Additional context information
        
    Returns:
        Enhanced context or empty string if enhancement fails
    """
    try:
        # Load .env file if it exists
        project_dir = context_data.get("cwd", "")
        env_path = os.path.join(project_dir, ".env")
        load_env_file(env_path)
        
        # Get OpenRouter API key from environment
        api_key = os.getenv('OPENROUTER_API_KEY')
        if not api_key:
            return ""
        
        # Prepare safe context summary (no sensitive data)
        context_summary = {
            "hook_event": context_data.get("hook_event_name", ""),
            "working_directory": context_data.get("cwd", "")
        }
        
        # Enhancement prompt for Gemini
        enhancement_prompt = f"""Analyze this user request and provide helpful context for an AI assistant:

User prompt: "{user_prompt}"

Context: {json.dumps(context_summary, indent=2)}

Provide 2-3 sentences of relevant technical context that would help understand the request better. Focus on likely programming tasks, file operations, or development workflows."""

        # Create OpenAI client for OpenRouter
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
        )
        
        completion = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "https://claude-code",
                "X-Title": "Claude Code Hook Enhancement",
            },
            model="google/gemini-2.5-flash:online",
            messages=[
                {
                    "role": "user",
                    "content": enhancement_prompt
                }
            ],
            temperature=0.3,
            max_tokens=500,
            timeout=5
        )
        
        # Safely extract content with null checks
        if (completion.choices and
            len(completion.choices) > 0 and
            completion.choices[0].message and
            completion.choices[0].message.content):
            enhanced_context = completion.choices[0].message.content.strip()
            
            # Validate response length and content
            if enhanced_context and 50 <= len(enhanced_context) <= 1000:
                return enhanced_context
                
    except Exception as e:
        # Log the error for debugging while providing fallback context
        print(f"Warning: Gemini enhancement failed: {e}", file=sys.stderr)
        # Fallback: provide basic context even if API call fails
        return f"User is working in directory: {context_data.get('cwd', 'unknown')}"
        
    return ""


def handle(input_data: Dict[str, Any]) -> None:
    """Handle UserPromptSubmit hook event - called by hook_handler.py."""
    # Validate input data
    if not sanitize_input(input_data):
        sys.exit(1)
    
    try:
        user_prompt = input_data.get("prompt", "")
        
        # Try to enhance with Gemini
        additional_context = enhance_prompt_with_gemini(user_prompt, input_data) + "\n\n Think deeply."
        
        # Output according to UserPromptSubmit contract
        output: Dict[str, Any] = {
            "continue": True,
            "suppressOutput": False
        }
        
        if additional_context:
            output["hookSpecificOutput"] = {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": additional_context
            }
        
        print(json.dumps(output))
        sys.exit(0)
        
    except Exception as e:
        print(f"Error in UserPromptSubmit handler: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point for standalone execution."""
    try:
        # Read and validate JSON input from stdin
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)
    
    handle(input_data)


if __name__ == "__main__":
    main()