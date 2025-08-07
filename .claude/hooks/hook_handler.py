#!/usr/bin/env python3
import importlib.util
import json
import os
import sys

# Get current directory and add hook_logs to path
handlers_dir = os.path.dirname(os.path.abspath(__file__))

# Import logger
from hook_logger import logger  # type: ignore  # noqa: E402

# Circuit breaker switches - Set to False to disable specific hooks
ENABLE_USER_PROMPT_SUBMIT = True
ENABLE_PRE_TOOL_USE = True
ENABLE_POST_TOOL_USE = True
ENABLE_NOTIFICATION = False
ENABLE_STOP = True
ENABLE_SUBAGENT_STOP = False
ENABLE_PRE_COMPACT = True
ENABLE_SESSION_START = True

# Master switch - Set to False to disable all hooks
ENABLE_ALL_HOOKS = True

# Hook enable/disable mapping
HOOK_SWITCHES = {
    "UserPromptSubmit": ENABLE_USER_PROMPT_SUBMIT,
    "PreToolUse": ENABLE_PRE_TOOL_USE,
    "PostToolUse": ENABLE_POST_TOOL_USE,
    "Notification": ENABLE_NOTIFICATION,
    "Stop": ENABLE_STOP,
    "SubagentStop": ENABLE_SUBAGENT_STOP,
    "PreCompact": ENABLE_PRE_COMPACT,
    "SessionStart": ENABLE_SESSION_START,
}


def load_handler(hook_event_name):
    """Dynamically load the handler module for the given hook event."""
    handlers_dir = os.path.dirname(os.path.abspath(__file__))
    handler_path = os.path.join(handlers_dir, "hook_handlers", f"{hook_event_name}.py")

    if not os.path.exists(handler_path):
        return None

    spec = importlib.util.spec_from_file_location(hook_event_name, handler_path)
    if spec is None:
        return None

    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        return None

    spec.loader.exec_module(module)

    return module


def main():
    # Read JSON data from stdin
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)

    # Log the incoming hook call
    logger.log_hook_call(data)

    hook_event_name = data.get("hook_event_name", "")

    # Check master switch
    if not ENABLE_ALL_HOOKS:
        # All hooks disabled, exit silently
        sys.exit(0)

    # Check individual hook switch
    if hook_event_name in HOOK_SWITCHES and not HOOK_SWITCHES[hook_event_name]:
        # This specific hook is disabled, exit silently
        sys.exit(0)

    # Load and delegate to the appropriate handler
    handler_module = load_handler(hook_event_name)

    if handler_module and hasattr(handler_module, "handle"):
        # Delegate to the specific handler
        handler_module.handle(data)
    else:
        # Unknown hook event or missing handler - log and exit
        data["error"] = f"No handler found for hook event: {hook_event_name}"
        logger.log_hook_call(data)
        print(
            f"Warning: No handler found for hook event: {hook_event_name}",
            file=sys.stderr,
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
