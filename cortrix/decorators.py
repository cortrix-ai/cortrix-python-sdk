"""cortrix/decorators.py — @guard decorator for securing LLM functions."""
import functools
import inspect
import logging
from typing import Optional

from cortrix.core import Cortrix
from cortrix.exceptions import PolicyViolation

logger = logging.getLogger("cortrix")

def guard(
    prompt_arg: Optional[str] = None, 
    agent_id: str = "default",
    model_id: str = "unknown",
    scan_output: bool = False, 
    fail_open: bool = True
):
    """
    Decorator that scans function inputs through Cortrix before execution.

    Args:
        prompt_arg: Name of the kwarg containing the prompt. If None, scans the first positional arg.
        agent_id: Identifier for the agent making the request.
        model_id: Identifier for the underlying LLM model (e.g. 'gpt-4').
        scan_output: If True, also scans the function's return value (outbound).
        fail_open: If True (default), allow execution even if Cortrix is unreachable.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            engine = Cortrix()

            # 1. Extract the prompt to scan
            text = _extract_prompt(func, args, kwargs, prompt_arg)

            # 2. Scan inbound
            if text:
                result = engine.scan(text, direction="inbound", agent_id=agent_id, model_id=model_id)
                if result.get("blocked"):
                    raise PolicyViolation(
                        reason=result.get("reason", "Policy violation"),
                        decision=result.get("decision", "DENY"),
                        event_id=result.get("event_id"),
                    )
                # 3. Replace with safe (redacted) prompt
                safe = result.get("redacted_prompt", text)
                args, kwargs = _replace_prompt(func, args, kwargs, prompt_arg, safe)

            # 4. Execute the original function
            output = func(*args, **kwargs)

            # 5. Optionally scan outbound
            if scan_output and isinstance(output, str):
                out_result = engine.scan(output, direction="outbound", agent_id=agent_id, model_id=model_id)
                if out_result.get("blocked"):
                    raise PolicyViolation(
                        reason=out_result.get("reason", "Output policy violation"),
                        decision=out_result.get("decision", "DENY"),
                        event_id=out_result.get("event_id")
                    )
                output = out_result.get("redacted_prompt", output)

            return output
        return wrapper
    return decorator


def _extract_prompt(func, args, kwargs, prompt_arg):
    """Extract the prompt text from function arguments."""
    if prompt_arg and prompt_arg in kwargs:
        return str(kwargs[prompt_arg])
    if prompt_arg:
        # Try to find it by position using function signature
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        if prompt_arg in params:
            idx = params.index(prompt_arg)
            if idx < len(args):
                return str(args[idx])
    # Default: first string argument
    if args:
        for arg in args:
            if isinstance(arg, str):
                return arg
    return None


def _replace_prompt(func, args, kwargs, prompt_arg, safe_text):
    """Replace the prompt text with the safe (redacted) version."""
    if prompt_arg and prompt_arg in kwargs:
        kwargs[prompt_arg] = safe_text
        return args, kwargs
    if prompt_arg:
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        if prompt_arg in params:
            idx = params.index(prompt_arg)
            if idx < len(args):
                args = list(args)
                args[idx] = safe_text
                args = tuple(args)
                return args, kwargs
    if args:
        args = list(args)
        for i, arg in enumerate(args):
            if isinstance(arg, str):
                args[i] = safe_text
                break
        args = tuple(args)
    return args, kwargs
