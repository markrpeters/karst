"""Strip thinking/reasoning tokens from LLM output.

Why this exists: reasoning models (Gemma, Qwen, OLMo and others) emit their
chain of thought inline, wrapped in model-specific delimiters. Left in, that
text contaminates structured-output parsing, repetition detection and any
downstream scoring. This module removes every known delimiter style so the
loop's final response is the answer, not the deliberation.
"""

from __future__ import annotations

import re

# Patterns ordered most-specific-first. All use re.DOTALL so `.` matches newlines.
_THINKING_PATTERNS: list[re.Pattern[str]] = [
    # Gemma 4: <|channel>thought\n...<channel|>
    re.compile(r"<\|channel>thought\n.*?<channel\|>", re.DOTALL),
    # OLMo-style: <|thinking|>...</|thinking|>
    re.compile(r"<\|thinking\|>.*?<\|/thinking\|>", re.DOTALL),
    # Qwen / generic: <think>...</think>
    re.compile(r"<think>.*?</think>", re.DOTALL),
    # Bracket-style: [Start thinking]...[End thinking]
    re.compile(r"\[Start thinking\].*?\[End thinking\]", re.DOTALL | re.IGNORECASE),
]


def strip_thinking_tokens(text: str) -> str:
    """Remove thinking/reasoning blocks from LLM output.

    Handles multiple formats:
    - Gemma 4: ``<|channel>thought\\n...<channel|>``
    - Qwen/generic: ``<think>...</think>``
    - OLMo/generic: ``<|thinking|>...</|thinking|>``
    - Bracket-style: ``[Start thinking]...[End thinking]``

    Multiple blocks are removed (model may think multiple times).
    Leading/trailing whitespace is stripped from the result.

    Returns the original text unchanged if no thinking tokens are found.
    """
    if not text:
        return text
    result = text
    for pattern in _THINKING_PATTERNS:
        result = pattern.sub("", result)
    return result.strip()
