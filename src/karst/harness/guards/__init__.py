"""karst.harness.guards — deterministic guards for tool-calling agent loops.

Four guards that catch the failure modes small local models hit inside a
tool-calling loop, plus a thinking-token stripper and a reference loop
showing where each guard plugs in. No LLM calls anywhere in the package.
"""

from __future__ import annotations

from .loop import LoopResult, Model, ModelTurn, OllamaModel, ScriptedModel, ToolCall, run_loop
from .loop_detector import ErrorSignature, LoopDetector
from .repetition_detector import RepetitionResult, detect_repetition
from .result_filter import filter_tool_result
from .thinking import strip_thinking_tokens
from .thread_injector import DEFAULT_TABLE_GUIDANCE, InjectionEvent, ThreadInjector

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_TABLE_GUIDANCE",
    "ErrorSignature",
    "InjectionEvent",
    "LoopDetector",
    "LoopResult",
    "Model",
    "ModelTurn",
    "OllamaModel",
    "RepetitionResult",
    "ScriptedModel",
    "ThreadInjector",
    "ToolCall",
    "__version__",
    "detect_repetition",
    "filter_tool_result",
    "run_loop",
    "strip_thinking_tokens",
]
