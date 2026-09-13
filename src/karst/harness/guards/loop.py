"""Minimal tool-calling loop showing where the guards plug in.

Why this exists: the four guards are plain functions and small classes that
know nothing about any particular agent loop. This module is the reference
wiring — a ~100-line loop with the five seams a host loop needs to expose:
tool dispatch, a result filter on every tool result, ``LoopDetector.record``
after every tool call, ``ThreadInjector.check`` once per iteration, and a
repetition check on the final answer. Copy the shape into your own loop or
use this one directly. The ``Model`` protocol keeps the loop model-agnostic:
``ScriptedModel`` replays canned turns for tests and demos with no model
process at all; ``OllamaModel`` drives a local Ollama server when the
optional ``ollama`` package is installed.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from .thinking import strip_thinking_tokens


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelTurn:
    """One assistant reply: free text and/or tool calls."""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class Model(Protocol):
    def chat(self, messages: list[dict[str, Any]], tools: list[Any]) -> ModelTurn: ...


class ScriptedModel:
    """Replays a fixed sequence of turns; repeats the last one if the loop runs longer."""

    def __init__(self, turns: Iterable[ModelTurn]) -> None:
        self._turns = list(turns)
        self.calls: list[list[dict[str, Any]]] = []

    def chat(self, messages: list[dict[str, Any]], tools: list[Any]) -> ModelTurn:
        self.calls.append(list(messages))
        idx = min(len(self.calls) - 1, len(self._turns) - 1)
        return self._turns[idx] if self._turns else ModelTurn()


class OllamaModel:
    """Model backed by ``ollama.Client.chat``. Requires the ``ollama`` extra."""

    def __init__(self, model: str, host: str | None = None, **options: Any) -> None:
        try:
            import ollama
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ImportError(
                "OllamaModel needs the optional dependency: pip install 'karst[ollama]'"
            ) from exc
        self._client = ollama.Client(host=host)
        self._model = model
        self._options = options

    def chat(self, messages: list[dict[str, Any]], tools: list[Any]) -> ModelTurn:
        resp = self._client.chat(
            model=self._model, messages=messages, tools=tools or None, options=self._options,
        )
        msg = resp.message
        calls = [
            ToolCall(tc.function.name, dict(tc.function.arguments or {}))
            for tc in (msg.tool_calls or [])
        ]
        return ModelTurn(content=msg.content or "", tool_calls=calls)


@dataclass
class LoopResult:
    final_response: str
    messages: list[dict[str, Any]]
    injections: list[dict[str, Any]]
    iterations: int
    tool_calls: int
    termination_reason: str
    degenerate_pattern: str = ""


def run_loop(
    model: Model,
    messages: list[dict[str, Any]],
    tools: Mapping[str, Callable[..., Any]],
    *,
    max_iterations: int = 10,
    tool_specs: list[Any] | None = None,
    result_filter: Callable[[str, str], str] | None = None,
    loop_detector: Any | None = None,
    thread_injector: Any | None = None,
    repetition_detector: Callable[[str], Any] | None = None,
) -> LoopResult:
    """Run a tool-calling loop with the guards wired at their seams.

    ``tools`` maps tool name to a callable taking keyword arguments; the
    callable's return value is stringified into a tool message and any
    exception becomes an ``"Error: <Type>: <msg>"`` tool message. Guards are
    all optional so the shim doubles as an unguarded baseline.
    """
    messages = list(messages)
    injections: list[dict[str, Any]] = []
    specs = tool_specs if tool_specs is not None else list(tools.values())
    total_calls = 0
    iterations = 0
    termination = "max_iterations"

    def inject(kind: str, iteration: int, text: str) -> None:
        messages.append({"role": "user", "content": text})
        injections.append({"type": kind, "iteration": iteration, "message": text})

    for iteration in range(max_iterations):
        iterations += 1
        turn = model.chat(messages, specs)
        assistant: dict[str, Any] = {"role": "assistant", "content": turn.content}
        if turn.tool_calls:
            assistant["tool_calls"] = [
                {"function": {"name": tc.name, "arguments": tc.arguments}} for tc in turn.tool_calls
            ]
        messages.append(assistant)

        last_sql: str | None = None
        for tc in turn.tool_calls:
            total_calls += 1
            fn = tools.get(tc.name)
            if fn is None:  # not a tool failure: tell the model and move on, no guards
                messages.append({"role": "tool", "content": f"Error: unknown tool {tc.name!r}"})
                continue
            try:
                raw = str(fn(**tc.arguments))
                success = True
            except Exception as exc:  # noqa: BLE001 - tool errors are returned to the model
                raw = f"Error: {type(exc).__name__}: {exc}"
                success = False
            filtered = result_filter(raw, tc.name) if result_filter else raw
            messages.append({"role": "tool", "content": filtered, "tool_name": tc.name})
            sql = tc.arguments.get("sql")
            if isinstance(sql, str):
                last_sql = sql
            if loop_detector is not None:
                diagnostic = loop_detector.record(tc.name, raw, success)
                if diagnostic:
                    inject("loop_detector", iteration, diagnostic)

        had_tool_calls = bool(turn.tool_calls)
        if thread_injector is not None:
            for note in thread_injector.check(iteration, had_tool_calls, last_sql):
                inject("thread_injector", iteration, note)

        if not had_tool_calls:
            if injections and injections[-1]["iteration"] == iteration:
                continue  # a nudge was injected: give the model another turn
            termination = "complete"
            break

    final = ""
    for m in reversed(messages):
        if m.get("role") == "assistant" and m.get("content"):
            final = strip_thinking_tokens(m["content"])
            break

    degenerate = ""
    if repetition_detector is not None and final:
        rep = repetition_detector(final)
        if rep.is_degenerate:
            final = rep.cleaned_text
            degenerate = rep.pattern_type
            if termination == "complete":
                termination = f"degenerate_output:{rep.pattern_type}"

    return LoopResult(
        final_response=final,
        messages=messages,
        injections=injections,
        iterations=iterations,
        tool_calls=total_calls,
        termination_reason=termination,
        degenerate_pattern=degenerate,
    )
