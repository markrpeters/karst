"""Shim tests — the reference loop wired with every guard, driven by ScriptedModel."""

from __future__ import annotations

from functools import partial

from agent_loop_guards import (
    LoopDetector,
    ModelTurn,
    ScriptedModel,
    ThreadInjector,
    ToolCall,
    detect_repetition,
    filter_tool_result,
    run_loop,
)

BINDER_ERROR = 'Error: BinderException: Referenced column "alert.type" not found'


def _query_tool(sql: str) -> str:
    if "alert.type" in sql:
        return BINDER_ERROR
    if "conn" in sql:
        return "src_ip | dst_ip | bytes\n--------+--------+------\n" + "\n".join(
            ["192.0.2.1 | 198.51.100.7 | 1024"] * 200
        )
    return "ok"


def _turns(*calls):
    return [
        ModelTurn(tool_calls=[ToolCall("query_database", {"sql": sql})]) for sql in calls
    ]


class TestUnguardedBaseline:
    def test_plain_loop_returns_final_text(self):
        model = ScriptedModel([
            *_turns("SELECT 1"),
            ModelTurn(content="<think>hmm</think>Done."),
        ])
        result = run_loop(model, [{"role": "user", "content": "go"}], {"query_database": _query_tool})
        assert result.final_response == "Done."
        assert result.tool_calls == 1
        assert result.iterations == 2
        assert result.termination_reason == "complete"
        assert result.injections == []


class TestResultFilterSeam:
    def test_large_tool_result_is_truncated_in_context(self):
        model = ScriptedModel([*_turns("SELECT * FROM conn"), ModelTurn(content="Done.")])
        result = run_loop(
            model,
            [{"role": "user", "content": "go"}],
            {"query_database": _query_tool},
            result_filter=partial(filter_tool_result, max_chars=500),
        )
        tool_msg = next(m for m in result.messages if m["role"] == "tool")
        assert len(tool_msg["content"]) < 700
        assert "[HARNESS: Showing" in tool_msg["content"]


class TestLoopDetectorSeam:
    def test_repeated_error_injects_diagnostic(self):
        model = ScriptedModel([
            *_turns("SELECT alert.type FROM t", "SELECT alert.type FROM t"),
            ModelTurn(content="Giving up."),
        ])
        result = run_loop(
            model,
            [{"role": "user", "content": "go"}],
            {"query_database": _query_tool},
            loop_detector=LoopDetector(window_size=5, threshold=2),
        )
        kinds = [i["type"] for i in result.injections]
        assert kinds == ["loop_detector"]
        assert "alert.type" in result.injections[0]["message"]
        # The diagnostic reached the model as a user message before its next turn.
        assert any(
            m["role"] == "user" and "HARNESS NOTE" in m["content"] for m in model.calls[2]
        )


class TestThreadInjectorSeam:
    def test_table_guidance_and_no_tool_nudge(self):
        model = ScriptedModel([
            *_turns("SELECT * FROM conn LIMIT 5"),
            ModelTurn(content="I think that is enough."),
            ModelTurn(content="Final answer after the nudge."),
        ])
        result = run_loop(
            model,
            [{"role": "user", "content": "go"}],
            {"query_database": _query_tool},
            max_iterations=10,
            thread_injector=ThreadInjector(max_iterations=10),
        )
        kinds = [i["type"] for i in result.injections]
        assert kinds == ["thread_injector", "thread_injector"]
        assert "connection data" in result.injections[0]["message"]
        assert "still use your tools" in result.injections[1]["message"]
        assert result.final_response == "Final answer after the nudge."
        assert result.iterations == 3


class TestRepetitionDetectorSeam:
    def test_degenerate_final_answer_is_truncated(self):
        row = "| HOST-A | 192.0.2.3 | admin | lateral_movement |"
        model = ScriptedModel([ModelTurn(content="## Findings\n" + "\n".join([row] * 12))])
        result = run_loop(
            model,
            [{"role": "user", "content": "go"}],
            {},
            repetition_detector=detect_repetition,
        )
        assert result.degenerate_pattern in ("phrase", "line")
        assert result.termination_reason.startswith("degenerate_output:")
        assert "degenerate repetition detected" in result.final_response
        assert result.final_response.count(row) < 12
