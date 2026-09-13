# agent-loop-guards

Deterministic guards for tool-calling agent loops. Four small, pure-Python
modules that catch the failure modes small local models hit once they are
given tools, plus a thinking-token stripper and a reference loop that shows
where each guard plugs in. No LLM calls anywhere in the package; the whole
test suite runs offline in under a second.

> **Status: v0 draft.** Extracted from a working incident-response analysis
> harness where these guards run on every model turn. API may still move.

## The problem

Give a 4B–30B local model a SQL tool and a question, and three things go wrong
in the first ten iterations:

1. **Context blow-up.** One query returns a 50-column table with a
   multi-kilobyte raw-event string per row. The context window fills, and the
   model loses whatever it was investigating.
2. **The retry loop.** A query fails on a missing column. The error text is in
   context, but the model re-issues the same query, verbatim, until its
   iteration budget is gone.
3. **Losing the thread.** After a few results land, the model stops calling
   tools and summarises the last thing it saw, or it keeps querying one table
   and never pivots to the related ones.

And one that shows up at the end: **degenerate output**, where a quantized
model locks into repeating the same table row or sentence until it hits the
token limit. It looks complete at a glance.

Each guard is a deterministic answer to one of these. They were built one at a
time, each after watching the failure happen in traces, and each is a few
dozen lines of code with no model in the loop.

## Install

```bash
pip install agent-loop-guards            # runtime dependency: pydantic only
pip install 'agent-loop-guards[ollama]'  # adds the optional Ollama-backed Model
```

Python 3.10+.

## Use it in your loop

The guards are independent. Wire whichever ones you need at the seams your
loop already has:

```python
from functools import partial
from agent_loop_guards import (
    LoopDetector, ThreadInjector, detect_repetition, filter_tool_result,
    strip_thinking_tokens,
)

result_filter = partial(filter_tool_result, max_chars=2000)   # every tool result
loop_detector = LoopDetector(window_size=5, threshold=2)      # after every tool call
thread_injector = ThreadInjector(max_iterations=15)           # once per iteration

for iteration in range(max_iterations):
    turn = model.chat(messages, tools)
    messages.append(turn.as_assistant_message())

    for call in turn.tool_calls:
        raw, ok = dispatch(call)                                # your tool dispatch
        messages.append({"role": "tool", "content": result_filter(raw, call.name)})
        if note := loop_detector.record(call.name, raw, ok):
            messages.append({"role": "user", "content": note})

    for note in thread_injector.check(iteration, bool(turn.tool_calls), sql=last_sql):
        messages.append({"role": "user", "content": note})

final = strip_thinking_tokens(last_assistant_text(messages))
rep = detect_repetition(final)
if rep.is_degenerate:
    final = rep.cleaned_text
```

Or use the reference loop directly:

```python
from agent_loop_guards import ScriptedModel, ModelTurn, ToolCall, run_loop

model = ScriptedModel([
    ModelTurn(tool_calls=[ToolCall("query_database", {"sql": "SELECT * FROM conn"})]),
    ModelTurn(content="Two hosts talked to the same external address."),
])
result = run_loop(
    model,
    [{"role": "user", "content": "What happened?"}],
    tools={"query_database": run_sql},
    result_filter=result_filter,
    loop_detector=loop_detector,
    thread_injector=thread_injector,
    repetition_detector=detect_repetition,
)
print(result.final_response, result.injections, result.termination_reason)
```

Swap `ScriptedModel` for `OllamaModel("qwen3:8b")` to drive a live local model
through the same loop.

## Modules

| Module | Guard | Seam |
|---|---|---|
| `result_filter` | Truncates tool results at row/line boundaries, keeps the table header, flags known high-noise metadata columns. Guidance says "analyze this sample", not "refine your query" — the latter was observed to trigger re-query churn. | every tool result, before it enters context |
| `loop_detector` | Sliding window of error signatures (exception type + failed column/table/function). On a repeat past the threshold, injects a diagnostic; with a database connection supplied, lists the columns or tables that actually exist. Classifies DuckDB-style binder, catalog and unknown-function errors, and does not trust a `success=True` flag when the result text reads as an error. | after every tool call |
| `thread_injector` | Three one-shot triggers: first query against a known table (suggest what to correlate next), approaching the iteration ceiling (start concluding), an iteration with no tool calls on a non-final turn (tools are still available). | once per iteration |
| `repetition_detector` | Detects phrase stutter, consecutive duplicate lines and over-repeated sentences in the final answer; truncates at the first repeat with an explicit marker. | on the final response |
| `thinking` | Strips `<think>`, `<|channel>thought`, `<|thinking|>` and bracket-style reasoning blocks. | before repetition check and any downstream parsing |
| `loop` | `run_loop` reference wiring, `Model` protocol, `ScriptedModel` (canned turns, default) and `OllamaModel` (optional, import-guarded). | — |

`thread_injector.DEFAULT_TABLE_GUIDANCE` is keyed on Zeek/Suricata table
names (`conn`, `http`, `files`, `dns`, `suricata`) purely as a documented
example of the mapping's shape. Pass your own `table_guidance` in production.

## Design notes

- **Deterministic by construction.** Nothing in the package calls a model. A
  guard that needs an LLM to decide whether the LLM is looping is not a guard.
- **Injections are user messages.** Every diagnostic and nudge goes into the
  conversation as a `user` turn prefixed `HARNESS NOTE:`, so it is visible in
  traces and the model treats it as an instruction rather than as data.
- **Fire once.** Table guidance fires once per table, urgency and the no-tool
  nudge once per run. A guard that repeats itself becomes the noise it was
  meant to remove.
- **Duck-typed database access.** `LoopDetector` accepts any object with
  `execute(sql, params).fetchall()`; the tests use a ten-line fake.
- **Error strings are errors.** Many tool wrappers catch exceptions and return
  `"Error: ..."` with a success flag set. The loop detector classifies on the
  text, not the flag.

## Development

```bash
pip install -e '.[dev]'
pytest                 # 90 tests, offline
ruff check .
scripts/ip_scan.sh     # data-hygiene gate; must report zero HIGH/MED hits
```

`scripts/ip_scan.sh` greps every tracked text file for identifiers that would
mark a real environment (ticket ids, vendor console URLs, corporate hostname
schemes, e-mail addresses, private address ranges, home-directory paths) and
fails on any hit. Test fixtures use RFC 5737 documentation addresses and
invented hostnames so the gate needs no allowlist.

## License

Apache-2.0. See `LICENSE`.
