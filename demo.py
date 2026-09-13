#!/usr/bin/env python3
"""Three failure modes, before and after the guards. Runs with no model and no GPU.

    python demo.py                 # scripted turns (default)
    python demo.py --model qwen3:8b   # same scenarios, live Ollama (needs the [ollama] extra)

Every scenario runs the same reference loop twice, unguarded then guarded,
against a tiny in-memory "database" whose errors mimic DuckDB's wording.
All identifiers are invented; addresses use RFC 5737 documentation ranges.
"""

from __future__ import annotations

import argparse
from functools import partial

from karst.harness.guards import (
    LoopDetector,
    ModelTurn,
    ScriptedModel,
    ThreadInjector,
    ToolCall,
    detect_repetition,
    filter_tool_result,
    run_loop,
)

# --------------------------------------------------------------------------- fake database
COLUMNS = ["ts", "src_ip", "dst_ip", "dst_port", "proto", "bytes", "alert_category",
           "alert_severity", "alert_rule", "@rawstring", "@ingesttimestamp", "#repo"]
RAW = '{"event":"conn","payload":"' + "x" * 180 + '"}'


def _rows(n: int) -> list[list[str]]:
    return [
        [f"2026-01-0{1 + i % 9}T10:{i % 60:02d}:00Z", f"192.0.2.{10 + i % 40}", "198.51.100.7",
         str(443 if i % 3 else 8443), "tcp", str(1024 + 37 * i), "policy", str(1 + i % 3),
         f"rule-{i % 5}", RAW, "1735725600", "netflow"]
        for i in range(n)
    ]


TABLES = {"conn": _rows(120)}


class SchemaConnection:
    """Enough of a DB-API connection for LoopDetector's column/table suggestions."""

    def execute(self, sql: str, params=None):
        if "information_schema.columns" in sql:
            prefix = params[0].rstrip("%")
            rows = [(c,) for c in COLUMNS if c.startswith(prefix)]
        else:
            rows = [(t,) for t in TABLES]
        return type("Cur", (), {"fetchall": staticmethod(lambda: rows)})()


def query_database(sql: str) -> str:
    """A toy SQL tool: SELECT <cols|*> FROM <table>. Errors use DuckDB wording."""
    words = sql.replace(",", " ").split()
    if "FROM" not in [w.upper() for w in words]:
        return "Error: ParserException: expected FROM"
    table = words[[w.upper() for w in words].index("FROM") + 1].strip(";\"'")
    if table not in TABLES:
        return f'Error: CatalogException: Table with name "{table}" does not exist'
    selected = words[1:[w.upper() for w in words].index("FROM")]
    cols = COLUMNS if selected == ["*"] else selected
    for c in cols:
        if c not in COLUMNS:
            return f'Error: BinderException: Referenced column "{c}" not found'
    idx = [COLUMNS.index(c) for c in cols]
    header = " | ".join(cols)
    sep = "-+-".join("-" * len(c) for c in cols)
    body = "\n".join(" | ".join(r[i] for i in idx) for r in TABLES[table])
    return f"{header}\n{sep}\n{body}"


TOOLS = {"query_database": query_database}
TOOL_SPECS = [{
    "type": "function",
    "function": {
        "name": "query_database",
        "description": "Run a SQL SELECT against the incident database. Tables: conn.",
        "parameters": {"type": "object", "properties": {"sql": {"type": "string"}},
                       "required": ["sql"]},
    },
}]


def make_guards(names: tuple[str, ...]) -> dict:
    """Fresh guard instances per run (LoopDetector and ThreadInjector are stateful)."""
    all_guards = {
        "result_filter": lambda: partial(filter_tool_result, max_chars=1500),
        "loop_detector": lambda: LoopDetector(
            window_size=5, threshold=2, duckdb_connection=SchemaConnection()),
        "thread_injector": lambda: ThreadInjector(max_iterations=8),
        "repetition_detector": lambda: detect_repetition,
    }
    return {n: all_guards[n]() for n in names}


def _sql_turns(*sqls: str) -> list[ModelTurn]:
    return [ModelTurn(tool_calls=[ToolCall("query_database", {"sql": s})]) for s in sqls]


def _context_chars(result) -> int:
    return sum(len(m.get("content", "")) for m in result.messages)


def _run(model_factory, prompt: str, guards: tuple[str, ...]):
    return run_loop(model_factory(), [{"role": "user", "content": prompt}], TOOLS,
                    max_iterations=8, tool_specs=TOOL_SPECS, **make_guards(guards))


def _banner(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def _summary(label: str, r) -> None:
    print(f"  {label:<10} iterations={r.iterations}  tool_calls={r.tool_calls}  "
          f"context_chars={_context_chars(r):>6}  injections={len(r.injections)}  "
          f"end={r.termination_reason}")
    for inj in r.injections:
        print(f"    -> [{inj['type']} @ iter {inj['iteration']}] {inj['message']}")


SCENARIOS = [
    (
        "A. Context blow-up: a 12-column table with a raw-event blob on every row",
        ("result_filter",),
        "Summarise the network connections.",
        lambda: ScriptedModel([*_sql_turns("SELECT * FROM conn"),
                               ModelTurn(content="Most traffic is TCP/443 to one external host.")]),
    ),
    (
        "B. The retry loop: the same binder error, three times",
        ("loop_detector",),
        "Which alert types appear in conn?",
        lambda: ScriptedModel([*_sql_turns("SELECT alert.type FROM conn",
                                           "SELECT alert.type FROM conn",
                                           "SELECT alert.type FROM conn"),
                               ModelTurn(content="I could not retrieve the alert types.")]),
    ),
    (
        "C. Losing the thread: one query, then a premature stop",
        ("thread_injector", "repetition_detector"),
        "Investigate the connections and report what else should be checked.",
        lambda: ScriptedModel([*_sql_turns("SELECT src_ip, dst_ip, bytes FROM conn"),
                               ModelTurn(content="That is probably enough to conclude."),
                               ModelTurn(content="Follow-up: correlate with the files table.")]),
    ),
]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", help="Ollama model name; omit to replay scripted turns")
    ap.add_argument("--host", default=None, help="Ollama host (default: local server)")
    args = ap.parse_args()

    for title, guards, prompt, scripted in SCENARIOS:
        _banner(f"{title}\n   guard under test: {', '.join(guards)}")
        if args.model:
            from karst.harness.guards import OllamaModel

            def factory(m=args.model, h=args.host):
                return OllamaModel(m, host=h)
        else:
            factory = scripted
        before = _run(factory, prompt, ())
        after = _run(factory, prompt, guards)
        _summary("unguarded", before)
        _summary("guarded", after)
        saved = _context_chars(before) - _context_chars(after)
        if saved > 0:
            print(f"  context saved by guards: {saved} chars")
        print(f"  final answer (guarded): {after.final_response[:120]!r}")


if __name__ == "__main__":
    main()
