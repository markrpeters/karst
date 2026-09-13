"""Tool result filtering — column exclusion notes and size truncation.

Why this exists: a tool-calling agent that runs SQL against event logs will
happily pull back a 50-column table with a multi-kilobyte raw-event string on
every row. Left alone, one such result fills the context window and the model
loses whatever it was investigating. This module trims tool results before
they are appended to the conversation. Two mechanisms: a size cap that
truncates at row boundaries for tabular output (header and separator are
kept, no row is cut mid-way) and at line boundaries otherwise, and a note
that flags known high-noise metadata columns when they appear in a result.
The truncation guidance deliberately says "analyze this sample" rather than
"refine your query" — the latter wording was observed to send small local
models into a re-query loop instead of reasoning over the rows they had.
"""

from __future__ import annotations

# Metadata columns that log-search platforms append to every row (the raw
# event string, ingest timestamp, repo/type bookkeeping). They dwarf the
# forensic fields and carry nothing the model can reason about. Override
# per deployment via ``excluded_columns``.
_DEFAULT_EXCLUDED = [
    "@rawstring", "@ingesttimestamp",
    "#repo", "#type", "@timestamp.nanos", "@timezone",
]


def filter_tool_result(
    result: str,
    tool_name: str,
    *,
    excluded_columns: list[str] | None = None,
    max_chars: int = 2000,
) -> str:
    """Filter a tool result before injecting into agent context.

    Args:
        result: Raw tool result string.
        tool_name: Name of the tool that produced the result.
        excluded_columns: Column names to flag if present. Defaults to
            the ``@``/``#`` metadata columns a log-search platform appends
            to every row.
        max_chars: Maximum result size before truncation.

    Returns:
        Filtered result string, potentially truncated with guidance.
    """
    if not result:
        return result

    cols = excluded_columns if excluded_columns is not None else _DEFAULT_EXCLUDED
    found = _detect_excluded_columns(result, cols)

    prefix = ""
    if found:
        col_list = ", ".join(found)
        prefix = (
            f"[HARNESS: High-noise columns detected in results: {col_list}. "
            "These columns contain metadata that is not relevant to your "
            "investigation. Focus on the forensic fields instead.]\n\n"
        )

    total = len(result)
    if total > max_chars:
        truncated, suffix = _smart_truncate(result, max_chars, total)
        return prefix + truncated + suffix

    return prefix + result if prefix else result


def _smart_truncate(result: str, max_chars: int, total_chars: int) -> tuple[str, str]:
    """Truncate result at row/line boundaries with analysis-first guidance."""
    lines = result.split("\n")

    if (len(lines) >= 3
            and " | " in lines[0]
            and _is_separator_line(lines[1])):
        return _truncate_tabular(lines, max_chars, total_chars)

    return _truncate_lines(lines, max_chars, total_chars)


def _is_separator_line(line: str) -> bool:
    """Check if a line is a DuckDB table separator (dashes and plus signs)."""
    stripped = line.strip()
    return bool(stripped) and all(c in "-+ |" for c in stripped)


def _truncate_tabular(
    lines: list[str],
    max_chars: int,
    total_chars: int,
) -> tuple[str, str]:
    """Truncate tabular DuckDB output at row boundaries, preserving header."""
    header = lines[0]
    separator = lines[1]
    data_lines = lines[2:]

    db_summary = ""
    if data_lines and data_lines[-1].startswith("... ("):
        db_summary = data_lines.pop()

    total_data_rows = len(data_lines)

    kept = [header, separator]
    used = len(header) + 1 + len(separator) + 1
    rows_kept = 0

    for line in data_lines:
        line_cost = len(line) + 1
        if used + line_cost > max_chars:
            break
        kept.append(line)
        used += line_cost
        rows_kept += 1

    if db_summary:
        kept.append(db_summary)

    suffix = (
        f"\n\n[HARNESS: Showing {rows_kept} of {total_data_rows} data rows "
        f"({total_chars} chars total). "
        "Analyze this sample or narrow with WHERE/column selection.]"
    )
    return "\n".join(kept), suffix


def _truncate_lines(
    lines: list[str],
    max_chars: int,
    total_chars: int,
) -> tuple[str, str]:
    """Truncate non-tabular output at line boundaries."""
    kept: list[str] = []
    used = 0

    for line in lines:
        line_cost = len(line) + 1
        if used + line_cost > max_chars:
            break
        kept.append(line)
        used += line_cost

    if not kept:
        truncated = lines[0][:max_chars] if lines else ""
        suffix = (
            f"\n\n[HARNESS: Result truncated ({total_chars} chars total, "
            f"showing first {len(truncated)}). "
            "Analyze available content or narrow your request.]"
        )
        return truncated, suffix

    suffix = (
        f"\n\n[HARNESS: Result truncated ({total_chars} chars total, "
        f"showing first {len(kept)} lines). "
        "Analyze available content or narrow your request.]"
    )
    return "\n".join(kept), suffix


def _detect_excluded_columns(result: str, excluded: list[str]) -> list[str]:
    """Return which excluded column names appear in the result text."""
    return [col for col in excluded if col in result]
