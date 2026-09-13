"""Loop detection — repeated error diagnosis and correction injection.

Why this exists: when a SQL tool call fails, a small local model will often
re-issue the same broken query, verbatim, for the rest of its iteration
budget — the error text is in its context, but it does not read it as an
instruction to change course. This module keeps a sliding window of error
signatures (exception type + the column, table or function that failed) and,
once the same signature repeats past a threshold, injects a diagnostic
message that names the problem and, when a database connection is supplied,
lists the columns or tables that actually exist. The classifier targets
DuckDB error text (binder, catalog and unknown-function errors); the
connection is duck-typed (``execute(sql, params).fetchall()``) so any
DB-API-shaped object works.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Any, NamedTuple


class ErrorSignature(NamedTuple):
    exception_type: str
    failed_entity: str


_BINDER_RE = re.compile(
    r'Binder(?:Exception)?: .*?(?:column|"([^"]+)")',
    re.IGNORECASE,
)
# GROUP BY binder errors — 'column "X" must appear in the GROUP BY clause'.
_GROUPBY_RE = re.compile(
    r'column "([^"]+)" must appear in the GROUP BY clause',
    re.IGNORECASE,
)
# Unknown-function catalog errors — catches ClickHouse/Postgres idioms
# like JSONExtractString ('Scalar Function with name X does not exist').
_UNKNOWN_FN_RE = re.compile(
    r'(?:Scalar |Aggregate |Macro )?Function (?:with name )?"?(\w+)"? does not exist',
    re.IGNORECASE,
)
_COLUMN_NOT_FOUND_RE = re.compile(
    r'Referenced column "([^"]+)" not found',
    re.IGNORECASE,
)
_TABLE_NOT_FOUND_RE = re.compile(
    r'Table (?:with name )?"?(\w+)"? does not exist',
    re.IGNORECASE,
)
_CATALOG_RE = re.compile(
    r'Catalog(?:Exception)?: .*?Table.*?"?(\w+)"?',
    re.IGNORECASE,
)


class LoopDetector:
    """Track tool results and detect repeated error patterns."""

    def __init__(
        self,
        window_size: int = 5,
        threshold: int = 2,
        duckdb_connection: Any | None = None,
    ) -> None:
        self._history: deque[ErrorSignature | None] = deque(maxlen=window_size)
        self._threshold = threshold
        self._con = duckdb_connection

    def record(
        self,
        tool_name: str,
        result: str,
        success: bool,
    ) -> str | None:
        """Record a tool result and return a diagnostic injection if needed.

        Args:
            tool_name: Name of the tool that was called.
            result: The tool result string (may contain error messages).
            success: Whether the tool execution succeeded.

        Returns:
            Diagnostic injection message if a repeated error pattern is
            detected, otherwise None.
        """
        # Many tool wrappers catch exceptions and return "Error: ..." STRINGS
        # with success=True (the tool call itself succeeded), so trusting the
        # flag alone makes the detector blind to every real query failure.
        # A successful call whose result reads as an error still gets
        # classified.
        if success and not _looks_like_error(result):
            self._history.append(None)
            return None

        sig = self._classify_error(result)
        if sig is None:
            self._history.append(None)
            return None

        self._history.append(sig)

        count = sum(1 for s in self._history if s == sig)
        if count < self._threshold:
            return None

        return self._build_diagnostic(sig, count)

    def _classify_error(self, error_text: str) -> ErrorSignature | None:
        """Extract an error signature from tool error text."""
        # GROUP BY errors are Binder errors too — classify them first
        # so they don't fall through to the column-not-found suggestion path.
        m = _GROUPBY_RE.search(error_text)
        if m:
            return ErrorSignature("GroupByBinderError", m.group(1))

        m = _UNKNOWN_FN_RE.search(error_text)
        if m:
            return ErrorSignature("UnknownFunction", m.group(1))

        m = _COLUMN_NOT_FOUND_RE.search(error_text)
        if m:
            return ErrorSignature("BinderException", m.group(1))

        m = _BINDER_RE.search(error_text)
        if m and m.group(1):
            return ErrorSignature("BinderException", m.group(1))

        m = _TABLE_NOT_FOUND_RE.search(error_text)
        if m:
            return ErrorSignature("CatalogException", m.group(1))

        m = _CATALOG_RE.search(error_text)
        if m:
            return ErrorSignature("CatalogException", m.group(1))

        return None

    def _build_diagnostic(self, sig: ErrorSignature, count: int) -> str:
        """Build a diagnostic injection message for a repeated error."""
        if sig.exception_type == "GroupByBinderError":
            return (
                f"HARNESS NOTE: Your last {count} queries failed with the same "
                f"GROUP BY binder error — column '{sig.failed_entity}' is "
                "selected but not grouped. Add every non-aggregated column to "
                "GROUP BY or use `GROUP BY ALL`."
            )

        if sig.exception_type == "UnknownFunction":
            return (
                f"HARNESS NOTE: Your last {count} queries called "
                f"'{sig.failed_entity}', which does not exist — this is DuckDB: "
                "use `json_extract_string(col, '$.key')` for JSON field "
                "extraction. ClickHouse/Postgres function names "
                "(JSONExtractString, etc.) are not available."
            )

        if sig.exception_type == "BinderException":
            suggestions = self._suggest_columns(sig.failed_entity)
            if suggestions:
                return (
                    f"HARNESS NOTE: Your last {count} queries failed with the "
                    f"same error — column '{sig.failed_entity}' does not exist. "
                    f"Available columns matching '{_column_prefix(sig.failed_entity)}': "
                    f"{', '.join(suggestions)}. "
                    "Please revise your query using one of these columns."
                )
            return (
                f"HARNESS NOTE: Your last {count} queries failed with the "
                f"same error — column '{sig.failed_entity}' does not exist. "
                "Use the describe_table or list_tables tool to see available "
                "columns before retrying."
            )

        if sig.exception_type == "CatalogException":
            tables = self._suggest_tables()
            if tables:
                return (
                    f"HARNESS NOTE: Your last {count} queries referenced table "
                    f"'{sig.failed_entity}' which does not exist. "
                    f"Available tables: {', '.join(tables)}. "
                    "Please use one of these table names."
                )
            return (
                f"HARNESS NOTE: Your last {count} queries referenced table "
                f"'{sig.failed_entity}' which does not exist. "
                "Use the list_tables tool to see available tables."
            )

        return (
            f"HARNESS NOTE: Your last {count} queries failed with "
            f"{sig.exception_type} on '{sig.failed_entity}'. "
            "Try a different approach."
        )

    def _suggest_columns(self, failed_column: str) -> list[str]:
        """Query DuckDB for columns matching the failed column's prefix."""
        if self._con is None:
            return []

        prefix = _column_prefix(failed_column)
        try:
            rows = self._con.execute(
                "SELECT DISTINCT column_name FROM information_schema.columns "
                "WHERE column_name LIKE ? ORDER BY column_name LIMIT 10",
                [f"{prefix}%"],
            ).fetchall()
            return [r[0] for r in rows]
        except Exception:
            return []

    def _suggest_tables(self) -> list[str]:
        """Query DuckDB for available table names."""
        if self._con is None:
            return []

        try:
            # Filter table_catalog = current_database() so ATTACHed catalogs
            # don't add duplicate suggestions.
            rows = self._con.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'main' "
                "AND table_catalog = current_database() "
                "ORDER BY table_name",
            ).fetchall()
            return [r[0] for r in rows]
        except Exception:
            return []


_ERROR_MARKERS = ("Binder Error", "BinderException", "Catalog Error")


def _looks_like_error(result: str) -> bool:
    """True when a tool result string reads as an error despite success=True.

    Shell/analyst tools convert exceptions into "Error: ..." result strings and
    report success=True (the tool call completed); DuckDB error classes also
    surface as "Binder Error"/"Catalog Error" text inside results.
    """
    text = result or ""
    if text.lstrip().startswith("Error:"):
        return True
    return any(marker in text for marker in _ERROR_MARKERS)


def _column_prefix(column_name: str) -> str:
    """Extract the prefix of a dotted column name (e.g. 'alert.type' -> 'alert')."""
    if "." in column_name:
        return column_name.rsplit(".", 1)[0]
    return column_name
