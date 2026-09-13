"""Investigation thread injection — guided follow-up prompts.

Why this exists: once a few tool results have landed in context, a local
model tends to forget what it was investigating — it stops calling tools and
summarizes whatever it last saw, or it keeps querying one table and never
pivots to the related ones. This module watches loop progress and injects
short guidance messages on three triggers: the first query against a known
table (suggest the correlating tables to look at next), approaching the
iteration ceiling (start concluding), and an iteration with no tool calls on
a non-final turn (remind the model its tools are still available). Each
trigger fires at most once per table or per run, so the guidance never
becomes its own noise.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

_FROM_TABLE_RE = re.compile(r"\bFROM\s+[\"']?(\w+)[\"']?", re.IGNORECASE)

# EXAMPLE guidance keyed on Zeek/Suricata table names (conn, http, files, dns
# from Zeek; suricata for IDS alerts). It documents the shape of the mapping
# — table name -> what to correlate next — and is the default only because
# that vocabulary is open and widely recognised. Pass ``table_guidance`` to
# ``ThreadInjector`` with your own schema's table names in production.
DEFAULT_TABLE_GUIDANCE: dict[str, str] = {
    "suricata": (
        "You found Suricata IDS alerts. Now correlate: query conn, http, "
        "and files tables using community_id or the IP pair to assess "
        "associated network activity and file transfers."
    ),
    "conn": (
        "You have connection data. Look for associated alerts in the "
        "suricata table and check the files table for any file "
        "transfers involving the same connection UIDs or IP pairs."
    ),
    "http": (
        "You have HTTP transaction data. Check if any URIs are associated "
        "with known malware C2 patterns, and correlate with conn table "
        "for connection duration and byte counts."
    ),
    "files": (
        "You found file transfer data. Check the MIME types and filenames "
        "for suspicious content, and correlate with conn and http tables "
        "to identify the source connection."
    ),
    "dns": (
        "You have DNS query data. Look for domain generation algorithm "
        "(DGA) patterns, tunneling indicators (high query volume, TXT "
        "records), and correlate queried domains with conn table "
        "destination IPs."
    ),
}


class InjectionEvent(BaseModel):
    trigger: str
    iteration: int
    message: str
    table: str | None = None


class ThreadInjector:
    """Inject investigation guidance messages into the agent loop."""

    def __init__(
        self,
        max_iterations: int,
        *,
        urgency_threshold: float = 0.75,
        table_guidance: dict[str, str] | None = None,
    ) -> None:
        self._max_iterations = max_iterations
        self._urgency_threshold = urgency_threshold
        self._table_guidance = table_guidance or DEFAULT_TABLE_GUIDANCE
        self._tables_seen: set[str] = set()
        self._urgency_injected = False
        self._nudge_injected = False
        self._events: list[InjectionEvent] = []

    @property
    def events(self) -> list[InjectionEvent]:
        return list(self._events)

    def check(
        self,
        iteration: int,
        had_tool_calls: bool,
        sql: str | None = None,
    ) -> list[str]:
        """Check all triggers and return injection messages for this iteration.

        Args:
            iteration: Current loop iteration (0-based).
            had_tool_calls: Whether the model made tool calls this iteration.
            sql: SQL query string from the most recent tool call, if any.

        Returns:
            List of injection message strings (0-2 messages per call).
        """
        messages: list[str] = []

        if sql and had_tool_calls:
            msg = self._check_data_retrieval(sql, iteration)
            if msg:
                messages.append(msg)

        msg = self._check_iteration_threshold(iteration)
        if msg:
            messages.append(msg)

        if not had_tool_calls:
            msg = self._check_no_tool_call(iteration)
            if msg:
                messages.append(msg)

        return messages

    def _check_data_retrieval(self, sql: str, iteration: int) -> str | None:
        """Inject correlation guidance after successful query on a known table."""
        tables = _extract_table_names(sql)
        for table in tables:
            table_lower = table.lower()
            if table_lower in self._tables_seen:
                continue
            if table_lower in self._table_guidance:
                self._tables_seen.add(table_lower)
                guidance = self._table_guidance[table_lower]
                msg = f"HARNESS NOTE: {guidance}"
                self._events.append(InjectionEvent(
                    trigger="data_retrieval",
                    iteration=iteration,
                    message=msg,
                    table=table_lower,
                ))
                return msg
        return None

    def _check_iteration_threshold(self, iteration: int) -> str | None:
        """Inject urgency when approaching the iteration ceiling."""
        if self._urgency_injected:
            return None

        threshold_iteration = int(self._max_iterations * self._urgency_threshold)
        if iteration < threshold_iteration:
            return None

        self._urgency_injected = True
        msg = (
            f"HARNESS NOTE: You have used {iteration + 1} of "
            f"{self._max_iterations} iterations. Focus on forming your "
            "conclusion with the evidence gathered so far."
        )
        self._events.append(InjectionEvent(
            trigger="iteration_threshold",
            iteration=iteration,
            message=msg,
        ))
        return msg

    def _check_no_tool_call(self, iteration: int) -> str | None:
        """Nudge the model to use tools on non-final iterations (fires once)."""
        if self._nudge_injected:
            return None
        if iteration >= self._max_iterations - 1:
            return None

        self._nudge_injected = True
        msg = (
            "HARNESS NOTE: You can still use your tools to gather more "
            "evidence before concluding. Have you checked all relevant "
            "data sources?"
        )
        self._events.append(InjectionEvent(
            trigger="no_tool_call",
            iteration=iteration,
            message=msg,
        ))
        return msg


def _extract_table_names(sql: str) -> list[str]:
    """Extract table names from FROM clauses in a SQL query."""
    return _FROM_TABLE_RE.findall(sql)
