"""Unit tests for loop_detector.py.

The detector's schema lookups are duck-typed (``execute(sql, params)
.fetchall()``), so these tests use an in-memory fake connection rather than
a real database — the suite stays offline and dependency-free.
"""

from __future__ import annotations

from karst.harness.guards.loop_detector import LoopDetector


class _Cursor:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class _FakeConnection:
    """Minimal stand-in for a DB-API-shaped connection with information_schema."""

    def __init__(self, columns=(), tables=()):
        self.columns = list(columns)
        self.tables = list(tables)
        self.queries: list[tuple[str, list | None]] = []

    def execute(self, sql, params=None):
        self.queries.append((sql, params))
        if "information_schema.columns" in sql:
            prefix = params[0].rstrip("%")
            rows = [(c,) for c in sorted(self.columns) if c.startswith(prefix)][:10]
        elif "information_schema.tables" in sql:
            rows = [(t,) for t in sorted(self.tables)]
        else:
            rows = []
        return _Cursor(rows)


class TestNoTriggerOnDifferentErrors:
    def test_three_different_errors(self):
        detector = LoopDetector(window_size=5, threshold=2)

        r1 = detector.record(
            "query_database",
            'Error: BinderException: Referenced column "alert.type" not found',
            success=False,
        )
        r2 = detector.record(
            "query_database",
            'Error: BinderException: Referenced column "event.category" not found',
            success=False,
        )
        r3 = detector.record(
            "query_database",
            'Error: CatalogException: Table with name "events" does not exist',
            success=False,
        )

        assert r1 is None
        assert r2 is None
        assert r3 is None


class TestTriggerOnRepeatedError:
    def test_two_identical_binder_errors(self):
        detector = LoopDetector(window_size=5, threshold=2)

        error = 'Error: BinderException: Referenced column "alert.type" not found'

        r1 = detector.record("query_database", error, success=False)
        assert r1 is None

        r2 = detector.record("query_database", error, success=False)
        assert r2 is not None
        assert "alert.type" in r2
        assert "HARNESS NOTE" in r2
        assert "last 2 queries" in r2

    def test_table_not_found_repeated(self):
        detector = LoopDetector(window_size=5, threshold=2)

        error = 'Error: CatalogException: Table with name "events" does not exist'

        detector.record("query_database", error, success=False)
        r2 = detector.record("query_database", error, success=False)

        assert r2 is not None
        assert "events" in r2
        assert "does not exist" in r2


class TestColumnSuggestionWithSchema:
    def test_suggests_columns_from_schema(self):
        con = _FakeConnection(
            columns=["alert_category", "alert_severity", "alert_rule", "alert_action"],
        )

        detector = LoopDetector(window_size=5, threshold=2, duckdb_connection=con)

        error = 'Error: BinderException: Referenced column "alert.type" not found'
        detector.record("query_database", error, success=False)
        r2 = detector.record("query_database", error, success=False)

        assert r2 is not None
        assert "alert_category" in r2 or "alert_severity" in r2
        assert con.queries and "LIKE" in con.queries[0][0]


class TestSuccessfulResultsTracking:
    def test_success_dilutes_error_window(self):
        """Successes don't remove errors, but a small window pushes them out."""
        detector = LoopDetector(window_size=2, threshold=2)

        error = 'Error: BinderException: Referenced column "col" not found'
        detector.record("query_database", error, success=False)
        detector.record("query_database", "rows returned: 5", success=True)
        r = detector.record("query_database", error, success=False)

        # Window of 2: [success, error] — only 1 error in window
        assert r is None

    def test_interleaved_different_errors_no_trigger(self):
        detector = LoopDetector(window_size=3, threshold=2)

        e1 = 'Error: BinderException: Referenced column "a" not found'
        e2 = 'Error: BinderException: Referenced column "b" not found'

        detector.record("q", e1, success=False)
        detector.record("q", "ok", success=True)
        r = detector.record("q", e2, success=False)

        assert r is None


class TestSuccessTrueWithErrorString:
    """Tool wrappers return 'Error: ...' strings with success=True —
    the flag alone must not short-circuit classification."""

    def test_error_string_with_success_true_triggers(self):
        detector = LoopDetector(window_size=5, threshold=2)

        error = 'Error: BinderException: Referenced column "alert.type" not found'
        r1 = detector.record("query_database", error, success=True)
        assert r1 is None

        r2 = detector.record("query_database", error, success=True)
        assert r2 is not None
        assert "HARNESS NOTE" in r2
        assert "alert.type" in r2

    def test_genuine_success_still_clears(self):
        detector = LoopDetector(window_size=5, threshold=2)
        r = detector.record("query_database", "rows returned: 5", success=True)
        assert r is None

    def test_binder_error_text_without_error_prefix_detected(self):
        detector = LoopDetector(window_size=5, threshold=2)
        error = 'Binder Error: Referenced column "alert.type" not found'
        detector.record("query_database", error, success=True)
        r2 = detector.record("query_database", error, success=True)
        assert r2 is not None


class TestGroupByBinderError:
    """Repeated GROUP BY binder errors coach `GROUP BY ALL`."""

    GROUPBY_ERROR = (
        'Error: Binder Error: column "computer_name" must appear in the '
        "GROUP BY clause or must be part of an aggregate function."
    )

    def test_two_groupby_errors_success_true_coach_group_by_all(self):
        detector = LoopDetector(window_size=5, threshold=2)

        r1 = detector.record("query_database", self.GROUPBY_ERROR, success=True)
        assert r1 is None

        r2 = detector.record("query_database", self.GROUPBY_ERROR, success=True)
        assert r2 is not None
        assert "GROUP BY ALL" in r2
        assert "computer_name" in r2

    def test_groupby_not_misclassified_as_missing_column(self):
        detector = LoopDetector(window_size=5, threshold=2)
        detector.record("query_database", self.GROUPBY_ERROR, success=False)
        r2 = detector.record("query_database", self.GROUPBY_ERROR, success=False)
        assert r2 is not None
        assert "does not exist" not in r2


class TestUnknownFunction:
    """ClickHouse/Postgres function names coach DuckDB idioms."""

    FN_ERROR = (
        "Error: Catalog Error: Scalar Function with name "
        '"JSONExtractString" does not exist!'
    )

    def test_two_unknown_function_errors_coach_json_extract_string(self):
        detector = LoopDetector(window_size=5, threshold=2)

        r1 = detector.record("query_database", self.FN_ERROR, success=True)
        assert r1 is None

        r2 = detector.record("query_database", self.FN_ERROR, success=True)
        assert r2 is not None
        assert "json_extract_string" in r2
        assert "DuckDB" in r2

    def test_bare_function_not_exist_message(self):
        detector = LoopDetector(window_size=5, threshold=2)
        error = 'Error: Catalog Error: Function "jsonextractstring" does not exist'
        detector.record("query_database", error, success=False)
        r2 = detector.record("query_database", error, success=False)
        assert r2 is not None
        assert "json_extract_string" in r2


class TestThresholdConfigurable:
    def test_threshold_three(self):
        detector = LoopDetector(window_size=5, threshold=3)

        error = 'Error: BinderException: Referenced column "col" not found'

        r1 = detector.record("q", error, success=False)
        r2 = detector.record("q", error, success=False)
        assert r1 is None
        assert r2 is None

        r3 = detector.record("q", error, success=False)
        assert r3 is not None
        assert "last 3 queries" in r3


class TestWindowSize:
    def test_old_errors_slide_out(self):
        detector = LoopDetector(window_size=2, threshold=2)

        error = 'Error: BinderException: Referenced column "x" not found'

        detector.record("q", error, success=False)
        detector.record("q", "ok", success=True)
        r = detector.record("q", error, success=False)

        assert r is None


class TestSuggestTablesScopedToCurrentCatalog:
    """_suggest_tables backs the "Table X does not exist" diagnostic. When a
    second catalog is ATTACHed and its base table is mirrored by a view in
    the main catalog, information_schema.tables lists the name twice unless
    the query is scoped to the current catalog. The fake connection cannot
    reproduce ATTACH semantics, so this test pins the scoping predicate in
    the SQL and the once-per-name shape of the resulting note.
    """

    def test_query_is_catalog_scoped_and_names_appear_once(self):
        con = _FakeConnection(tables=["events", "unified_parsed_events"])

        detector = LoopDetector(
            window_size=5, threshold=2, duckdb_connection=con,
        )

        error = (
            'Error: CatalogException: Table with name "eventz" does not exist'
        )
        detector.record("query_database", error, success=False)
        note = detector.record("query_database", error, success=False)

        assert note is not None
        sql = con.queries[-1][0]
        assert "table_catalog = current_database()" in sql
        assert "table_schema = 'main'" in sql
        # Parse the "Available tables: X, Y." fragment out of the note.
        tables_part = note.split("Available tables: ")[1]
        tables_part = tables_part.split(".")[0]
        tokens = [t.strip() for t in tables_part.split(",")]
        assert tokens.count("events") == 1
        assert tokens.count("unified_parsed_events") == 1


class TestSuggestTablesAttachedDedupLive:
    """The real ATTACH scenario, run only when DuckDB happens to be installed.

    Not a dependency of this package; the fake-connection test above pins
    the SQL shape, this one proves the predicate against DuckDB semantics.
    """

    def test_attached_view_and_base_appear_once(self, tmp_path):
        duckdb = __import__("pytest").importorskip("duckdb")
        side_path = tmp_path / "side.duckdb"
        other = duckdb.connect(str(side_path))
        other.execute("CREATE TABLE events (id INTEGER)")
        other.close()

        con = duckdb.connect(":memory:")
        con.execute(f"ATTACH '{side_path}' AS side_db (READ_ONLY)")
        con.execute("CREATE VIEW events AS SELECT * FROM side_db.events")
        con.execute("CREATE TABLE parsed_events (event_id INTEGER)")

        detector = LoopDetector(window_size=5, threshold=2, duckdb_connection=con)
        error = 'Error: CatalogException: Table with name "eventz" does not exist'
        detector.record("query_database", error, success=False)
        note = detector.record("query_database", error, success=False)
        con.close()

        assert note is not None
        tables_part = note.split("Available tables: ")[1].split(".")[0]
        tokens = [t.strip() for t in tables_part.split(",")]
        assert tokens.count("events") == 1
        assert tokens.count("parsed_events") == 1
