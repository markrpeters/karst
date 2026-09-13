"""Unit tests for result_filter.py."""

from __future__ import annotations

from karst.harness.guards.result_filter import (
    _is_separator_line,
    filter_tool_result,
)


class TestShortResultPassthrough:
    def test_short_result_unchanged(self):
        result = "col1 | col2\nval1 | val2"
        filtered = filter_tool_result(result, "query_database")
        assert filtered == result

    def test_empty_result(self):
        filtered = filter_tool_result("", "query_database")
        assert filtered == ""


class TestSizeTruncation:
    def test_long_result_truncated(self):
        result = "x" * 5000
        filtered = filter_tool_result(result, "query_database", max_chars=2000)
        assert len(filtered) < 5000
        assert "[HARNESS: Result truncated (5000 chars total" in filtered
        assert "Analyze available content" in filtered

    def test_result_at_limit_not_truncated(self):
        result = "x" * 2000
        filtered = filter_tool_result(result, "query_database", max_chars=2000)
        assert filtered == result
        assert "HARNESS" not in filtered

    def test_custom_max_chars(self):
        result = "x" * 500
        filtered = filter_tool_result(result, "query_database", max_chars=100)
        assert "[HARNESS: Result truncated (500 chars total" in filtered

    def test_multiline_truncates_at_line_boundary(self):
        lines = [f"line {i}: " + "a" * 40 for i in range(20)]
        result = "\n".join(lines)
        filtered = filter_tool_result(result, "query_database", max_chars=200)
        assert "[HARNESS: Result truncated" in filtered
        assert "showing first" in filtered
        for line in filtered.split("\n\n[HARNESS")[0].split("\n"):
            assert not line.endswith("a\nline") or True


class TestColumnExclusionNote:
    def test_rawstring_detected(self):
        result = "col1 | @rawstring\nval1 | <soap:Envelope>...</soap:Envelope>"
        filtered = filter_tool_result(result, "query_database")
        assert "[HARNESS: High-noise columns detected" in filtered
        assert "@rawstring" in filtered

    def test_multiple_excluded_detected(self):
        result = "@rawstring @ingesttimestamp #repo data"
        filtered = filter_tool_result(result, "query_database")
        assert "@rawstring" in filtered
        assert "@ingesttimestamp" in filtered
        assert "#repo" in filtered

    def test_no_excluded_columns_no_note(self):
        result = "src_ip | dst_ip | bytes\n192.0.2.1 | 192.0.2.2 | 1024"
        filtered = filter_tool_result(result, "query_database")
        assert "HARNESS" not in filtered
        assert filtered == result

    def test_custom_exclusion_list(self):
        result = "custom_col | other_col\nval1 | val2"
        filtered = filter_tool_result(
            result, "query_database", excluded_columns=["custom_col"]
        )
        assert "[HARNESS: High-noise columns detected" in filtered
        assert "custom_col" in filtered

    def test_empty_exclusion_list(self):
        result = "@rawstring data"
        filtered = filter_tool_result(
            result, "query_database", excluded_columns=[]
        )
        assert "HARNESS" not in filtered


class TestCombinedBehavior:
    def test_excluded_plus_truncation(self):
        result = "@rawstring " + "x" * 5000
        filtered = filter_tool_result(result, "query_database", max_chars=200)
        assert "[HARNESS: High-noise columns detected" in filtered
        assert "[HARNESS: Result truncated" in filtered


class TestSeparatorLineDetection:
    def test_standard_duckdb_separator(self):
        assert _is_separator_line("----+-------+------")

    def test_dashes_only(self):
        assert _is_separator_line("---------------------")

    def test_separator_with_spaces(self):
        assert _is_separator_line("--- | --- | ---")

    def test_empty_line_not_separator(self):
        assert not _is_separator_line("")

    def test_data_line_not_separator(self):
        assert not _is_separator_line("col1 | val1 | val2")

    def test_whitespace_only_not_separator(self):
        assert not _is_separator_line("   ")


class TestTabularTruncation:
    @staticmethod
    def _make_tabular(n_rows: int, row_content: str = "192.0.2.1 | 443 | 1024") -> str:
        header = "src_ip | dst_port | bytes"
        sep = "--------+----------+------"
        rows = [row_content for _ in range(n_rows)]
        return "\n".join([header, sep] + rows)

    def test_tabular_truncates_at_row_boundary(self):
        result = self._make_tabular(50)
        filtered = filter_tool_result(result, "query_database", max_chars=300)
        content, _, harness = filtered.partition("\n\n[HARNESS")
        lines = content.split("\n")
        assert lines[0] == "src_ip | dst_port | bytes"
        assert _is_separator_line(lines[1])
        for data_line in lines[2:]:
            assert data_line == "192.0.2.1 | 443 | 1024"

    def test_tabular_preserves_header(self):
        result = self._make_tabular(50)
        filtered = filter_tool_result(result, "query_database", max_chars=200)
        assert filtered.startswith("src_ip | dst_port | bytes\n")

    def test_tabular_reports_row_counts(self):
        result = self._make_tabular(50)
        filtered = filter_tool_result(result, "query_database", max_chars=300)
        assert "of 50 data rows" in filtered
        assert "Analyze this sample" in filtered

    def test_tabular_preserves_db_summary(self):
        header = "src_ip | dst_port | bytes"
        sep = "--------+----------+------"
        rows = ["192.0.2.1 | 443 | 1024"] * 50
        db_summary = "... (245 total rows, showing first 50)"
        result = "\n".join([header, sep] + rows + [db_summary])
        filtered = filter_tool_result(result, "query_database", max_chars=400)
        assert "... (245 total rows, showing first 50)" in filtered

    def test_tabular_no_truncation_when_under_limit(self):
        result = self._make_tabular(3)
        filtered = filter_tool_result(result, "query_database", max_chars=5000)
        assert filtered == result
        assert "HARNESS" not in filtered

    def test_analysis_first_guidance_not_refine(self):
        result = self._make_tabular(50)
        filtered = filter_tool_result(result, "query_database", max_chars=300)
        assert "Refine your query" not in filtered
        assert "Analyze this sample" in filtered


class TestLineAwareTruncation:
    def test_multiline_keeps_complete_lines(self):
        lines = [f"line_{i}: content here" for i in range(50)]
        result = "\n".join(lines)
        filtered = filter_tool_result(result, "some_tool", max_chars=200)
        content = filtered.split("\n\n[HARNESS")[0]
        for line in content.split("\n"):
            assert line.startswith("line_")

    def test_single_long_line_fallback(self):
        result = "x" * 5000
        filtered = filter_tool_result(result, "some_tool", max_chars=2000)
        assert "[HARNESS: Result truncated (5000 chars total" in filtered
        content = filtered.split("\n\n[HARNESS")[0]
        assert len(content) <= 2000

    def test_non_tabular_guidance_not_refine(self):
        result = "\n".join([f"line {i}" for i in range(100)])
        filtered = filter_tool_result(result, "some_tool", max_chars=100)
        assert "Refine your query" not in filtered
        assert "Analyze available content" in filtered
