"""Unit tests for repetition_detector.py.

All hostnames and addresses in these fixtures are invented; IPs use the
RFC 5737 documentation ranges.
"""

from __future__ import annotations

from agent_loop_guards.repetition_detector import (
    RepetitionResult,
    detect_repetition,
)


class TestNormalText:
    def test_normal_text_passes_through(self):
        text = (
            "The investigation revealed lateral movement from 192.0.2.3 to 192.0.2.4. "
            "Process cmd.exe spawned powershell.exe with encoded arguments. "
            "Network connections to external C2 at 203.0.113.50 were observed."
        )
        result = detect_repetition(text)
        assert not result.is_degenerate
        assert result.cleaned_text == text
        assert result.pattern_type == ""
        assert result.repeat_count == 0

    def test_empty_text(self):
        result = detect_repetition("")
        assert not result.is_degenerate
        assert result.cleaned_text == ""

    def test_short_text(self):
        result = detect_repetition("hello world")
        assert not result.is_degenerate
        assert result.cleaned_text == "hello world"


class TestPhraseStutter:
    def test_table_row_stutter(self):
        """Table-row stutter as emitted by a 20B mixture-of-experts model in a local bench run."""
        row = "| HOST-A | 192.0.2.3 | admin | lateral_movement |"
        text = "## Findings\n" + "\n".join([row] * 12)
        result = detect_repetition(text)
        assert result.is_degenerate
        assert result.pattern_type == "phrase"
        assert result.repeat_count >= 4
        assert "truncated" in result.cleaned_text
        assert "degenerate repetition detected" in result.cleaned_text

    def test_repeated_analysis_block(self):
        block = "The host WORKSTATION-01 exhibited anomalous behavior with outbound connections to 203.0.113.50. "
        text = block * 8
        result = detect_repetition(text)
        assert result.is_degenerate
        assert result.repeat_count >= 4

    def test_below_threshold_not_flagged(self):
        block = "The host WORKSTATION-01 exhibited anomalous behavior with outbound connections to 203.0.113.50. "
        text = block * 2
        result = detect_repetition(text, max_phrase_repeats=3)
        assert not result.is_degenerate

    def test_short_phrase_not_flagged(self):
        """Very short repeated tokens (< 4 words per unit) should not trigger phrase detection."""
        text = "OK. " * 20
        result = detect_repetition(text, min_phrase_chars=40, max_line_repeats=100, max_sentence_repeats=100)
        assert not result.is_degenerate


class TestLineRepetition:
    def test_identical_table_rows(self):
        header = "| Host | IP | User | Action |"
        sep = "|------|-----|------|--------|"
        row = "| HOST-B | 192.0.2.1 | SYSTEM | kerberos_tgt |"
        text = header + "\n" + sep + "\n" + "\n".join([row] * 8)
        result = detect_repetition(text, max_line_repeats=5)
        assert result.is_degenerate
        assert result.pattern_type in ("phrase", "line")
        assert result.repeat_count >= 4
        assert "truncated" in result.cleaned_text

    def test_line_detection_without_phrase(self):
        """When phrase detector doesn't fire, line detector catches repeats."""
        row = "| A | B |"
        text = "\n".join([row] * 8)
        result = detect_repetition(text, max_line_repeats=5, min_phrase_chars=200)
        assert result.is_degenerate
        assert result.pattern_type == "line"

    def test_below_threshold_lines_pass(self):
        row = "| HOST-B | 192.0.2.1 | SYSTEM | kerberos_tgt |"
        text = "\n".join([row] * 4)
        result = detect_repetition(text, max_line_repeats=5)
        assert not result.is_degenerate

    def test_empty_lines_not_counted(self):
        """Blank lines between content shouldn't trigger line repetition."""
        text = "Finding 1\n\n\n\n\n\n\n\nFinding 2"
        result = detect_repetition(text, max_line_repeats=5)
        assert not result.is_degenerate


class TestSentenceRepetition:
    def test_sentence_repeated_four_times(self):
        unique = "The investigation identified lateral movement across the network segment. "
        repeated = "The attacker used pass-the-hash techniques to authenticate to remote systems. "
        text = unique + (repeated * 5) + unique
        result = detect_repetition(text, max_sentence_repeats=3)
        assert result.is_degenerate
        assert result.pattern_type in ("phrase", "sentence")
        assert result.repeat_count >= 4

    def test_sentence_detection_without_phrase(self):
        """When phrase detector doesn't fire, sentence detector catches repeats."""
        unique = "Introduction paragraph with enough content. "
        repeated = "The attacker used pass-the-hash techniques to authenticate to remote systems. "
        text = unique + (repeated * 5) + unique
        result = detect_repetition(text, max_sentence_repeats=3, min_phrase_chars=200)
        assert result.is_degenerate
        assert result.pattern_type == "sentence"

    def test_below_threshold_sentences_pass(self):
        sentence = "The attacker used pass-the-hash techniques to authenticate to remote systems. "
        text = "Introduction. " + sentence * 2 + "Conclusion."
        result = detect_repetition(text, max_sentence_repeats=3)
        assert not result.is_degenerate

    def test_short_sentences_not_counted(self):
        """Sentences under 50 chars should not be counted by sentence detector."""
        text = "This is fine. " * 5
        result = detect_repetition(text, max_sentence_repeats=3, min_phrase_chars=200)
        assert not result.is_degenerate


class TestMixedContent:
    def test_degenerate_section_in_longer_text(self):
        preamble = "## Executive Summary\n\nThe investigation covered 3 hosts.\n\n"
        row = "| HOST-A | 192.0.2.3 | admin | lateral_movement |"
        stutter = "## Findings\n" + "\n".join([row] * 10)
        epilogue = "\n\n## Conclusion\n\nFurther analysis recommended."
        text = preamble + stutter + epilogue
        result = detect_repetition(text)
        assert result.is_degenerate
        assert "Executive Summary" in result.cleaned_text

    def test_cleaned_text_preserves_content_before_stutter(self):
        good = "The analyst identified 5 suspicious connections. "
        bad = "REPEATED BLOCK with enough characters to exceed the minimum threshold for detection. " * 6
        text = good + bad
        result = detect_repetition(text)
        assert result.is_degenerate
        assert good.strip() in result.cleaned_text


class TestCustomThresholds:
    def test_strict_thresholds(self):
        sentence = "The host exhibited anomalous network behavior during the analysis period. "
        text = sentence * 3
        result = detect_repetition(text, max_sentence_repeats=2)
        assert result.is_degenerate

    def test_relaxed_thresholds(self):
        sentence = "The host exhibited anomalous network behavior during the analysis period. "
        text = sentence * 3
        result = detect_repetition(text, max_sentence_repeats=5)
        assert not result.is_degenerate


class TestReturnStructure:
    def test_result_is_named_tuple(self):
        result = detect_repetition("normal text")
        assert isinstance(result, RepetitionResult)
        assert isinstance(result, tuple)

    def test_degenerate_fields_populated(self):
        row = "| HOST-A | 192.0.2.3 | admin | lateral_movement |"
        text = "\n".join([row] * 12)
        result = detect_repetition(text)
        assert result.is_degenerate
        assert len(result.repeated_content) > 0
        assert len(result.repeated_content) <= 100
        assert result.repeat_count > 0
        assert result.pattern_type in ("phrase", "line", "sentence")
