"""Unit tests for thinking.py — thinking-token stripping across delimiter styles."""

from __future__ import annotations

from karst.harness.guards.thinking import strip_thinking_tokens


class TestStripThinkingTokens:
    def test_gemma_channel_format(self):
        text = (
            "<|channel>thought\nI need to analyze this data carefully.\n"
            "Let me consider the auth events.<channel|>\n"
            '[{"title": "Brute force detected", "severity": "high"}]'
        )
        result = strip_thinking_tokens(text)
        assert "<|channel>" not in result
        assert "<channel|>" not in result
        assert "Brute force detected" in result

    def test_qwen_think_format(self):
        text = (
            "<think>\nLet me reason about the findings.\n"
            "The auth failures look suspicious.\n</think>\n"
            '[{"title": "Auth anomaly", "severity": "medium"}]'
        )
        result = strip_thinking_tokens(text)
        assert "<think>" not in result
        assert "</think>" not in result
        assert "Auth anomaly" in result

    def test_olmo_thinking_format(self):
        text = (
            "<|thinking|>Processing the network events...\n"
            "High volume of DNS queries.<|/thinking|>\n"
            '[{"title": "DNS tunneling", "severity": "high"}]'
        )
        result = strip_thinking_tokens(text)
        assert "<|thinking|>" not in result
        assert "<|/thinking|>" not in result
        assert "DNS tunneling" in result

    def test_bracket_format(self):
        text = (
            "[Start thinking]\nAnalyzing the endpoint data.\n"
            "Multiple process injections observed.\n[End thinking]\n"
            '[{"title": "Process injection", "severity": "critical"}]'
        )
        result = strip_thinking_tokens(text)
        assert "[Start thinking]" not in result
        assert "[End thinking]" not in result
        assert "Process injection" in result

    def test_no_thinking_passthrough(self):
        text = '[{"title": "Clean output", "severity": "low"}]'
        result = strip_thinking_tokens(text)
        assert result == text

    def test_multiple_thinking_blocks(self):
        text = (
            "<think>First thought.</think>\n"
            '[{"title": "Finding 1"}]\n'
            "<think>Second thought.</think>\n"
            "More findings here."
        )
        result = strip_thinking_tokens(text)
        assert "<think>" not in result
        assert "Finding 1" in result
        assert "More findings here" in result

    def test_empty_string(self):
        assert strip_thinking_tokens("") == ""

    def test_multiline_thinking(self):
        text = (
            "<think>\nLine 1\nLine 2\nLine 3\n</think>\n"
            "Actual output"
        )
        result = strip_thinking_tokens(text)
        assert result == "Actual output"

    def test_mixed_formats(self):
        text = (
            "<|channel>thought\nGemma thinking<channel|>\n"
            "<think>Qwen thinking</think>\n"
            "Final answer"
        )
        result = strip_thinking_tokens(text)
        assert result == "Final answer"
