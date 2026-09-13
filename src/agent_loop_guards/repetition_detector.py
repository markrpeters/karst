"""Output repetition detection — catch degenerate stutter in LLM output.

Why this exists: quantized local models, mixture-of-experts models in
particular, sometimes lock into a repetition attractor and emit the same
table row or sentence dozens of times until they hit the token limit. The
output looks complete at a glance and passes naive length checks, so it
must be caught deterministically before it is scored or shown to a person.
This module detects three patterns in raw text and truncates at the first
repeat with an explicit marker:

1. Phrase stutter: same substring repeated consecutively
2. Line duplication: same line repeated consecutively (table row stutter)
3. Sentence repetition: same sentence appearing too many times in total

NO LLM CALLS. Pure Python only.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class RepetitionResult(NamedTuple):
    is_degenerate: bool
    cleaned_text: str
    pattern_type: str
    repeated_content: str
    repeat_count: int


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")

_WHITESPACE_RUN_RE = re.compile(r"\s+")


def detect_repetition(
    text: str,
    *,
    max_sentence_repeats: int = 3,
    max_phrase_repeats: int = 3,
    min_phrase_chars: int = 40,
    max_line_repeats: int = 5,
) -> RepetitionResult:
    """Detect degenerate repetition in LLM output text.

    Checks three patterns in order (phrase, line, sentence). Returns on first
    match with cleaned (truncated) text. Non-degenerate text passes through
    unchanged.

    Args:
        text: Raw LLM output text.
        max_sentence_repeats: Max allowed total occurrences of any sentence.
        max_phrase_repeats: Max allowed consecutive phrase repetitions.
        min_phrase_chars: Minimum character length for phrase stutter detection.
        max_line_repeats: Max allowed consecutive identical lines.

    Returns:
        RepetitionResult with detection info and optionally cleaned text.
    """
    if not text:
        return RepetitionResult(False, text, "", "", 0)

    result = (
        _detect_phrase_stutter(text, min_phrase_chars, max_phrase_repeats)
        if len(text) >= min_phrase_chars * 2
        else None
    )
    if result is not None:
        return result

    result = _detect_line_repetition(text, max_line_repeats)
    if result is not None:
        return result

    result = _detect_sentence_repetition(text, max_sentence_repeats)
    if result is not None:
        return result

    return RepetitionResult(False, text, "", "", 0)


def _detect_phrase_stutter(
    text: str, min_chars: int, max_repeats: int,
) -> RepetitionResult | None:
    normalized = _WHITESPACE_RUN_RE.sub(" ", text)
    upper = min(200, min_chars * 3)
    pattern = re.compile(
        r"(.{" + str(min_chars) + r"," + str(upper) + r"})\1{"
        + str(max_repeats) + r",}",
        re.DOTALL,
    )
    m = pattern.search(normalized)
    if m is None:
        return None

    repeated = m.group(1)
    words = repeated.split()
    if len(words) < 4:
        return None

    full_match = m.group(0)
    count = len(full_match) // len(repeated)

    orig_start = _map_normalized_pos_to_original(text, normalized, m.start())
    first_end = _find_first_occurrence_end(text, orig_start, repeated)
    cleaned = text[:first_end] + (
        f"\n[truncated — degenerate repetition detected:"
        f" \"{repeated[:60].strip()}\" repeated {count}x]"
    )
    return RepetitionResult(True, cleaned, "phrase", repeated[:100].strip(), count)


def _detect_line_repetition(
    text: str, max_repeats: int,
) -> RepetitionResult | None:
    lines = text.split("\n")
    if len(lines) < max_repeats + 1:
        return None

    consecutive = 1
    prev = lines[0].strip()

    for i, line in enumerate(lines[1:], 1):
        stripped = line.strip()
        if stripped and stripped == prev:
            consecutive += 1
            if consecutive > max_repeats:
                start_line = i - max_repeats + 1
                kept = "\n".join(lines[:start_line + 1])
                cleaned = kept + (
                    f"\n[truncated — degenerate repetition detected:"
                    f" identical line repeated {consecutive}x]"
                )
                return RepetitionResult(
                    True, cleaned, "line", prev[:100], consecutive,
                )
        else:
            consecutive = 1
            prev = stripped

    return None


def _detect_sentence_repetition(
    text: str, max_repeats: int,
) -> RepetitionResult | None:
    sentences = _SENTENCE_SPLIT_RE.split(text)
    counts: dict[str, int] = {}
    kept: list[str] = []
    truncated_sentence = ""
    truncated_count = 0

    for sentence in sentences:
        normalized = sentence.strip().lower()
        if len(normalized) < 50:
            kept.append(sentence)
            continue
        count = counts.get(normalized, 0) + 1
        counts[normalized] = count
        if count <= max_repeats:
            kept.append(sentence)
        elif not truncated_sentence:
            truncated_sentence = sentence.strip()
            truncated_count = count

    if truncated_sentence:
        final_count = counts.get(truncated_sentence.lower(), truncated_count)
        cleaned = " ".join(kept) + (
            f" [truncated — degenerate repetition detected:"
            f" sentence repeated {final_count}x]"
        )
        return RepetitionResult(
            True, cleaned, "sentence", truncated_sentence[:100], final_count,
        )

    return None


def _map_normalized_pos_to_original(
    original: str, normalized: str, norm_pos: int,
) -> int:
    norm_idx = 0
    orig_idx = 0
    while norm_idx < norm_pos and orig_idx < len(original):
        if original[orig_idx].isspace():
            while orig_idx < len(original) and original[orig_idx].isspace():
                orig_idx += 1
            norm_idx += 1
        else:
            orig_idx += 1
            norm_idx += 1
    return orig_idx


def _find_first_occurrence_end(
    text: str, start: int, pattern_text: str,
) -> int:
    normalized_pattern = _WHITESPACE_RUN_RE.sub(" ", pattern_text)
    pattern_len = len(normalized_pattern)

    norm_matched = 0
    idx = start
    while idx < len(text) and norm_matched < pattern_len:
        if text[idx].isspace():
            while idx < len(text) and text[idx].isspace():
                idx += 1
            norm_matched += 1
        else:
            idx += 1
            norm_matched += 1

    return idx
