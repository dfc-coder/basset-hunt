#!/usr/bin/env python3
"""Regression checks for safe Kingfisher rule-source normalization."""

from update_kingfisher_rules import normalize_rule_block


def test_unused_fields_and_indentless_lists_are_removed() -> None:
    block = [
        "  - id: sample-rule",
        "    pattern: 'sample_[A-Z]+'",
        "    examples:",
        "    - 'sample-example-value'",
        "    negative_examples:",
        "    - 'ordinary-example'",
        "    references:",
        "    - 'https://example.invalid/rules'",
        "    words:",
        "    - 'sample-word'",
        "    response_matcher:",
        "    - type: status",
        "    request:",
        "      headers:",
        "        Authorization: sample-only",
        "    content:",
        "      sample: unused",
        "    type: API_KEY",
        "    validation:",
        "    - request:",
        "      body: sample-value",
        "    min_entropy: 2.0",
    ]

    normalized = normalize_rule_block(block, top_indent=2)

    for unused in (
        "examples:",
        "negative_examples:",
        "references:",
        "words:",
        "response_matcher:",
        "request:",
        "Authorization:",
        "content:",
        "type: API_KEY",
        "validation:",
        "sample-value",
        "sample-example-value",
        "ordinary-example",
    ):
        assert unused not in normalized
    assert "id: sample-rule" in normalized
    assert "pattern: 'sample_[A-Z]+'" in normalized
    assert "min_entropy: 2.0" in normalized


def test_secret_shaped_regex_literals_are_encoded() -> None:
    sample = "-".join(["ABCDEF", "GHI", "JKL", "Z" * 28])
    block = [
        "  - id: kingfisher.aws.6",
        "    pattern: |",
        f"      {sample}",
    ]
    normalized = normalize_rule_block(block, top_indent=2, rule_id="kingfisher.aws.6")
    assert sample not in normalized
    assert r"\x{41}" in normalized

    pem_marker = " ".join(["PRIVATE", "KEY"])
    block = [
        "  - id: kingfisher.pem.2",
        "    pattern: |",
        f"      {pem_marker}",
    ]
    normalized = normalize_rule_block(block, top_indent=2, rule_id="kingfisher.pem.2")
    assert pem_marker not in normalized
    assert r"\x{50}" in normalized


if __name__ == "__main__":
    test_unused_fields_and_indentless_lists_are_removed()
    test_secret_shaped_regex_literals_are_encoded()
    print("Kingfisher source sanitization checks passed")
