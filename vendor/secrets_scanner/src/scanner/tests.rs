use super::*;

fn synthetic_github_pat() -> String {
    let suffix = (0..36)
        .map(|index| {
            let byte = match index % 3 {
                0 => b'A' + ((index * 7 + 3) % 26) as u8,
                1 => b'a' + ((index * 11 + 5) % 26) as u8,
                _ => b'0' + ((index * 13 + 1) % 10) as u8,
            };
            char::from(byte)
        })
        .collect::<String>();
    format!("ghp_{suffix}")
}

fn synthetic_aws_key() -> String {
    let suffix = (0..16)
        .map(|index| {
            if index % 3 == 0 {
                char::from(b'A' + ((index * 7 + 3) % 26) as u8)
            } else {
                char::from(b'2' + ((index * 5 + 2) % 6) as u8)
            }
        })
        .collect::<String>();
    format!("AKIA{suffix}")
}

fn synthetic_pem_content() -> String {
    let dashes = "-".repeat(5);
    let private_key = ["PRIVATE", "KEY"].join(" ");
    format!(
        "{dashes}BEGIN RSA {private_key}{dashes}\n{}",
        "A".repeat(64)
    )
}

fn synthetic_slack_webhook() -> String {
    let suffix = synthetic_github_pat();
    let suffix = &suffix[4..];
    format!(
        "https://hooks.slack.com/services/T{}/{}/{}",
        &suffix[..8],
        &suffix[8..16],
        &suffix[12..36]
    )
}

fn test_scanner() -> Scanner {
    let dashes = "-".repeat(5);
    let private_key = ["PRIVATE", "KEY"].join(" ");
    let pem_regex = format!("{dashes}BEGIN (RSA |EC |OPENSSH )?{private_key}{dashes}");
    let pem_keyword = format!("{dashes}begin");
    let aws_regex = r"\b(AKIA[A-Z2-7]{16})\b";
    let github_regex = r"ghp_[A-Za-z0-9_]{36,}";
    let toml = format!(
        r#"
title = "test"

[[rules]]
id = "aws-access-token"
description = "AWS access key"
regex = {aws_regex:?}
entropy = 3.0
keywords = ["akia"]

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = {github_regex:?}
keywords = ["ghp_"]

[[rules]]
id = "pem-private-key"
description = "PEM private key"
regex = {pem_regex:?}
keywords = [{pem_keyword:?}]
"#
    );
    Scanner::from_toml(&toml).expect("should build test scanner")
}
const INVALID_CUSTOM_RULES: &str = r#"
title = "invalid"

[[rules]]
id = "lookahead"
description = "Unsupported lookahead"
regex = '(?=SECRET)SECRET[0-9]+'
keywords = ["secret"]
"#;

#[test]
fn from_toml_rejects_invalid_custom_regex() {
    assert!(
        matches!(
            Scanner::from_toml(INVALID_CUSTOM_RULES),
            Err(crate::error::ScannerError::InvalidRules(_))
        ),
        "scanner constructors must reject invalid custom regexes"
    );
}

#[test]
fn lazy_detection_matches_eager_and_compiles_only_candidate_rules() {
    let toml = r#"
title = "lazy regex"
[[rules]]
id = "selected"
regex = 'primary_[A-Za-z0-9]{8}'
keywords = ["primary_"]
[[rules]]
id = "path-filtered"
regex = 'filtered_[A-Za-z0-9]{8}'
path = '\.pem$'
keywords = ["primary_"]
[[rules]]
id = "not-selected"
regex = 'unused_[A-Za-z0-9]{8}'
keywords = ["unused_"]
"#;
    let eager = Scanner::from_engine(
        crate::rules::engine::RuleEngine::from_toml(toml).expect("eager engine"),
    );
    let lazy = Scanner::from_engine(
        crate::rules::engine::RuleEngine::from_toml_lazy(toml).expect("lazy engine"),
    );
    let content = b"TOKEN=primary_ABCDEFGH";

    let eager_findings = serde_json::to_value(eager.scan_bytes("test.env", content))
        .expect("serialize eager findings");
    let lazy_findings = serde_json::to_value(lazy.scan_bytes("test.env", content))
        .expect("serialize lazy findings");
    assert_eq!(lazy_findings, eager_findings);
    assert!(lazy.engine().keyworded_rules()[0]
        .regex
        .as_ref()
        .expect("selected regex")
        .is_compiled());
    for rule in &lazy.engine().keyworded_rules()[1..] {
        assert!(
            !rule.regex.as_ref().expect("unselected regex").is_compiled(),
            "{} should remain uncompiled",
            rule.id
        );
    }
}

#[test]
fn from_file_rejects_invalid_custom_regex() {
    let file = tempfile::NamedTempFile::new().expect("temp rules");
    std::fs::write(file.path(), INVALID_CUSTOM_RULES).expect("write rules");

    assert!(
        matches!(
            Scanner::from_file(file.path().to_str().expect("path")),
            Err(crate::error::ScannerError::InvalidRules(_))
        ),
        "scanner file constructor must reject invalid custom regexes"
    );
}

#[test]
fn from_toml_rejects_duplicate_ids() {
    let toml = r#"
title = "duplicate"
[[rules]]
id = "same"
regex = 'first-[A-Z]+'
[[rules]]
id = "same"
regex = 'second-[A-Z]+'
"#;
    assert!(
        matches!(
            Scanner::from_toml(toml),
            Err(crate::error::ScannerError::InvalidRules(_))
        ),
        "scanner constructors must reject duplicate rule IDs"
    );
}

#[test]
fn detects_aws_key() {
    let scanner = test_scanner();
    let content = format!("aws_key = \"{}\"", synthetic_aws_key());
    let findings = scanner.scan_content("test.env", &content);

    assert!(!findings.is_empty(), "should detect AWS access key");
    assert_eq!(findings[0].rule_id, "aws-access-token");
    assert_eq!(findings[0].line, 1);
}

#[test]
fn detects_github_pat() {
    let scanner = test_scanner();
    let content = format!("GITHUB_TOKEN={}", synthetic_github_pat());
    let findings = scanner.scan_content("config.yml", &content);

    assert!(!findings.is_empty(), "should detect GitHub PAT");
    assert_eq!(findings[0].rule_id, "github-pat");
}

#[test]
fn detects_pem_key() {
    let scanner = test_scanner();
    let content = synthetic_pem_content();
    let findings = scanner.scan_content("key.pem", &content);
    assert!(!findings.is_empty(), "should detect PEM private key header");
    assert_eq!(findings[0].rule_id, "pem-private-key");
}

#[test]
fn skips_low_entropy() {
    let scanner = test_scanner();
    let content = format!("key = \"AKIA{}\"", "A".repeat(16));
    let findings = scanner.scan_content("test.env", &content);
    assert!(
        findings.is_empty(),
        "low-entropy AWS key should be filtered out"
    );
}

#[test]
fn redacts_by_default() {
    let scanner = test_scanner();
    let content = synthetic_pem_content();
    let findings = scanner.scan_content("key.pem", &content);
    assert!(!findings.is_empty(), "should detect PEM private key header");
    assert!(
        findings[0].matched.contains('*'),
        "should redact matched text"
    );
}

#[test]
fn respects_no_redact_config() {
    let scanner = test_scanner().with_config(ScanConfig {
        redact: false,
        ..Default::default()
    });
    let content = synthetic_pem_content();
    let findings = scanner.scan_content("key.pem", &content);
    assert!(!findings.is_empty(), "should detect PEM private key header");
    assert!(
        !findings[0].matched.contains('*'),
        "should not redact when config says no"
    );
}

#[test]
fn loads_bundled_and_scans() {
    // Smoke test: load the real bundled rules and scan a known secret
    let scanner = Scanner::from_bundled().expect("bundled rules should load");
    assert!(scanner.engine().rule_count() > 100);

    // Scan content with a planted GitHub PAT (avoid contiguous alphabet to bypass global stopwords allowlist)
    let content = format!("export TOKEN={}", synthetic_github_pat());
    let findings = scanner.scan_content("deploy.sh", &content);
    // Should find at least one hit (github-pat or generic-api-key)
    assert!(
        !findings.is_empty(),
        "bundled scanner should detect planted GitHub PAT"
    );
}

#[test]
fn detects_match_outside_keyword_window() {
    let toml = r#"
title = "window-test"
[[rules]]
id = "aws-access-token"
description = "AWS access key"
regex = '\b(AKIA[A-Z2-7]{16})\b'
entropy = 3.0
keywords = ["akia"]
"#;
    let scanner = Scanner::from_toml(toml).expect("should build test scanner");
    let content = format!("akia {}\n\n{}", " ".repeat(300), synthetic_aws_key());
    let findings = scanner.scan_content("test.env", &content);
    assert!(
        !findings.is_empty(),
        "should detect match outside of keyword window"
    );
    assert_eq!(findings[0].rule_id, "aws-access-token");
    assert!(findings[0].start_offset > 300);
}

#[test]
fn detects_secret_with_fallback_rule_no_keywords() {
    let toml = r#"
title = "fallback-test"
[[rules]]
id = "slack-webhook"
description = "Slack Webhook"
regex = 'https://hooks\.slack\.com/services/[T|B][A-Za-z0-9_]{8}/[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24}'
"#;
    let scanner = Scanner::from_toml(toml).expect("should build test scanner");
    let content = synthetic_slack_webhook();
    let findings = scanner.scan_content("test.env", &content);
    assert!(
        !findings.is_empty(),
        "fallback rule should detect without keywords"
    );
    assert_eq!(findings[0].rule_id, "slack-webhook");
}

#[test]
fn detects_path_only_rule_without_scanning_all_rules_for_paths() {
    let toml = r#"
title = "path-only-test"

[[rules]]
id = "path-only-secret"
description = "Path-only secret file"
path = 'secret\.env$'
"#;
    let scanner = Scanner::from_toml(toml).expect("should build test scanner");

    let findings = scanner.scan_content("secret.env", "clean content");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "path-only-secret");
    assert!(scanner.scan_content("safe.env", "clean content").is_empty());
}

#[cfg(feature = "bench")]
#[test]
fn unkeyworded_scan_time_is_benchmarked() {
    let toml = r#"
title = "benchmarking-test"

[[rules]]
id = "no-keyword-rule"
regex = 'secret-[0-9]+'
"#;
    let scanner = Scanner::from_toml(toml).expect("should build test scanner");
    assert_eq!(scanner.unkeyworded_scan_time_ns(), 0);

    let content = "my secret key is secret-12345";
    let findings = scanner.scan_content("secrets.txt", &content);
    assert!(!findings.is_empty());

    let time_ns = scanner.unkeyworded_scan_time_ns();
    assert!(
        time_ns > 0,
        "unkeyworded scan time should be recorded and non-zero"
    );

    scanner.reset_unkeyworded_scan_time();
    assert_eq!(
        scanner.unkeyworded_scan_time_ns(),
        0,
        "reset should set time to 0"
    );
}

#[test]
fn min_entropy_override_keeps_structural_rules() {
    let dashes = "-".repeat(5);
    let private_key = ["PRIVATE", "KEY"].join(" ");
    let regex = format!("{dashes}BEGIN (RSA |EC )?{private_key}{dashes}");
    let keyword = format!("{dashes}begin");
    let toml = format!(
        "title = \"structural\"\n\n[[rules]]\nid = \"pem-private-key\"\ndescription = \"PEM private key\"\nregex = {regex:?}\nkeywords = [{keyword:?}]\n"
    );
    let scanner = Scanner::from_toml(&toml)
        .expect("build")
        .with_config(ScanConfig {
            min_entropy_override: Some(7.0),
            ..Default::default()
        });
    let content = format!("{dashes}BEGIN RSA {private_key}{dashes}");
    let findings = scanner.scan_content("id_rsa", &content);
    assert!(
        !findings.is_empty(),
        "structural rule should survive entropy override"
    );
    assert_eq!(findings[0].rule_id, "pem-private-key");
}

#[test]
fn min_entropy_override_is_a_floor_not_a_replacement() {
    let toml = r#"
title = "floor"
[[rules]]
id = "tok"
description = "token"
regex = 'tok-[A-Za-z0-9]{12}'
keywords = ["tok-"]
entropy = 3.0
"#;
    let build = |override_value: Option<f64>| {
        Scanner::from_toml(toml)
            .expect("build")
            .with_config(ScanConfig {
                min_entropy_override: override_value,
                ..Default::default()
            })
    };
    let sample = synthetic_github_pat();
    let high = format!("tok-{}", &sample[4..16]);
    assert_eq!(build(None).scan_content("a", &high).len(), 1);
    assert!(build(Some(5.0)).scan_content("a", &high).is_empty());

    let low = format!("tok-{}", "a".repeat(12));
    assert!(build(None).scan_content("a", &low).is_empty());
    assert!(build(Some(1.0)).scan_content("a", &low).is_empty());
}

#[test]
fn distinct_rules_matching_same_span_are_both_reported() {
    // Two rules whose regexes match the EXACT same span; both should be reported
    // (position-only dedup would drop the second rule's finding). Distinct
    // keywords ensure both rules become candidates and actually run.
    let toml = r#"
title = "overlap"

[[rules]]
id = "rule-a"
regex = 'AKIA[A-Z0-9]{16}'
keywords = ["akia"]

[[rules]]
id = "rule-b"
regex = 'AKIA[A-Z0-9]{16}'
keywords = ["key"]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let content = format!("key = {}", synthetic_aws_key());
    let findings = scanner.scan_content("test.env", &content);
    let ids: std::collections::HashSet<&str> =
        findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains("rule-a"), "rule-a should report");
    assert!(
        ids.contains("rule-b"),
        "rule-b should report — identical spans from different rules must not be deduped"
    );
}

#[test]
fn overlapping_keywords_make_both_rules_candidates() {
    let toml = r#"
title = "overlapping-keywords"

[[rules]]
id = "rule-a"
regex = 'abc-secret-[0-9]+'
keywords = ["abc"]

[[rules]]
id = "rule-b"
regex = 'bc-secret-[0-9]+'
keywords = ["bc"]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let findings = scanner.scan_content("test.env", "abc-secret-123");
    let ids: std::collections::HashSet<&str> =
        findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(ids.contains("rule-a"), "rule-a should report");
    assert!(
        ids.contains("rule-b"),
        "rule-b should report even though its keyword overlaps rule-a's keyword"
    );
}

#[test]
fn absent_secret_group_uses_full_match_for_entropy() {
    let toml = r#"
title = "implicit-secret-group"
[[rules]]
id = "implicit-group"
regex = '(api|token)=([A-Za-z0-9]{32})'
entropy = 3.0
keywords = ["api="]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let sample = synthetic_github_pat();
    let content = format!("api={}", &sample[4..36]);
    let findings = scanner.scan_content("test.env", &content);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "implicit-group");
    assert_eq!(findings[0].secret_start_offset, 0);
    assert_eq!(findings[0].secret_end_offset, content.len());
}

#[test]
fn context_lines_span_two_lines_each_side() {
    let toml = r#"
title = "ctx"
[[rules]]
id = "github-pat"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let secret = synthetic_github_pat();
    let content = format!("line1\nline2\nTOKEN={secret}\nline4\nline5\nline6");
    let findings = scanner.scan_content("c.txt", &content);
    assert!(!findings.is_empty());
    let finding = &findings[0];
    assert_eq!(finding.line, 3);
    let nums: Vec<usize> = finding.context_lines.iter().map(|(n, _)| *n).collect();
    assert_eq!(nums, vec![1, 2, 3, 4, 5]);
}

#[test]
fn capture_context_false_keeps_locations_without_context_lines() {
    let toml = r#"
title = "ctx-off"

[[rules]]
id = "github-pat"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;
    let scanner = Scanner::from_toml(toml)
        .expect("build")
        .with_config(ScanConfig {
            capture_context: false,
            ..Default::default()
        });
    let content = format!("line1\nTOKEN={}\nline3", synthetic_github_pat());

    let findings = scanner.scan_content("c.txt", &content);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 2);
    assert!(findings[0].matched.contains('*'));
    assert!(findings[0].context_lines.is_empty());
}

#[test]
fn reports_multiline_and_later_match_locations() {
    let toml = r#"
title = "locations"

[[rules]]
id = "token"
regex = 'TOKEN-[A-Z0-9]{4}(?:\nNEXT-[A-Z0-9]{4})?'
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let content = "aa\nbb TOKEN-ABCD\nNEXT-EFGH tail\nxx TOKEN-IJKL end";
    let findings = scanner.scan_content("tokens.txt", &content);

    assert_eq!(findings.len(), 2);
    assert_eq!(
        (
            findings[0].line,
            findings[0].col,
            findings[0].end_line,
            findings[0].end_col,
        ),
        (2, 4, 3, 10)
    );
    assert_eq!(
        (
            findings[1].line,
            findings[1].col,
            findings[1].end_line,
            findings[1].end_col,
        ),
        (4, 4, 4, 14)
    );
}

#[test]
fn utf16_columns_account_for_multibyte_prefix() {
    // A line with a multibyte prefix: byte columns and UTF-16 columns diverge.
    // "δ" is 2 UTF-8 bytes but 1 UTF-16 code unit; "𝟚" (U+1D7DA) is 4 UTF-8
    // bytes but 2 UTF-16 code units (a surrogate pair). The ASCII fast path must
    // NOT apply here, so the scanner must report the UTF-16 columns.
    let toml = r#"
title = "u16"

[[rules]]
id = "tok"
regex = 'TOKEN-[A-Z0-9]{4}'
keywords = ["token-"]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let prefix = "δ𝟚 "; // 1 + 2 = 3 UTF-16 units, then a space => 4 units before TOKEN
    let content = format!("{prefix}TOKEN-ABCD");
    let findings = scanner.scan_content("u.txt", &content);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    // Byte column counts UTF-8 bytes (2 + 4 + 1 = 7 bytes) => 1-based col 8.
    assert_eq!(f.col, 8, "byte column counts UTF-8 bytes");
    // UTF-16 column counts code units (1 + 2 + 1 = 4) => 1-based col 5.
    assert_eq!(f.col_utf16, 5, "utf16 column counts UTF-16 code units");
    assert_eq!(
        f.end_col_utf16,
        f.col_utf16 + 10,
        "TOKEN-ABCD is 10 ASCII units"
    );
}

#[test]
fn redacted_context_lines_do_not_leak_any_secret_in_context_window() {
    let toml = r#"
title = "ctx-redaction"

[[rules]]
id = "github-pat"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]
"#;
    let scanner = Scanner::from_toml(toml).expect("build");
    let first_secret = synthetic_github_pat();
    let second_secret = synthetic_github_pat();
    let content = format!("line1\nFIRST={first_secret}\nSECOND={second_secret}\nline4");

    let findings = scanner.scan_content("c.txt", &content);

    assert_eq!(findings.len(), 2);
    for finding in &findings {
        assert!(!finding.matched.contains(&first_secret));
        assert!(!finding.matched.contains(&second_secret));
        let context = finding
            .context_lines
            .iter()
            .map(|(_, text)| text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!context.contains(&first_secret));
        assert!(!context.contains(&second_secret));
        assert!(context.contains("[REDACTED_SECRET]"));
    }
}

#[test]
fn bundled_scanner_adds_custom_rules_with_lazy_compilation() {
    let custom = r#"
[[rules]]
id = "internal-token"
regex = 'internal_[A-Z0-9]{16}'
keywords = ["internal_"]
"#;
    let bundled_count = Scanner::from_bundled()
        .expect("bundled scanner")
        .engine()
        .rule_count();
    let scanner = Scanner::from_bundled_with_rules(custom).expect("valid custom rules");
    assert_eq!(scanner.engine().rule_count(), bundled_count + 1);

    let rule = scanner
        .engine()
        .rules()
        .into_iter()
        .find(|rule| rule.id == "internal-token")
        .expect("custom rule is included");
    assert!(!rule.regex.as_ref().expect("custom regex").is_compiled());

    let token = format!("internal_{}", "A".repeat(16));
    let findings = scanner.scan_content("internal.env", &format!("TOKEN={token}"));
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "internal-token"));
    assert!(rule.regex.as_ref().expect("custom regex").is_compiled());
}
