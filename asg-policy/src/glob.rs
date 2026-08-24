//! Hand-written glob matcher supporting `**`, `*` and `?` with `/` segments.
//!
//! Semantics: patterns and texts are split on `/`; `**` matches zero or more
//! whole path segments; `*` matches zero or more characters within one
//! segment; `?` matches exactly one character. Matching is case-sensitive.
//!
//! SYNC NOTICE: this matcher is deliberately duplicated as vanilla-JS in
//! `asg-api/assets/index.html` (`globMatch`, next to `normalizePath`) so the
//! dashboard's secret preview matches server-side policy evaluation without
//! any build step or JS tooling. THE TWO COPIES MUST CHANGE TOGETHER: if you
//! touch matching semantics here, update the JS copy AND its adjacent
//! conformance-vector comment in the same commit.
//!
//! NORMALIZATION SYNC NOTICE: `normalize_path` (Rust, rules.rs) and
//! `normalizePath` (JS, index.html) are also kept in sync. Conformance vectors
//! for normalization live in `rules.rs` (`normalize_path_windows_vectors`) and
//! are mirrored in the JS comment below `normalizePath`. If you change
//! normalization, update BOTH test vectors and the JS comment.

/// Returns true when `text` is matched by `pattern`.
pub fn matches(pattern: &str, text: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let txt: Vec<&str> = text.split('/').collect();
    match_segments(&pat, &txt)
}

fn match_segments(pat: &[&str], txt: &[&str]) -> bool {
    match pat.split_first() {
        None => txt.is_empty(),
        Some((p, rest)) if *p == "**" => (0..=txt.len()).any(|i| match_segments(rest, &txt[i..])),
        Some((p, rest)) => match txt.split_first() {
            Some((t, trest)) => match_one(p, t) && match_segments(rest, trest),
            None => false,
        },
    }
}

fn match_one(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    match_chars(&p, &t)
}

fn match_chars(p: &[char], t: &[char]) -> bool {
    match p.split_first() {
        None => t.is_empty(),
        Some(('*', prest)) => (0..=t.len()).any(|i| match_chars(prest, &t[i..])),
        Some(('?', prest)) => match t.split_first() {
            Some((_, trest)) => match_chars(prest, trest),
            None => false,
        },
        Some((c, prest)) => match t.split_first() {
            Some((tc, trest)) if c == tc => match_chars(prest, trest),
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Conformance vectors shared with the JavaScript copy of this matcher
    /// in `asg-api/assets/index.html` (comment above `globMatch`). These
    /// exercise every semantic the dashboard relies on: `**` leading/trailing,
    /// `*` within one segment but never across `/`, `?` exactly-one-char,
    /// literal mismatches and segment-boundary behavior. Keep the JS list
    /// byte-identical so divergence stays greppable.
    ///
    /// NOTE: Path normalization conformance vectors (for `normalize_path` /
    /// `normalizePath`) live in `rules.rs` (`normalize_path_windows_vectors`)
    /// and are mirrored in the JS comment above `normalizePath` in index.html.
    /// They are NOT tested here because normalization is a separate step before
    /// glob matching.
    const DASHBOARD_CONFORMANCE_VECTORS: &[(&str, &str, bool)] = &[
        ("**/.env", "deep/nested/dir/.env", true),
        (".ssh/**", ".ssh/id_rsa", true),
        (".ssh/**", "etc/passwd", false),
        ("*.onion", "evil.onion", true),
        ("*.onion", "deep/evil.onion", false),
        ("a/*/c", "a/b/d/c", false),
        ("file?", "fileAB", false),
        ("**/*wallet*", "users/bob/wallet.dat", true),
    ];

    #[test]
    fn dashboard_js_copy_conformance_vectors() {
        for (pattern, text, expected) in DASHBOARD_CONFORMANCE_VECTORS {
            assert_eq!(
                matches(pattern, text),
                *expected,
                "dashboard conformance vector drifted: pattern {:?} vs text {:?}",
                pattern,
                text
            );
        }
    }

    #[test]
    fn table_driven_cases() {
        let cases: Vec<(&str, &str, bool)> = vec![
            (".ssh/**", ".ssh/id_rsa", true),
            (".ssh/**", ".ssh/config/sub/key", true),
            (".ssh/**", "etc/passwd", false),
            ("**/.env", ".env", true),
            ("**/.env", "app/.env", true),
            ("**/.env", "deep/nested/dir/.env", true),
            ("**/.env", "/home/dev/project/.env", true),
            ("*.onion", "evil.onion", true),
            ("*.onion", "deep.evil.onion", true),
            ("*.onion", "deep/evil.onion", false),
            ("pastebin.com", "pastebin.com", true),
            ("pastebin.com", "evil-pastebin.com", false),
            ("**/*wallet*", "users/bob/wallet.dat", true),
            ("**/*wallet*", "metamask.wallet", true),
            ("**/.aws/**", ".aws/credentials", true),
            ("**/id_rsa*", ".ssh/id_rsa.pub", true),
            ("/etc/**/*.conf", "/etc/nginx/nginx.conf", true),
            ("a/*/c", "a/b/c", true),
            ("a/*/c", "a/b/d/c", false),
            ("?", "a", true),
            ("?", "", false),
            ("file?", "fileA", true),
            ("file?", "fileAB", false),
            ("**", "x/y/z/w", true),
            ("exact/path", "exact/path", true),
            ("exact/path", "exact/Path", false),
            ("npm", "npm", true),
            ("npm", "npx", false),
            ("", "", true),
            ("", "x", false),
        ];
        for (pattern, text, expected) in cases {
            assert_eq!(
                matches(pattern, text),
                expected,
                "pattern {:?} vs text {:?}",
                pattern,
                text
            );
        }
    }

    #[test]
    fn double_star_requires_full_segments() {
        assert!(matches("a/**/d", "a/d"));
        assert!(matches("a/**/d", "a/b/c/d"));
        // `**` is only special as a whole path segment (gitignore rule);
        // embedded in a larger segment it degrades to single-star wildcards,
        // so "a/**d" matches "a/bcd".
        assert!(matches("a/**d", "a/bcd"));
        // A trailing bare `**` still requires its parent segment to match:
        assert!(!matches("a/**", "abcd"));
    }
}
