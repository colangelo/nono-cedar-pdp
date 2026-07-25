//! Ambiguity check for the raw endpoint path nono sends.
//!
//! nono's credential proxy forwards the request target verbatim — not normalised,
//! still percent-encoded (`upstream_path` in `crates/nono-proxy/src/reverse.rs`) —
//! and that raw string is what a policy matches. So `resource.path like "/repos/*"`
//! is satisfied by `/repos/../user/keys`, which a normalising origin routes to
//! `/user/keys`: the policy approved one resource and the upstream serves another.
//!
//! Normalising the path here would be the wrong fix twice over: it would change what
//! the policy sees (a policy matching `path` would no longer be matching what nono
//! sent and the upstream receives), and it would encode a *guess* about which of the
//! many normalisation rules this particular upstream applies. So this module decides
//! nothing about policy — it only answers "is this path's meaning knowable?", and an
//! unknowable path is denied outright, before any policy is consulted.

/// Deepest percent-decode nesting followed before giving up. Decoding shrinks a
/// string, so a fixed point is always reached long before this; the bound exists so
/// a pathologically nested path (`%2525…2e`) resolves to a deny rather than a long
/// loop.
const MAX_DECODE_PASSES: usize = 8;

/// Why a raw endpoint path cannot be handed to a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ambiguity {
    /// A `.` or `..` path segment, found after `passes` percent-decode passes.
    DotSegment { segment: String, passes: usize },
    /// A `%` that is not followed by two hex digits, in the path as nono sent it.
    MalformedEscape,
    /// Percent-decoding the path as nono sent it yields non-UTF-8 bytes.
    NonUtf8,
    /// Percent-encoding nested deeper than [`MAX_DECODE_PASSES`].
    NestedTooDeep,
}

impl Ambiguity {
    /// Operator-facing description, used to build the deny reason. Carries no
    /// request bytes of its own except the offending segment, which the caller's
    /// `Decision::deny` control-escapes along with the rest of the reason.
    pub fn describe(&self) -> String {
        match self {
            Ambiguity::DotSegment { segment, passes } => {
                let depth = match passes {
                    0 => "in the path as sent".to_string(),
                    1 => "after one percent-decode pass".to_string(),
                    n => format!("after {n} percent-decode passes"),
                };
                format!(
                    "a {segment:?} path segment appears {depth}, so a normalising \
                     upstream resolves this to a different resource than the raw path \
                     a policy matches"
                )
            }
            Ambiguity::MalformedEscape => "it contains a malformed percent-escape, so \
                 what the upstream decodes cannot be known"
                .to_string(),
            Ambiguity::NonUtf8 => "percent-decoding it yields bytes that are not UTF-8, \
                 which an upstream may still fold onto \".\" (overlong encodings), so \
                 what it resolves to cannot be known"
                .to_string(),
            Ambiguity::NestedTooDeep => format!(
                "its percent-encoding nests deeper than {MAX_DECODE_PASSES} decode \
                 passes, so what the upstream resolves cannot be known"
            ),
        }
    }
}

/// `Some(reason)` when the path's meaning depends on normalisation rules we would
/// have to guess at; `None` when the raw path is safe to hand to a policy as-is.
///
/// Traversal is looked for at every decode depth, not just the first: an upstream (or
/// a proxy in front of it) that decodes twice turns `%252e%252e` into `..`, and this
/// daemon has no way to know how many times the path will be decoded downstream.
/// *Undecodability*, by contrast, is only decisive on the first pass — see the
/// `Err` arm below.
pub fn ambiguity(path: &str) -> Option<Ambiguity> {
    // Only the routing part of the target: nono sends the raw request line's target,
    // query string included. A `..` inside a query *value* cannot change which
    // resource the origin routes to — RFC 3986 §5.2.4 defines `remove_dot_segments`
    // over the path component alone — so treating one as traversal would reject
    // legitimate calls (`?path=../x` is an ordinary API parameter). That makes `?`
    // a *specified* boundary rather than a guess about the upstream, which is why it
    // is the only truncation here. A `?` that arrives percent-encoded is deliberately
    // NOT a separator, because the upstream will not treat it as one either — it
    // stays in the analysed path below.
    //
    // `#` is deliberately NOT a separator, unlike `?`. An origin-form request target
    // carries no fragment (RFC 9112 §3.2.1) — a conforming client percent-encodes it
    // as `%23` — so a raw `#` reaching us is either a literal path character or
    // something a proxy reconstructed, and whether the upstream splits on it is
    // exactly the upstream-dependent meaning this guard refuses to guess at.
    // Truncating there hid `/repos/x#/../user/keys`; reading through it denies that
    // while leaving a harmless `/issues/issue#5` alone. Removing a guess, not adding
    // one — which is why this is a scan-through rather than a blanket deny on `#`.
    let routing = path.split('?').next().unwrap_or(path);

    let mut current = routing.to_string();
    for passes in 0..=MAX_DECODE_PASSES {
        if let Some(segment) = dot_segment(&current) {
            return Some(Ambiguity::DotSegment { segment, passes });
        }
        if !current.contains('%') {
            return None;
        }
        match percent_decode(&current) {
            Ok(decoded) if decoded == current => return None,
            Ok(decoded) => current = decoded,
            Err(undecodable) => {
                // The first pass decodes what the upstream itself decodes, so a
                // malformed escape there is a genuine unknown. Deeper passes are
                // speculative: `/x/50%25-done` legitimately decodes to `50%-done`,
                // whose stray `%` is data rather than an escape. Denying that would
                // reject an ordinary path, so undecodability below the first pass
                // just ends the search.
                return if passes == 0 { Some(undecodable) } else { None };
            }
        }
    }
    Some(Ambiguity::NestedTooDeep)
}

/// The first `.` or `..` segment, ignoring `;`-parameters. Some servers (Tomcat and
/// friends) strip `;jsessionid=…` style parameters before resolving the path, which
/// makes `/repos/..;/user/keys` a traversal there and a literal segment elsewhere —
/// exactly the kind of divergence that makes the path's meaning unknowable from here.
/// Segments split on `/` **and `\`**. The WHATWG URL standard folds a backslash onto a
/// forward slash for special schemes (http/https), so browsers and a good deal of
/// server-side URL handling read `..\..` as traversal. Covering the `;`-parameter quirk
/// while omitting this one would be inconsistent rather than principled — both are cases
/// where the upstream may see a segment boundary we would not.
fn dot_segment(path: &str) -> Option<String> {
    path.split(['/', '\\'])
        .map(|segment| segment.split(';').next().unwrap_or(segment))
        .find(|segment| *segment == "." || *segment == "..")
        .map(str::to_string)
}

/// One percent-decode pass over the whole string. Byte-oriented, so a decoded
/// sequence that is not valid UTF-8 is reported rather than replaced: a lossy
/// conversion would invent a `\u{FFFD}` the upstream never sees.
fn percent_decode(text: &str) -> Result<String, Ambiguity> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let (Some(high), Some(low)) = (
            bytes.get(i + 1).copied().and_then(hex),
            bytes.get(i + 2).copied().and_then(hex),
        ) else {
            return Err(Ambiguity::MalformedEscape);
        };
        out.push(high * 16 + low);
        i += 3;
    }
    String::from_utf8(out).map_err(|_| Ambiguity::NonUtf8)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// The finding, in its plainest form: a prefix glob meant for `/repos/*` is
    /// satisfied by a path the upstream resolves to `/user/keys`.
    #[test]
    fn a_literal_traversal_segment_is_ambiguous() {
        let found = ambiguity("/repos/../user/keys").expect("must be ambiguous");
        assert_eq!(
            found,
            Ambiguity::DotSegment {
                segment: "..".to_string(),
                passes: 0
            }
        );
        assert!(found.describe().contains(".."), "{}", found.describe());
    }

    /// Every encoding of the same traversal the audit demonstrated, plus the
    /// double-encoded form a second decoding hop downstream would resolve.
    #[test]
    fn encoded_traversal_segments_are_ambiguous_at_every_depth() {
        for path in [
            "/repos/%2e%2e/user/keys",         // percent-encoded dots
            "/repos/%2E%2E/user/keys",         // upper-case hex
            "/repos/%2e%2E/user/keys",         // mixed case
            "/repos/%2E%2E%2Fuser/keys",       // encoded separator too
            "/repos/%252e%252e/user/keys",     // double-encoded
            "/repos/%25252e%25252e/user/keys", // triple-encoded
            "/repos/..;/user/keys",            // `;`-parameter after the dots
            "/repos/..;a=b/user/keys",
            "/repos//../user/emails", // empty segment before the dots
            "/repos/./user/keys",     // single-dot segment
            "/repos/foo/..",          // trailing traversal
            "..",                     // nothing but a traversal
            // A raw `#` does not end the scan: an origin-form target carries no
            // fragment (RFC 9112 §3.2.1), so whether the upstream splits there is its
            // business, not something to assume. Truncating hid this one.
            "/repos/x#/../user/keys",
            "/repos/x#/%2e%2e/user/keys", // ...and still after a decode pass
            // Backslash separators: WHATWG folds `\` onto `/` for http(s).
            "/repos/..\\..\\user/keys",
            "/repos/foo\\../user/keys",
            "/repos/%5c..%5c/user/keys", // encoded backslash, caught after decoding
            "/repos/..%5C../user/keys",  // the spec's own backslash-traversal example
        ] {
            let found = ambiguity(path);
            assert!(
                matches!(found, Some(Ambiguity::DotSegment { .. })),
                "{path} must be ambiguous, got {found:?}"
            );
        }
    }

    /// A path we cannot decode is a path whose meaning we cannot know, so it is
    /// denied rather than guessed at — including the overlong-UTF-8 dot trick.
    #[test]
    fn an_undecodable_path_is_ambiguous() {
        for path in ["/repos/%zz/foo", "/repos/%2/foo", "/repos/foo%", "/%"] {
            assert_eq!(
                ambiguity(path),
                Some(Ambiguity::MalformedEscape),
                "{path} must be reported as undecodable"
            );
        }
        for path in ["/repos/%ff/foo", "/repos/%c0%ae%c0%ae/user/keys"] {
            assert_eq!(
                ambiguity(path),
                Some(Ambiguity::NonUtf8),
                "{path} must be reported as non-UTF-8"
            );
        }
    }

    /// The paths a real API call carries must still reach policy, or the fix trades a
    /// wrong allow for a daemon that denies everything interesting.
    #[test]
    fn ordinary_paths_are_not_ambiguous() {
        for path in [
            "/repos/foo/bar",
            "/",
            "",
            "/repos/foo/bar/contents/src/main.rs",
            "/repos/foo..bar/x",         // dots inside a segment, not a segment
            "/repos/...",                // three dots is a name, not a traversal
            "/repos/.hidden",            // leading dot is a name
            "/repos/foo/bar?ref=..",     // a `..` in the query cannot move the route
            "/repos/foo/bar?path=../x",  // ditto, the common API-parameter shape
            "/repos/foo/bar?q=..\\..",   // backslashes in a query are data too
            "/search?q=..%2F..%2Fetc",   // encoded traversal in a query value is data
            "/repos/foo/bar#..",         // `bar#..` is one segment, not a `..` segment
            "/issues/issue#5",           // a raw `#` alone is not traversal
            "/repos/foo/bar\\baz",       // a backslash alone is not traversal either
            "/repos/50%25-done",         // legitimately encoded `%`, decodes to `50%-done`
            "/repos/foo%2Fbar/contents", // encoded separator, no traversal
            "/repos/caf%C3%A9",          // ordinary UTF-8 escape
            "/repos/foo/bar;a=b",        // `;`-parameter on an ordinary segment
        ] {
            assert_eq!(ambiguity(path), None, "{path} must reach policy");
        }
    }

    /// The check runs on the routing part only, but an *encoded* `?` is not a
    /// separator to the upstream either, so it must not be used to hide a traversal.
    #[test]
    fn an_encoded_question_mark_does_not_hide_a_traversal() {
        assert!(matches!(
            ambiguity("/repos/x%3f/../user/keys"),
            Some(Ambiguity::DotSegment { .. })
        ));
    }

    /// A `.` hidden under more nesting than we follow is refused rather than quietly
    /// treated as unambiguous. `%2e` is `.`, `%252e` is `%2e`, `%25252e` is `%252e`:
    /// each extra `25` costs one decode pass.
    #[test]
    fn nesting_beyond_the_decode_bound_is_ambiguous() {
        let deep = format!("/repos/%{}2e/x", "25".repeat(MAX_DECODE_PASSES + 1));
        assert_eq!(ambiguity(&deep), Some(Ambiguity::NestedTooDeep));
        // Inside the bound the same shape resolves and is caught as the dot segment
        // it is, so the bound is what the deny above is really about.
        let shallow = format!("/repos/%{}2e/x", "25".repeat(MAX_DECODE_PASSES - 2));
        assert!(
            matches!(ambiguity(&shallow), Some(Ambiguity::DotSegment { .. })),
            "{shallow} -> {:?}",
            ambiguity(&shallow)
        );
    }

    /// Each variant has to say *which* ambiguity it is: the reason lands in nono's
    /// audit trail, and "denied" without the cause is not actionable.
    ///
    /// Asserting a length here would be hollow — four variants all returning the same
    /// sentence would pass it. So this pins the distinguishing token of each variant and
    /// that no two descriptions coincide.
    #[test]
    fn every_ambiguity_describes_itself() {
        let cases = [
            (
                Ambiguity::DotSegment {
                    segment: "..".to_string(),
                    passes: 2,
                },
                vec!["\"..\"", "after 2 percent-decode passes", "normalising"],
            ),
            (Ambiguity::MalformedEscape, vec!["malformed percent-escape"]),
            (Ambiguity::NonUtf8, vec!["not UTF-8"]),
            (
                Ambiguity::NestedTooDeep,
                vec!["nests deeper than", "decode"],
            ),
        ];

        let mut seen: Vec<String> = Vec::new();
        for (found, must_mention) in cases {
            let text = found.describe();
            for token in must_mention {
                assert!(
                    text.contains(token),
                    "{found:?} must name its cause: expected {token:?} in {text:?}"
                );
            }
            assert!(
                !text.chars().any(char::is_control),
                "a reason reaches nono's audit trail, so it must carry no control bytes: \
                 {text:?}"
            );
            assert!(
                !seen.contains(&text),
                "two variants share a description, so the reason cannot identify which \
                 ambiguity was found: {text:?}"
            );
            seen.push(text);
        }
    }

    /// The `passes` count is part of the cause, not decoration: an operator reading the
    /// audit trail needs to know whether the traversal was visible in the path as sent or
    /// only surfaced after decoding.
    #[test]
    fn a_dot_segment_reports_the_decode_depth_it_surfaced_at() {
        let described = |passes| {
            Ambiguity::DotSegment {
                segment: "..".to_string(),
                passes,
            }
            .describe()
        };
        assert!(described(0).contains("in the path as sent"), "{}", described(0));
        assert!(
            described(1).contains("after one percent-decode pass"),
            "{}",
            described(1)
        );
        assert!(
            described(3).contains("after 3 percent-decode passes"),
            "{}",
            described(3)
        );
    }
}
