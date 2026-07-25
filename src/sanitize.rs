//! Escaping for attacker-controlled text that ends up in operator-facing output.
//!
//! The escaping is terminal-safety, not a reversible encoding: text that
//! literally spells an escape sequence (`"a\\u{001b}b"`) reads identically to an
//! escaped control, so the recorded trail is not forensically injective.

/// Replace every control character with a `\u{XXXX}` escape.
///
/// Command names, argv entries and request ids are chosen by whatever the agent
/// ran, and they end up in deny reasons, `tracing` lines and the JSONL audit
/// trail. A raw `ESC` or `CR` there lets a crafted name rewrite the line an
/// operator reads (`git\u{1b}[2K\rDENY OVERRIDDEN: decision=allow`), and a raw
/// `LF` lets it forge an extra line. Non-ASCII text is data, not control, and is
/// left untouched.
pub fn control_escape(input: &str) -> String {
    if !input.chars().any(char::is_control) {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_control() {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_escaped() {
        let hostile = "git\u{1b}[2K\rDENY OVERRIDDEN: decision=allow";
        let clean = control_escape(hostile);
        assert!(
            !clean.chars().any(char::is_control),
            "no raw control byte may survive: {clean:?}"
        );
        assert_eq!(
            clean,
            "git\\u{001b}[2K\\u{000d}DENY OVERRIDDEN: decision=allow"
        );
    }

    #[test]
    fn ordinary_text_is_untouched() {
        let plain = "denied by 10-git:no-history-rewrites (git push --force)";
        assert_eq!(control_escape(plain), plain);
        // non-ASCII is data, not control: leave it alone
        assert_eq!(control_escape("café ✓"), "café ✓");
    }

    #[test]
    fn newlines_cannot_forge_an_extra_log_line() {
        let clean = control_escape("ok\nERROR fake log line");
        assert_eq!(clean, "ok\\u{000a}ERROR fake log line");
    }
}
