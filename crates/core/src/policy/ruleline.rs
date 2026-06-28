//! The compact rule DSL carried in a TOML literal `rules = '''…'''` block.
//!
//! One rule per line, four whitespace-separated fields:
//!
//! ```text
//! POLICY  SUBJECT[,SUBJECT…]  ACTION[,ACTION…]  OBJECT[,OBJECT…]
//! #   e.g.
//! allow   /usr/bin/ssh        read              ~/.ssh
//! audit   *                   @rwc              @secrets
//! deny    /usr/bin/docker,/usr/lib/docker/cli-plugins/docker-buildx  read  @kube-docker
//! allow   /usr/bin/backup     read              "~/My Secrets/tokens"
//! ```
//!
//! - **Fields** are split on unquoted whitespace (so columns can be aligned freely);
//!   **list items** within a field are split on unquoted commas.
//! - `"…"` quotes a token: spaces are allowed inside, and `*` / `@` are taken
//!   **literally** (the one way to name a path that starts with those sigils). An
//!   unquoted token is classified like a `[[rule]]` field — `*` → wildcard, `@x` →
//!   group, else a leaf path/name.
//! - `#` starts an end-of-line comment (outside quotes); blank lines are skipped.
//!
//! This module is *only* surface syntax: each field becomes the same [`Token`] list a
//! `[[rule]]` field produces, so [`super::resolve`] and everything downstream are
//! unchanged. The literal-string content is a verbatim slice of the source, so byte
//! offsets here map to exact file positions for diagnostics.

use super::parse::{ParsedRule, Token};
use super::{LineIndex, PolicyName};
use crate::{Error, Result};

/// Parse a `rules = '''…'''` block into rules. `content` is the literal block text;
/// `content_start` is its absolute byte offset in the source file, so a diagnostic
/// reports the real file `line:col` via `lines`.
pub(crate) fn parse_block(
    content: &str,
    content_start: usize,
    lines: &LineIndex,
) -> Result<Vec<ParsedRule>> {
    let mut out = Vec::new();
    let mut line_off = 0usize; // byte offset of the current line within `content`
    for raw in content.split_inclusive('\n') {
        let base = content_start + line_off;
        line_off += raw.len();

        // Strip the trailing newline (and a CR) and any `#` comment, then the fields.
        let mut line = raw.strip_suffix('\n').unwrap_or(raw);
        line = line.strip_suffix('\r').unwrap_or(line);
        let body = strip_comment(line);

        let fields =
            split_quoted(body, Sep::Whitespace).map_err(|(c, m)| at(lines, base + c, m))?;
        if fields.is_empty() {
            continue; // blank or comment-only line
        }
        if fields.len() != 4 {
            let col = fields.first().map_or(0, |f| f.0);
            return Err(at(
                lines,
                base + col,
                format!(
                    "rule needs 4 fields `POLICY SUBJECT ACTION OBJECT`, found {}",
                    fields.len()
                ),
            ));
        }

        let (pcol, ptext) = fields[0];
        let policy = PolicyName::parse(ptext).ok_or_else(|| {
            at(
                lines,
                base + pcol,
                format!("unknown policy {ptext:?} (expected allow, deny, audit, or silence)"),
            )
        })?;
        let who = field_tokens(fields[1].1, base + fields[1].0, lines)?;
        let action = field_tokens(fields[2].1, base + fields[2].0, lines)?;
        let where_ = field_tokens(fields[3].1, base + fields[3].0, lines)?;

        out.push(ParsedRule {
            who,
            where_,
            action,
            policy,
            pos: lines.pos(base + pcol),
        });
    }
    Ok(out)
}

/// Split one field into comma-separated items, each classified to a [`Token`]: a
/// quoted item is always a literal [`Token::Leaf`] (sigils inert); an unquoted item is
/// [`Token::classify`]d. `field_base` is the field's absolute source offset.
fn field_tokens(field: &str, field_base: usize, lines: &LineIndex) -> Result<Vec<Token>> {
    let items = split_quoted(field, Sep::Comma).map_err(|(c, m)| at(lines, field_base + c, m))?;
    let mut toks = Vec::with_capacity(items.len());
    for (col, item) in items {
        let parsed = Item::parse(item).map_err(|m| at(lines, field_base + col, m))?;
        toks.extend(parsed.into_token()); // empty item (stray trailing comma) → skipped
    }
    Ok(toks)
}

/// Truncate `line` at the first `#` that is not inside double quotes.
fn strip_comment(line: &str) -> &str {
    let mut in_quote = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quote = !in_quote,
            '#' if !in_quote => return &line[..i],
            _ => {}
        }
    }
    line
}

/// What separates segments in [`split_quoted`]: the two nesting levels of the DSL.
#[derive(Clone, Copy)]
enum Sep {
    /// Top level: fields, split on runs of whitespace (free column alignment).
    Whitespace,
    /// Within a field: list items, split on commas.
    Comma,
}

impl Sep {
    fn is_boundary(self, c: char) -> bool {
        match self {
            Sep::Whitespace => c.is_whitespace(),
            Sep::Comma => c == ',',
        }
    }
}

/// Split `s` into segments separated by `sep`, with `"…"` spans never split. Returns
/// each segment's byte offset within `s` and its raw text (quotes retained —
/// [`Item::parse`] strips them). `Err((col, msg))` on an unterminated quote, positioned
/// at the opening quote.
fn split_quoted(s: &str, sep: Sep) -> std::result::Result<Vec<(usize, &str)>, (usize, String)> {
    let mut segs = Vec::new();
    let mut in_quote = false;
    let mut start: Option<usize> = None;
    let mut quote_at = 0usize;
    for (i, c) in s.char_indices() {
        if in_quote {
            if c == '"' {
                in_quote = false;
            }
            continue;
        }
        if c == '"' {
            in_quote = true;
            quote_at = i;
            start.get_or_insert(i);
        } else if sep.is_boundary(c) {
            // Close the current segment. An empty run (consecutive separators, or a
            // leading/trailing one) leaves `start` unset, so nothing is emitted —
            // whitespace collapses and a stray `,,`/trailing comma is dropped.
            if let Some(st) = start.take() {
                segs.push((st, &s[st..i]));
            }
        } else {
            start.get_or_insert(i);
        }
    }
    if in_quote {
        return Err((
            quote_at,
            "unterminated quote (missing closing `\"`)".to_string(),
        ));
    }
    if let Some(st) = start.take() {
        segs.push((st, &s[st..]));
    }
    Ok(segs)
}

/// One comma-separated field item, after splitting but before classification: the raw
/// text with its optional `"…"` quotes resolved into `content` + a `quoted` flag.
/// Quoting forces a literal [`Token::Leaf`] (so `*`/`@` can name a real path); an
/// unquoted item is [`Token::classify`]d.
struct Item {
    content: String,
    quoted: bool,
}

impl Item {
    /// Strip an optional surrounding `"…"`. A token that opens with `"` must close
    /// with `"` and nothing after it.
    fn parse(raw: &str) -> std::result::Result<Item, String> {
        match raw.strip_prefix('"') {
            Some(rest) => match rest.strip_suffix('"') {
                // `rest.is_empty()` ⇒ the item was a lone `"`; no closing quote.
                Some(inner) if !rest.is_empty() => Ok(Item {
                    content: inner.to_string(),
                    quoted: true,
                }),
                _ => Err(format!("malformed quoted token {raw:?}")),
            },
            None => Ok(Item {
                content: raw.to_string(),
                quoted: false,
            }),
        }
    }

    /// The classified [`Token`], or `None` for an empty item (e.g. a stray trailing
    /// comma) the caller skips.
    fn into_token(self) -> Option<Token> {
        if self.content.is_empty() {
            None
        } else if self.quoted {
            Some(Token::Leaf(self.content))
        } else {
            Some(Token::classify(&self.content))
        }
    }
}

/// A `line:col`-prefixed error at absolute source byte `abs` (same shape as
/// [`super::resolve`]'s diagnostics, so `cordon policy check` renders them uniformly).
fn at(lines: &LineIndex, abs: usize, msg: impl Into<String>) -> Error {
    Error::msg(format!("{}: {}", lines.pos(abs), msg.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a block in isolation (offset 0). Real callers pass the block's source
    /// offset; here positions are block-relative, which is all these tests check.
    fn block(content: &str) -> Result<Vec<ParsedRule>> {
        let lines = LineIndex::new(content);
        parse_block(content, 0, &lines)
    }

    #[test]
    fn single_rule_fields() {
        let r = block("allow /usr/bin/ssh read ~/.ssh\n").unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].policy, PolicyName::Allow);
        assert_eq!(r[0].who, vec![Token::Leaf("/usr/bin/ssh".into())]);
        assert_eq!(r[0].action, vec![Token::Leaf("read".into())]);
        assert_eq!(r[0].where_, vec![Token::Leaf("~/.ssh".into())]);
    }

    #[test]
    fn wildcard_group_and_comma_lists() {
        let r = block("audit * @rwc @secrets\ndeny /a,/b read,write ~/.x,~/.y\n").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].who, vec![Token::Wildcard]);
        assert_eq!(r[0].action, vec![Token::Group("rwc".into())]);
        assert_eq!(r[0].where_, vec![Token::Group("secrets".into())]);
        assert_eq!(
            r[1].who,
            vec![Token::Leaf("/a".into()), Token::Leaf("/b".into())]
        );
        assert_eq!(
            r[1].action,
            vec![Token::Leaf("read".into()), Token::Leaf("write".into())]
        );
        assert_eq!(
            r[1].where_,
            vec![Token::Leaf("~/.x".into()), Token::Leaf("~/.y".into())]
        );
    }

    #[test]
    fn blank_lines_and_comments_skipped() {
        let r = block(
            "# a header comment\n\
             allow /usr/bin/ssh read ~/.ssh   # inline comment\n\
             \n   \n\
             deny * @rwc ~/.npmrc\n",
        )
        .unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].policy, PolicyName::Allow);
        assert_eq!(r[1].policy, PolicyName::Deny);
    }

    #[test]
    fn quoted_path_with_spaces() {
        let r = block("allow /usr/bin/backup read \"~/My Secrets/tokens\"\n").unwrap();
        assert_eq!(r[0].where_, vec![Token::Leaf("~/My Secrets/tokens".into())]);
    }

    #[test]
    fn quoting_suppresses_sigils() {
        // A dir literally named `@weird` or `*odd` — unrepresentable unquoted.
        let r = block("allow /usr/bin/x read \"@weird\",\"*odd\"\n").unwrap();
        assert_eq!(
            r[0].where_,
            vec![Token::Leaf("@weird".into()), Token::Leaf("*odd".into())]
        );
    }

    #[test]
    fn quoted_item_inside_comma_list() {
        // The comma inside the quotes must not split the item.
        let r = block("allow \"/a,b\",/usr/bin/x read ~/.x\n").unwrap();
        assert_eq!(
            r[0].who,
            vec![Token::Leaf("/a,b".into()), Token::Leaf("/usr/bin/x".into())]
        );
    }

    #[test]
    fn wrong_arity_is_an_error() {
        let err = format!("{}", block("allow /usr/bin/ssh read\n").unwrap_err());
        assert!(err.contains("4 fields"), "got: {err}");
        assert!(err.starts_with("1:1"), "should point at the line: {err}");
    }

    #[test]
    fn unknown_policy_keyword_is_an_error() {
        let err = format!(
            "{}",
            block("allowe /usr/bin/ssh read ~/.ssh\n").unwrap_err()
        );
        assert!(err.contains("unknown policy"), "got: {err}");
        assert!(err.starts_with("1:1"), "points at the policy field: {err}");
    }

    #[test]
    fn unterminated_quote_is_an_error() {
        let err = format!("{}", block("allow /usr/bin/x read \"~/oops\n").unwrap_err());
        assert!(err.contains("unterminated quote"), "got: {err}");
    }

    /// A field-level error lands on the right line *and* column when the block sits
    /// deeper in a file — exercising the `content_start` + intra-block offset math.
    #[test]
    fn diagnostic_position_is_file_absolute() {
        // Simulate a block whose content starts at file line 5, col 1.
        let preamble = "user = \"nb\"\nrules = '''\n"; // 2 lines
        let content = "allow /usr/bin/ssh read ~/.ssh\nfrob * @rwc ~/.x\n";
        let full = format!("{preamble}{content}'''\n");
        let lines = LineIndex::new(&full);
        let content_start = preamble.len();
        let err = format!(
            "{}",
            parse_block(content, content_start, &lines).unwrap_err()
        );
        // `frob` is the policy field on the 2nd content line = file line 4, col 1.
        assert!(err.starts_with("4:1"), "got: {err}");
        assert!(err.contains("unknown policy"), "got: {err}");
    }
}
