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
//! - Fields are split on unquoted whitespace, so columns can be aligned freely. List
//!   items within a field are split on unquoted commas.
//! - `"…"` quotes a token. Spaces are allowed inside, and `*` and `@` are taken
//!   literally, which is the one way to name a path that starts with those sigils. An
//!   unquoted token is classified like a `[[rule]]` field, so `*` is the wildcard, `@x`
//!   is a group, and anything else is a leaf path or name.
//! - `#` outside quotes starts an end-of-line comment, and blank lines are skipped.
//!
//! This module is only surface syntax. Each field becomes the same [`Token`] list that a
//! `[[rule]]` field produces, so [`super::resolve`] and every later stage stay unchanged.

use super::parse::{ParsedRule, Token};
use super::{LineIndex, parse_policy};
use crate::{Error, Result};

/// Parses the text of a `rules = '''…'''` block into rules. `content_start` is the
/// block's byte offset in the source file, so that each diagnostic reports the real
/// `line:col` in the file. Errors when a line has other than four fields, an unknown
/// policy keyword, or a malformed or unterminated quote.
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
        let policy = parse_policy(ptext).map_err(|msg| at(lines, base + pcol, msg))?;
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

/// Returns the tokens of one field's comma-separated items. A quoted item is always a
/// literal [`Token::Leaf`], and [`Token::classify`] classifies an unquoted one.
/// `field_base` is the field's absolute source offset. Errors when an item's quote is
/// malformed or unterminated.
fn field_tokens(field: &str, field_base: usize, lines: &LineIndex) -> Result<Vec<Token>> {
    let items = split_quoted(field, Sep::Comma).map_err(|(c, m)| at(lines, field_base + c, m))?;
    let mut toks = Vec::with_capacity(items.len());
    for (col, item) in items {
        let parsed = Item::parse(item).map_err(|m| at(lines, field_base + col, m))?;
        toks.extend(parsed.into_token()); // empty item (stray trailing comma) → skipped
    }
    Ok(toks)
}

/// Returns `line` cut at the first `#` that is not inside double quotes.
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

/// The separator for [`split_quoted`], one for each of the two nesting levels of the DSL.
#[derive(Clone, Copy)]
enum Sep {
    /// Splits a line into fields on runs of whitespace, so that columns can be aligned
    /// freely.
    Whitespace,
    /// Splits a field into list items on commas.
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

/// Returns the segments of `s` between `sep` boundaries, each with its byte offset in `s`.
/// A `"…"` span is never split, and a segment keeps its quotes for [`Item::parse`] to
/// strip. Errors with the offset of the opening quote when a quote is unterminated.
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
            // An empty run, such as consecutive separators or a leading or trailing one,
            // leaves `start` unset, so nothing is emitted. That collapses whitespace and
            // drops a stray `,,` or a trailing comma.
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

/// One comma-separated field item, after splitting and before classification. Quoting
/// forces a literal [`Token::Leaf`], so that `*` or `@` can name a real path, and
/// [`Token::classify`] classifies an unquoted item.
struct Item {
    content: String,
    quoted: bool,
}

impl Item {
    /// Parses one raw item, stripping an optional pair of surrounding quotes. Errors when
    /// an item that opens with `"` does not end with a closing `"`.
    fn parse(raw: &str) -> std::result::Result<Item, String> {
        match raw.strip_prefix('"') {
            Some(rest) => match rest.strip_suffix('"') {
                // An empty `rest` means the item was a lone `"` with no closing quote.
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

    /// Returns the classified [`Token`], or `None` for an empty item, such as the one
    /// after a stray trailing comma.
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

/// Returns the error at absolute source byte `abs`.
fn at(lines: &LineIndex, abs: usize, msg: impl Into<String>) -> Error {
    Error::at(lines.pos(abs), msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a block in isolation, at offset 0. Real callers pass the block's source
    /// offset, but here positions are relative to the block, which is all these tests
    /// check.
    fn block(content: &str) -> Result<Vec<ParsedRule>> {
        let lines = LineIndex::new(content);
        parse_block(content, 0, &lines)
    }

    #[test]
    fn single_rule_fields() {
        let r = block("allow /usr/bin/ssh read ~/.ssh\n").unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].policy, cordon_bpf_common::Policy::ALLOW);
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
        assert_eq!(r[0].policy, cordon_bpf_common::Policy::ALLOW);
        assert_eq!(r[1].policy, cordon_bpf_common::Policy::DENY);
    }

    #[test]
    fn quoted_path_with_spaces() {
        let r = block("allow /usr/bin/backup read \"~/My Secrets/tokens\"\n").unwrap();
        assert_eq!(r[0].where_, vec![Token::Leaf("~/My Secrets/tokens".into())]);
    }

    #[test]
    fn quoting_suppresses_sigils() {
        // A directory literally named `@weird` or `*odd` cannot be written unquoted.
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

    /// A field-level error lands on the right line and column when the block sits deeper
    /// in a file. This exercises the offset math of `content_start` plus the offset
    /// within the block.
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
