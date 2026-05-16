//! Erlang heap term decoder for OTP crash dump format.
//!
//! Parses the textual heap-term encoding used in `erl_crash.dump` files into
//! an `ErlTerm` tree, then pretty-prints using the same string heuristics as
//! Erlang's `io_lib:printable_latin1_list/1`.
//!
//! # String heuristic
//!
//! A list (or binary) is rendered as a quoted string if and only if every
//! element / byte is a *printable Latin-1 character*:
//! - Printable: `32..=126` (space – tilde), `160..=255` (Latin-1 supplement),
//!   plus whitespace escapes `\b`(8) `\t`(9) `\n`(10) `\v`(11) `\f`(12)
//!   `\r`(13) `\e`(27).
//! - Everything else (including 0-7, 14-26, 28-31, 127-159) → NOT printable.
//!
//! Matches `io_lib:printable_latin1_list/1` in `OTP/lib/stdlib/src/io_lib.erl`.

use std::io::Write;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use base64::Engine;
use crashdump_db::Reader;

// ─── Term representation ────────────────────────────────────────────────────

/// An Erlang term decoded from a crash dump heap encoding.
#[derive(Debug, Clone)]
pub enum ErlTerm {
    /// `[]`
    Nil,
    /// Small integer (`I<decimal>`)
    Integer(i64),
    /// Big integer — stored as a display string like `16#BEEF` or `-16#BEEF`
    BigInt(String),
    /// Float (`F<hexlen>:<chars>`)
    Float(f64),
    /// Atom (`A<hexlen>:<chars>`)
    Atom(String),
    /// PID (`P<N.M.K>`)
    Pid(String),
    /// Port (`p<N.M>`)
    Port(String),
    /// Binary blob (`Yh`, `Yc`, `Ys`)
    Binary(Vec<u8>),
    /// Cons cell (`l<head>|<tail>`)
    Cons(Box<ErlTerm>, Box<ErlTerm>),
    /// Tuple (`t<n>:<e1>,…`)
    Tuple(Vec<ErlTerm>),
    /// Map (`Mf` or `Mh`) — flattened key-value pairs
    Map(Vec<(ErlTerm, ErlTerm)>),
    /// Info string (`S<text>`) — rest of line, shown verbatim
    InfoString(String),
    /// ETF-encoded term (`E<hexlen>:<base64>`) — raw bytes shown as hex
    ExternalTerm(Vec<u8>),
    /// Heap pointer that had no entry in the address store
    NotInDump(u64),
}

// ─── Printer / parser ───────────────────────────────────────────────────────

const MAX_DEPTH: usize = 128;

/// Decodes Erlang heap terms from a crash dump address store.
pub struct TermDecoder {
    db: Arc<Reader>,
    depth: usize,
}

impl TermDecoder {
    /// Create a new decoder backed by the given address store.
    pub fn new(db: Arc<Reader>) -> Self {
        TermDecoder { db, depth: 0 }
    }

    fn deeper(&self) -> Self {
        TermDecoder {
            db: Arc::clone(&self.db),
            depth: self.depth + 1,
        }
    }

    // ─── Public parse entry points ──────────────────────────────────────────

    /// Parse a single term from the beginning of `s`.
    /// Returns `(term, remainder)`.
    pub fn parse_term<'a>(&self, s: &'a str) -> Result<(ErlTerm, &'a str)> {
        if self.depth > MAX_DEPTH {
            return Ok((ErlTerm::InfoString("...depth limit...".into()), s));
        }
        let s = s.trim_start_matches(' ');
        if s.is_empty() {
            bail!("unexpected end of input in parse_term");
        }
        match s.as_bytes()[0] {
            b'N' => Ok((ErlTerm::Nil, &s[1..])),
            b'I' => parse_integer(&s[1..]),
            b'A' => parse_atom(&s[1..]),
            b'H' => self.follow_ptr(&s[1..]),
            b'P' => parse_pid(&s[1..]),
            b'p' => parse_port(&s[1..]),
            b'S' => Ok((ErlTerm::InfoString(s[1..].to_string()), "")),
            b'l' => self.parse_cons(&s[1..]),
            b't' => self.parse_tuple(&s[1..]),
            b'F' => parse_float(&s[1..]),
            b'B' => parse_bigint(&s[1..]),
            b'Y' => self.parse_binary(s),
            b'M' => self.parse_map(s),
            b'E' => parse_external(&s[1..]),
            b'D' => Ok((ErlTerm::InfoString("#DistExternal".into()), "")),
            b => bail!(
                "unknown term tag {:?} in {:?}",
                b as char,
                &s[..s.len().min(20)]
            ),
        }
    }

    // ─── Individual term parsers ─────────────────────────────────────────────

    fn follow_ptr<'a>(&self, s: &'a str) -> Result<(ErlTerm, &'a str)> {
        let (addr, rest) = parse_hex_u64(s)?;
        match self.db.get(addr)? {
            None => Ok((ErlTerm::NotInDump(addr), rest)),
            Some(bytes) => {
                let content = std::str::from_utf8(&bytes)
                    .context("heap entry not valid UTF-8")?;
                let (term, _) = self.deeper().parse_term(content)?;
                Ok((term, rest))
            }
        }
    }

    fn parse_cons<'a>(&self, s: &'a str) -> Result<(ErlTerm, &'a str)> {
        let (head, after_head) = self.parse_term(s)?;
        let after_pipe = after_head.strip_prefix('|').ok_or_else(|| {
            anyhow::anyhow!(
                "expected '|' in cons, got {:?}",
                &after_head[..after_head.len().min(10)]
            )
        })?;
        let (tail, rest) = self.parse_term(after_pipe)?;
        Ok((ErlTerm::Cons(Box::new(head), Box::new(tail)), rest))
    }

    fn parse_tuple<'a>(&self, s: &'a str) -> Result<(ErlTerm, &'a str)> {
        // t<hexn>:<e1>,<e2>,...
        let (n, after_n) = parse_hex_u64(s)?;
        let after_colon = after_n
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("expected ':' after tuple arity"))?;
        if n == 0 {
            return Ok((ErlTerm::Tuple(vec![]), after_colon));
        }
        let (elements, rest) = self.parse_n_terms(n as usize, after_colon)?;
        Ok((ErlTerm::Tuple(elements), rest))
    }

    fn parse_binary<'a>(&self, s: &'a str) -> Result<(ErlTerm, &'a str)> {
        match s.as_bytes().get(1) {
            Some(b'h') => {
                // Yh<hexbytelen>:<base64>
                let (bytes, rest) = parse_binary_data(&s[2..])?;
                Ok((ErlTerm::Binary(bytes), rest))
            }
            Some(b'c') | Some(b's') => {
                // Yc<hexaddr>:<hexoffset>:<hexsize> or Ys...
                self.deref_binary(&s[2..])
            }
            _ => bail!("unknown binary kind in {:?}", &s[..s.len().min(5)]),
        }
    }

    fn deref_binary<'a>(&self, s: &'a str) -> Result<(ErlTerm, &'a str)> {
        let (addr, s) = parse_hex_u64(s)?;
        let s = s
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("expected ':' in binary ref (offset)"))?;
        let (offset, s) = parse_hex_u64(s)?;
        let s = s
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("expected ':' in binary ref (size)"))?;
        let (size, rest) = parse_hex_u64(s)?;
        let bytes = match self.db.get(addr)? {
            None => vec![],
            Some(raw) => {
                let off = offset as usize;
                let sz = size as usize;
                let end = (off + sz).min(raw.len());
                raw[off.min(raw.len())..end].to_vec()
            }
        };
        Ok((ErlTerm::Binary(bytes), rest))
    }

    fn parse_map<'a>(&self, s: &'a str) -> Result<(ErlTerm, &'a str)> {
        match s.as_bytes().get(1) {
            Some(b'f') => self.parse_flat_map(&s[2..]),
            Some(b'h') => self.parse_hashmap_head(&s[2..]),
            Some(b'n') => self.parse_hashmap_node(&s[2..]),
            _ => bail!("unknown map kind in {:?}", &s[..s.len().min(5)]),
        }
    }

    fn parse_flat_map<'a>(&self, s: &'a str) -> Result<(ErlTerm, &'a str)> {
        // Mf<hexsize>:<t<n>:k1,k2,...>:<v1>,<v2>,...
        let (size, s) = parse_hex_u64(s)?;
        let s = s
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("expected ':' after flat map size"))?;
        // Keys are a tuple term
        let (keys_term, after_keys) = self.parse_term(s)?;
        let keys = match keys_term {
            ErlTerm::Tuple(v) => v,
            other => bail!("expected tuple for flat map keys, got {other:?}"),
        };
        let after_keys = after_keys
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("expected ':' after flat map keys"))?;
        let n = size as usize;
        let (values, rest) = if n > 0 {
            self.parse_n_terms(n, after_keys)?
        } else {
            (vec![], after_keys)
        };
        let pairs = keys.into_iter().zip(values).collect();
        Ok((ErlTerm::Map(pairs), rest))
    }

    fn parse_hashmap_head<'a>(&self, s: &'a str) -> Result<(ErlTerm, &'a str)> {
        // Mh<hexmapsize>:<hexn>:<nodes...>
        let (_mapsize, s) = parse_hex_u64(s)?;
        let s = s
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("expected ':' after hashmap head mapsize"))?;
        let (n, s) = parse_hex_u64(s)?;
        let s = s
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("expected ':' after hashmap head n"))?;
        let (nodes, rest) = if n > 0 {
            self.parse_n_terms(n as usize, s)?
        } else {
            (vec![], s)
        };
        let pairs = flatten_hashmap_nodes(&nodes);
        Ok((ErlTerm::Map(pairs), rest))
    }

    fn parse_hashmap_node<'a>(&self, s: &'a str) -> Result<(ErlTerm, &'a str)> {
        // Mn<hexn>:<nodes...> — rendered as Tuple so flatten_hashmap_nodes can recurse
        let (n, s) = parse_hex_u64(s)?;
        let s = s
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("expected ':' after hashmap node n"))?;
        let (nodes, rest) = if n > 0 {
            self.parse_n_terms(n as usize, s)?
        } else {
            (vec![], s)
        };
        Ok((ErlTerm::Tuple(nodes), rest))
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /// Parse exactly `n` comma-separated terms.
    fn parse_n_terms<'a>(&self, n: usize, s: &'a str) -> Result<(Vec<ErlTerm>, &'a str)> {
        let mut terms = Vec::with_capacity(n);
        let mut s = s;
        for i in 0..n {
            let (t, rest) = self.parse_term(s)?;
            terms.push(t);
            if i + 1 < n {
                s = rest.strip_prefix(',').ok_or_else(|| {
                    anyhow::anyhow!(
                        "expected ',' between terms (at element {}/{}), got {:?}",
                        i + 1,
                        n,
                        &rest[..rest.len().min(15)]
                    )
                })?;
            } else {
                s = rest;
            }
        }
        Ok((terms, s))
    }
}

// ─── Free-function parsers ───────────────────────────────────────────────────

fn parse_integer(s: &str) -> Result<(ErlTerm, &str)> {
    let (n, rest) = parse_decimal_i64(s)?;
    Ok((ErlTerm::Integer(n), rest))
}

fn parse_atom(s: &str) -> Result<(ErlTerm, &str)> {
    // A<hexlen>:<chars>
    let (len, s) = parse_hex_u64(s)?;
    let s = s
        .strip_prefix(':')
        .ok_or_else(|| anyhow::anyhow!("expected ':' in atom"))?;
    let len = len as usize;
    if s.len() < len {
        bail!("atom content truncated: need {} bytes, have {}", len, s.len());
    }
    let name = s[..len].to_string();
    Ok((ErlTerm::Atom(name), &s[len..]))
}

fn parse_pid(s: &str) -> Result<(ErlTerm, &str)> {
    let (inner, rest) = parse_angle_brackets(s)?;
    Ok((ErlTerm::Pid(inner), rest))
}

fn parse_port(s: &str) -> Result<(ErlTerm, &str)> {
    let (inner, rest) = parse_angle_brackets(s)?;
    Ok((ErlTerm::Port(inner), rest))
}

fn parse_angle_brackets(s: &str) -> Result<(String, &str)> {
    let s = s
        .strip_prefix('<')
        .ok_or_else(|| anyhow::anyhow!("expected '<' for pid/port"))?;
    let end = s
        .find('>')
        .ok_or_else(|| anyhow::anyhow!("no '>' for pid/port"))?;
    Ok((s[..end].to_string(), &s[end + 1..]))
}

fn parse_float(s: &str) -> Result<(ErlTerm, &str)> {
    // F<hexlen>:<chars>
    let (len, s) = parse_hex_u64(s)?;
    let s = s
        .strip_prefix(':')
        .ok_or_else(|| anyhow::anyhow!("expected ':' in float"))?;
    let len = len as usize;
    if s.len() < len {
        bail!("float content truncated");
    }
    let f: f64 = s[..len]
        .parse()
        .with_context(|| format!("parsing float {:?}", &s[..len]))?;
    Ok((ErlTerm::Float(f), &s[len..]))
}

fn parse_bigint(s: &str) -> Result<(ErlTerm, &str)> {
    // B16#<hex>  |  B-16#<hex>  |  B<decimal>
    if let Some(hex) = s.strip_prefix("16#") {
        let end = hex
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(hex.len());
        Ok((ErlTerm::BigInt(format!("16#{}", &hex[..end])), &hex[end..]))
    } else if let Some(hex) = s.strip_prefix("-16#") {
        let end = hex
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(hex.len());
        Ok((ErlTerm::BigInt(format!("-16#{}", &hex[..end])), &hex[end..]))
    } else {
        // Plain decimal bigint
        let end = s
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(s.len());
        if end == 0 {
            bail!("empty bigint in {:?}", &s[..s.len().min(10)]);
        }
        Ok((ErlTerm::BigInt(s[..end].to_string()), &s[end..]))
    }
}

fn parse_binary_data(s: &str) -> Result<(Vec<u8>, &str)> {
    // <hexbytelen>:<base64>
    let (byte_len, s) = parse_hex_u64(s)?;
    let s = s
        .strip_prefix(':')
        .ok_or_else(|| anyhow::anyhow!("expected ':' in binary data"))?;
    let byte_len = byte_len as usize;
    let b64_len = ((byte_len + 2) / 3) * 4;
    let b64 = &s[..b64_len.min(s.len())];
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64))
        .with_context(|| format!("decoding base64 binary ({byte_len} bytes)"))?;
    Ok((bytes, &s[b64_len..]))
}

fn parse_external(s: &str) -> Result<(ErlTerm, &str)> {
    let (bytes, rest) = parse_binary_data(s)?;
    // Try to decode the ETF bytes into an ErlTerm for human-readable display.
    let term = if bytes.first() == Some(&131) {
        etf_decode(&bytes[1..]).unwrap_or(ErlTerm::ExternalTerm(bytes))
    } else {
        ErlTerm::ExternalTerm(bytes)
    };
    Ok((term, rest))
}

// ─── ETF (External Term Format) decoder ─────────────────────────────────────

fn etf_decode(data: &[u8]) -> Result<ErlTerm> {
    let (term, _) = etf_term(data)?;
    Ok(term)
}

fn etf_term(data: &[u8]) -> Result<(ErlTerm, &[u8])> {
    let (tag, rest) = data.split_first().ok_or_else(|| anyhow::anyhow!("ETF: empty"))?;
    match tag {
        // SMALL_INTEGER_EXT
        97 => {
            let (b, r) = rest.split_first().ok_or_else(|| anyhow::anyhow!("ETF small_int short"))?;
            Ok((ErlTerm::Integer(*b as i64), r))
        }
        // INTEGER_EXT
        98 => {
            if rest.len() < 4 { anyhow::bail!("ETF integer short") }
            let n = i32::from_be_bytes(rest[..4].try_into().unwrap());
            Ok((ErlTerm::Integer(n as i64), &rest[4..]))
        }
        // NEW_FLOAT_EXT
        70 => {
            if rest.len() < 8 { anyhow::bail!("ETF new_float short") }
            let f = f64::from_be_bytes(rest[..8].try_into().unwrap());
            Ok((ErlTerm::Float(f), &rest[8..]))
        }
        // FLOAT_EXT (old 31-byte text)
        99 => {
            if rest.len() < 31 { anyhow::bail!("ETF float short") }
            let s = std::str::from_utf8(&rest[..31]).unwrap_or("0.0").trim_matches('\0');
            let f: f64 = s.parse().unwrap_or(0.0);
            Ok((ErlTerm::Float(f), &rest[31..]))
        }
        // ATOM_EXT (latin-1, 2-byte len)
        100 => etf_atom2(rest),
        // SMALL_ATOM_EXT (latin-1, 1-byte len)
        115 => etf_atom1(rest),
        // ATOM_UTF8_EXT (2-byte len)
        118 => etf_atom2(rest),
        // SMALL_ATOM_UTF8_EXT (1-byte len)
        119 => etf_atom1(rest),
        // NIL_EXT
        106 => Ok((ErlTerm::Nil, rest)),
        // STRING_EXT (compact list-of-chars; display as binary)
        107 => {
            if rest.len() < 2 { anyhow::bail!("ETF string short") }
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if rest.len() < 2 + len { anyhow::bail!("ETF string truncated") }
            Ok((ErlTerm::Binary(rest[2..2+len].to_vec()), &rest[2+len..]))
        }
        // BINARY_EXT
        109 => {
            if rest.len() < 4 { anyhow::bail!("ETF binary short") }
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            if rest.len() < 4 + len { anyhow::bail!("ETF binary truncated") }
            Ok((ErlTerm::Binary(rest[4..4+len].to_vec()), &rest[4+len..]))
        }
        // BIT_BINARY_EXT
        77 => {
            if rest.len() < 5 { anyhow::bail!("ETF bit_binary short") }
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            // rest[4] = bits in last byte (ignore for display)
            if rest.len() < 5 + len { anyhow::bail!("ETF bit_binary truncated") }
            Ok((ErlTerm::Binary(rest[5..5+len].to_vec()), &rest[5+len..]))
        }
        // SMALL_BIG_EXT
        110 => {
            let (n, r) = rest.split_first().ok_or_else(|| anyhow::anyhow!("ETF small_big short"))?;
            let n = *n as usize;
            if r.len() < 1 + n { anyhow::bail!("ETF small_big truncated") }
            let neg = r[0] != 0;
            Ok((ErlTerm::BigInt(etf_bignum(&r[1..1+n], neg)), &r[1+n..]))
        }
        // LARGE_BIG_EXT
        111 => {
            if rest.len() < 4 { anyhow::bail!("ETF large_big short") }
            let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            if rest.len() < 5 + n { anyhow::bail!("ETF large_big truncated") }
            let neg = rest[4] != 0;
            Ok((ErlTerm::BigInt(etf_bignum(&rest[5..5+n], neg)), &rest[5+n..]))
        }
        // SMALL_TUPLE_EXT
        104 => {
            let (arity, r) = rest.split_first().ok_or_else(|| anyhow::anyhow!("ETF small_tuple short"))?;
            etf_tuple(*arity as usize, r)
        }
        // LARGE_TUPLE_EXT
        105 => {
            if rest.len() < 4 { anyhow::bail!("ETF large_tuple short") }
            let arity = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            etf_tuple(arity, &rest[4..])
        }
        // LIST_EXT
        108 => {
            if rest.len() < 4 { anyhow::bail!("ETF list short") }
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            let mut cur = &rest[4..];
            let mut elems = Vec::with_capacity(len);
            for _ in 0..len {
                let (e, r) = etf_term(cur)?;
                elems.push(e);
                cur = r;
            }
            let (tail, cur) = etf_term(cur)?;
            let mut result = tail;
            for e in elems.into_iter().rev() {
                result = ErlTerm::Cons(Box::new(e), Box::new(result));
            }
            Ok((result, cur))
        }
        // MAP_EXT
        116 => {
            if rest.len() < 4 { anyhow::bail!("ETF map short") }
            let arity = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            let mut cur = &rest[4..];
            let mut pairs = Vec::with_capacity(arity);
            for _ in 0..arity {
                let (k, r) = etf_term(cur)?;
                let (v, r) = etf_term(r)?;
                pairs.push((k, v));
                cur = r;
            }
            Ok((ErlTerm::Map(pairs), cur))
        }
        // NEWER_REFERENCE_EXT (90) | NEW_REFERENCE_EXT (114) | REFERENCE_EXT (101)
        90 | 114 | 101 => etf_reference(*tag, rest),
        // NEW_PID_EXT (88) | PID_EXT (103)
        88 | 103 => etf_pid(*tag, rest),
        // NEW_PORT_EXT (89) | PORT_EXT (102)
        89 | 102 => etf_port(*tag, rest),
        // EXPORT_EXT: {module, function, arity}
        113 => {
            let (m, r) = etf_term(rest)?;
            let (f, r) = etf_term(r)?;
            let (a, r) = etf_term(r)?;
            Ok((ErlTerm::Tuple(vec![m, f, a]), r))
        }
        // NEW_FUN_EXT: Size(4), Arity(1), Uniq(16), Index(4), NumFree(4),
        //              Module, OldIndex, OldUniq, Pid, Free[NumFree]
        // Size includes the tag byte → remainder = rest[Size-1..]
        112 => {
            if rest.len() < 29 { anyhow::bail!("ETF new_fun short") }
            let size = u32::from_be_bytes(rest[0..4].try_into().unwrap()) as usize;
            if rest.len() + 1 < size { anyhow::bail!("ETF new_fun truncated") }
            // fixed header: Size(4)+Arity(1)+Uniq(16)+Index(4)+NumFree(4) = 29 bytes
            let (module, r) = etf_term(&rest[29..])?;
            let (old_idx, r) = etf_term(r)?;
            let (old_uniq, _) = etf_term(r)?;
            Ok((etf_fun_term(&module, &old_idx, &old_uniq), &rest[size - 1..]))
        }
        // FUN_EXT: NumFree(4), Pid, Module, Index, Uniq, Free[NumFree]
        117 => {
            if rest.len() < 4 { anyhow::bail!("ETF fun_ext short") }
            let num_free = u32::from_be_bytes(rest[0..4].try_into().unwrap()) as usize;
            let (_, r) = etf_term(&rest[4..])?; // skip Pid
            let (module, r) = etf_term(r)?;
            let (idx, r) = etf_term(r)?;
            let (uniq, mut r) = etf_term(r)?;
            for _ in 0..num_free { let (_, nr) = etf_term(r)?; r = nr; }
            Ok((etf_fun_term(&module, &idx, &uniq), r))
        }
        _ => anyhow::bail!("ETF: unknown tag {tag}"),
    }
}

fn etf_atom1(data: &[u8]) -> Result<(ErlTerm, &[u8])> {
    let (len_b, r) = data.split_first().ok_or_else(|| anyhow::anyhow!("ETF atom1 short"))?;
    let len = *len_b as usize;
    if r.len() < len { anyhow::bail!("ETF atom1 truncated") }
    Ok((ErlTerm::Atom(String::from_utf8_lossy(&r[..len]).into_owned()), &r[len..]))
}

fn etf_atom2(data: &[u8]) -> Result<(ErlTerm, &[u8])> {
    if data.len() < 2 { anyhow::bail!("ETF atom2 short") }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len { anyhow::bail!("ETF atom2 truncated") }
    Ok((ErlTerm::Atom(String::from_utf8_lossy(&data[2..2+len]).into_owned()), &data[2+len..]))
}

fn etf_tuple(arity: usize, mut data: &[u8]) -> Result<(ErlTerm, &[u8])> {
    let mut elems = Vec::with_capacity(arity);
    for _ in 0..arity {
        let (e, r) = etf_term(data)?;
        elems.push(e);
        data = r;
    }
    Ok((ErlTerm::Tuple(elems), data))
}

fn etf_bignum(digits: &[u8], neg: bool) -> String {
    // digits are little-endian base-256; convert to hex
    let hex: String = digits.iter().rev().map(|b| format!("{b:02X}")).collect();
    let hex = hex.trim_start_matches('0');
    let hex = if hex.is_empty() { "0" } else { hex };
    if neg { format!("-16#{hex}") } else { format!("16#{hex}") }
}

fn etf_reference(tag: u8, data: &[u8]) -> Result<(ErlTerm, &[u8])> {
    match tag {
        // NEWER_REFERENCE_EXT: 2-byte id_count, node_atom, 4-byte creation, 4*n id bytes
        90 => {
            if data.len() < 2 { anyhow::bail!("ETF newer_ref short") }
            let id_count = u16::from_be_bytes([data[0], data[1]]) as usize;
            let (_node, rest) = etf_term(&data[2..])?;
            if rest.len() < 4 + 4 * id_count { anyhow::bail!("ETF newer_ref truncated") }
            let creation = u32::from_be_bytes(rest[..4].try_into().unwrap());
            let ids: Vec<u32> = (0..id_count)
                .map(|i| u32::from_be_bytes(rest[4+4*i..8+4*i].try_into().unwrap()))
                .collect();
            let id_str = ids.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".");
            Ok((ErlTerm::InfoString(format!("#Ref<{creation}.{id_str}>")), &rest[4+4*id_count..]))
        }
        // NEW_REFERENCE_EXT: 2-byte id_count, node_atom, 1-byte creation, 4*n id bytes
        114 => {
            if data.len() < 2 { anyhow::bail!("ETF new_ref short") }
            let id_count = u16::from_be_bytes([data[0], data[1]]) as usize;
            let (_node, rest) = etf_term(&data[2..])?; // node atom (not used in display)
            if rest.len() < 1 + 4 * id_count { anyhow::bail!("ETF new_ref truncated") }
            let creation = rest[0] as u32;
            let ids: Vec<u32> = (0..id_count)
                .map(|i| u32::from_be_bytes(rest[1+4*i..5+4*i].try_into().unwrap()))
                .collect();
            let id_str = ids.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".");
            Ok((ErlTerm::InfoString(format!("#Ref<{creation}.{id_str}>")), &rest[1+4*id_count..]))
        }
        // REFERENCE_EXT (old): node_atom, 4-byte id, 1-byte creation
        101 => {
            let (_, rest) = etf_term(data)?;
            if rest.len() < 5 { anyhow::bail!("ETF ref short") }
            let id = u32::from_be_bytes(rest[..4].try_into().unwrap());
            let creation = rest[4] as u32;
            Ok((ErlTerm::InfoString(format!("#Ref<{creation}.{id}>")), &rest[5..]))
        }
        _ => unreachable!(),
    }
}

fn etf_pid(tag: u8, data: &[u8]) -> Result<(ErlTerm, &[u8])> {
    let (node, rest) = etf_term(data)?;
    let node_str = match &node { ErlTerm::Atom(s) => s.clone(), _ => "?".into() };
    match tag {
        // NEW_PID_EXT: node, id:4, serial:4, creation:4
        88 => {
            if rest.len() < 12 { anyhow::bail!("ETF new_pid short") }
            let id       = u32::from_be_bytes(rest[0..4].try_into().unwrap());
            let serial   = u32::from_be_bytes(rest[4..8].try_into().unwrap());
            let creation = u32::from_be_bytes(rest[8..12].try_into().unwrap());
            Ok((ErlTerm::Pid(format!("{node_str}.{id}.{serial}.{creation}")), &rest[12..]))
        }
        // PID_EXT: node, id:4, serial:4, creation:1
        103 => {
            if rest.len() < 9 { anyhow::bail!("ETF pid short") }
            let id       = u32::from_be_bytes(rest[0..4].try_into().unwrap());
            let serial   = u32::from_be_bytes(rest[4..8].try_into().unwrap());
            let creation = rest[8] as u32;
            Ok((ErlTerm::Pid(format!("{node_str}.{id}.{serial}.{creation}")), &rest[9..]))
        }
        _ => unreachable!(),
    }
}

fn etf_port(tag: u8, data: &[u8]) -> Result<(ErlTerm, &[u8])> {
    let (node, rest) = etf_term(data)?;
    let node_str = match &node { ErlTerm::Atom(s) => s.clone(), _ => "?".into() };
    match tag {
        // NEW_PORT_EXT: node, id:4, creation:4
        89 => {
            if rest.len() < 8 { anyhow::bail!("ETF new_port short") }
            let id       = u32::from_be_bytes(rest[0..4].try_into().unwrap());
            let creation = u32::from_be_bytes(rest[4..8].try_into().unwrap());
            Ok((ErlTerm::Port(format!("{node_str}.{id}.{creation}")), &rest[8..]))
        }
        // PORT_EXT: node, id:4, creation:1
        102 => {
            if rest.len() < 5 { anyhow::bail!("ETF port short") }
            let id       = u32::from_be_bytes(rest[0..4].try_into().unwrap());
            let creation = rest[4] as u32;
            Ok((ErlTerm::Port(format!("{node_str}.{id}.{creation}")), &rest[5..]))
        }
        _ => unreachable!(),
    }
}

fn etf_fun_term(module: &ErlTerm, idx: &ErlTerm, uniq: &ErlTerm) -> ErlTerm {
    let m = match module { ErlTerm::Atom(s) => s.as_str(), _ => "?" };
    let i = match idx   { ErlTerm::Integer(n) => n.to_string(), _ => "?".into() };
    let u = match uniq  {
        ErlTerm::Integer(n) => n.to_string(),
        ErlTerm::BigInt(s)  => s.clone(),
        _ => "?".into(),
    };
    ErlTerm::InfoString(format!("#Fun<{m}.{i}.{u}>"))
}


fn parse_hex_u64(s: &str) -> Result<(u64, &str)> {
    let end = s
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(s.len());
    if end == 0 {
        bail!("expected hex digits, got {:?}", &s[..s.len().min(10)]);
    }
    let val = u64::from_str_radix(&s[..end], 16)
        .with_context(|| format!("parsing hex {:?}", &s[..end]))?;
    Ok((val, &s[end..]))
}

fn parse_decimal_i64(s: &str) -> Result<(i64, &str)> {
    let start = if s.starts_with('-') { 1 } else { 0 };
    let end = s[start..]
        .find(|c: char| !c.is_ascii_digit())
        .map(|i| i + start)
        .unwrap_or(s.len());
    if end == start {
        bail!("expected decimal digits in {:?}", &s[..s.len().min(10)]);
    }
    let val: i64 = s[..end]
        .parse()
        .with_context(|| format!("parsing integer {:?}", &s[..end]))?;
    Ok((val, &s[end..]))
}

// ─── Flatten HAMT nodes ──────────────────────────────────────────────────────

/// Recursively collect key-value pairs from parsed hashmap nodes.
///
/// Hashmap interior nodes (`Mn`) are parsed as `Tuple(nodes)`.
/// Key-value slots are `Cons(key, val)` (from `l<k>|<v>`).
/// Nested sub-maps are `Map(pairs)`.
fn flatten_hashmap_nodes(nodes: &[ErlTerm]) -> Vec<(ErlTerm, ErlTerm)> {
    let mut pairs = Vec::new();
    for node in nodes {
        collect_pairs(node, &mut pairs);
    }
    pairs
}

fn collect_pairs(node: &ErlTerm, out: &mut Vec<(ErlTerm, ErlTerm)>) {
    match node {
        ErlTerm::Cons(k, v) => out.push((*k.clone(), *v.clone())),
        ErlTerm::Tuple(inner) => {
            for n in inner {
                collect_pairs(n, out);
            }
        }
        ErlTerm::Map(inner_pairs) => {
            out.extend(inner_pairs.iter().cloned());
        }
        _ => {}
    }
}

// ─── Pretty printer ──────────────────────────────────────────────────────────

/// Write `term` as Erlang source syntax to `out`.
pub fn print_term<W: Write>(term: &ErlTerm, out: &mut W) -> std::io::Result<()> {
    match term {
        ErlTerm::Nil => write!(out, "[]"),
        ErlTerm::Integer(n) => write!(out, "{n}"),
        ErlTerm::BigInt(s) => write!(out, "{s}"),
        ErlTerm::Float(f) => write_float(*f, out),
        ErlTerm::Atom(s) => write_atom(s, out),
        ErlTerm::Pid(s) => write!(out, "<{s}>"),
        ErlTerm::Port(s) => write!(out, "#Port<{s}>"),
        ErlTerm::Binary(bytes) => write_binary(bytes, out),
        ErlTerm::InfoString(s) => write!(out, "{s}"),
        ErlTerm::ExternalTerm(bytes) => {
            write!(out, "#ETF<<")?;
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    write!(out, ",")?;
                }
                write!(out, "{b}")?;
            }
            write!(out, ">>")
        }
        ErlTerm::NotInDump(_addr) => write!(out, "(dump_truncated)"),
        ErlTerm::Cons(_, _) => {
            let (elems, tail) = flatten_list(term);
            write_list(&elems, tail, out)
        }
        ErlTerm::Tuple(elements) => {
            write!(out, "{{")?;
            for (i, el) in elements.iter().enumerate() {
                if i > 0 {
                    write!(out, ",")?;
                }
                print_term(el, out)?;
            }
            write!(out, "}}")
        }
        ErlTerm::Map(pairs) => {
            write!(out, "#{{")?;
            for (i, (k, v)) in pairs.iter().enumerate() {
                if i > 0 {
                    write!(out, ",")?;
                }
                print_term(k, out)?;
                write!(out, " => ")?;
                print_term(v, out)?;
            }
            write!(out, "}}")
        }
    }
}

fn flatten_list(term: &ErlTerm) -> (Vec<&ErlTerm>, &ErlTerm) {
    let mut elements = Vec::new();
    let mut current = term;
    loop {
        match current {
            ErlTerm::Cons(head, tail) => {
                elements.push(head.as_ref());
                current = tail.as_ref();
            }
            other => return (elements, other),
        }
    }
}

/// Try to render `elems` as a string literal; fall back to list syntax.
fn write_list<W: Write>(
    elems: &[&ErlTerm],
    tail: &ErlTerm,
    out: &mut W,
) -> std::io::Result<()> {
    // String heuristic: proper list where every element is a printable char
    if matches!(tail, ErlTerm::Nil) && !elems.is_empty() {
        if let Some(chars) = try_as_char_codes(elems) {
            return write_string_literal(&chars, out);
        }
    }
    // General list
    write!(out, "[")?;
    for (i, el) in elems.iter().enumerate() {
        if i > 0 {
            write!(out, ",")?;
        }
        print_term(el, out)?;
    }
    if !matches!(tail, ErlTerm::Nil) {
        write!(out, "|")?;
        print_term(tail, out)?;
    }
    write!(out, "]")
}

/// If every element is a printable character code, return them; otherwise `None`.
fn try_as_char_codes(elems: &[&ErlTerm]) -> Option<Vec<u32>> {
    let mut codes = Vec::with_capacity(elems.len());
    for el in elems {
        match el {
            ErlTerm::Integer(n) if *n >= 0 => {
                if is_latin1_printable(*n as u32) {
                    codes.push(*n as u32);
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some(codes)
}

// ─── Printable character classification (matches OTP io_lib) ────────────────

/// Returns `true` iff `c` is a printable Latin-1 character per
/// `io_lib:printable_latin1_list/1`.
///
/// Printable: 32-126 (ASCII printable), 160-255 (Latin-1 supplement),
/// and the whitespace escapes 8 (\b), 9 (\t), 10 (\n), 11 (\v),
/// 12 (\f), 13 (\r), 27 (\e).
pub fn is_latin1_printable(c: u32) -> bool {
    matches!(c, 32..=126 | 160..=255 | 8 | 9 | 10 | 11 | 12 | 13 | 27)
}

// ─── Character / string rendering ───────────────────────────────────────────

fn write_string_literal<W: Write>(chars: &[u32], out: &mut W) -> std::io::Result<()> {
    write!(out, "\"")?;
    for &c in chars {
        write_char_in_string(c, out)?;
    }
    write!(out, "\"")
}

/// Write a single character code inside a double-quoted string.
/// Assumes `c` is already known to be `is_latin1_printable`.
fn write_char_in_string<W: Write>(c: u32, out: &mut W) -> std::io::Result<()> {
    match c {
        34 => write!(out, "\\\""),  // "
        92 => write!(out, "\\\\"),  // \
        8 => write!(out, "\\b"),
        9 => write!(out, "\\t"),
        10 => write!(out, "\\n"),
        11 => write!(out, "\\v"),
        12 => write!(out, "\\f"),
        13 => write!(out, "\\r"),
        27 => write!(out, "\\e"),
        32..=126 => {
            out.write_all(&[c as u8])
        }
        160..=255 => {
            // Latin-1 supplement: encode as UTF-8 (two bytes: 0xC0|hi, 0x80|lo)
            let ch = char::from_u32(c).unwrap();
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            out.write_all(s.as_bytes())
        }
        // Anything else that somehow slipped through: octal escape
        other => {
            let c1 = (other >> 6) & 7;
            let c2 = (other >> 3) & 7;
            let c3 = other & 7;
            write!(out, "\\{c1}{c2}{c3}")
        }
    }
}

fn write_binary<W: Write>(bytes: &[u8], out: &mut W) -> std::io::Result<()> {
    // String heuristic: non-empty and every byte is a printable Latin-1 char
    if !bytes.is_empty() && bytes.iter().all(|&b| is_latin1_printable(b as u32)) {
        write!(out, "<<\"")?;
        for &b in bytes {
            write_char_in_string(b as u32, out)?;
        }
        write!(out, "\">>")?;
    } else {
        write!(out, "<<")?;
        for (i, &b) in bytes.iter().enumerate() {
            if i > 0 {
                write!(out, ",")?;
            }
            write!(out, "{b}")?;
        }
        write!(out, ">>")?;
    }
    Ok(())
}

fn write_float<W: Write>(f: f64, out: &mut W) -> std::io::Result<()> {
    if f.is_nan() {
        write!(out, "nan")
    } else if f.is_infinite() {
        if f > 0.0 {
            write!(out, "inf")
        } else {
            write!(out, "-inf")
        }
    } else {
        let s = format!("{f}");
        if s.contains('.') || s.contains('e') || s.contains('E') {
            write!(out, "{s}")
        } else {
            write!(out, "{s}.0")
        }
    }
}

/// Write an atom, quoting with `'` if necessary.
///
/// An atom needs quoting when:
/// - It is empty
/// - It is an Erlang reserved word
/// - Its first character is not a lowercase ASCII letter
/// - Any subsequent character is not alphanumeric, `_`, or `@`
fn write_atom<W: Write>(name: &str, out: &mut W) -> std::io::Result<()> {
    if needs_atom_quoting(name) {
        write!(out, "'")?;
        for c in name.chars() {
            match c {
                '\'' => write!(out, "\\'")?,
                '\\' => write!(out, "\\\\")?,
                '\n' => write!(out, "\\n")?,
                '\t' => write!(out, "\\t")?,
                '\r' => write!(out, "\\r")?,
                _ => write!(out, "{c}")?,
            }
        }
        write!(out, "'")
    } else {
        write!(out, "{name}")
    }
}

fn needs_atom_quoting(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    // Must start with a lowercase ASCII letter
    if !first.is_ascii_lowercase() {
        return true;
    }
    // Remaining must be alphanumeric, '_', or '@'
    for c in chars {
        if !c.is_alphanumeric() && c != '_' && c != '@' {
            return true;
        }
    }
    // Reserved words (erl_scan:reserved_word/1)
    matches!(
        name,
        "after"
            | "and"
            | "andalso"
            | "band"
            | "begin"
            | "bnot"
            | "bor"
            | "bsl"
            | "bsr"
            | "bxor"
            | "case"
            | "catch"
            | "cond"
            | "div"
            | "else"
            | "end"
            | "fun"
            | "if"
            | "let"
            | "maybe"
            | "not"
            | "of"
            | "or"
            | "orelse"
            | "query"
            | "receive"
            | "rem"
            | "try"
            | "when"
            | "xor"
    )
}

// ─── JSON serialization ──────────────────────────────────────────────────────

/// Serialise a decoded Erlang term to a compact JSON value for client-side
/// pretty-printing.
///
/// Type tags (`"t"` field):
/// - Structural: `"tuple"`, `"list"`, `"map"`
/// - String-like: `"str"` (printable char-code list), `"bin"` (binary)
/// - Scalars: `"nil"`, `"int"`, `"bigint"`, `"float"`, `"atom"`, `"pid"`,
///   `"port"`, `"info"`, `"etf"`, `"missing"`
///
/// String heuristic: proper lists of printable Latin-1 character codes are
/// represented as `{"t":"str","v":"..."}` rather than arrays of integers,
/// matching the flat printer's heuristic and keeping the JSON compact.
/// Binaries whose bytes are all printable use `{"t":"bin","str":"..."}`;
/// others use `{"t":"bin","hex":"deadbeef"}`.
pub fn term_to_json(term: &ErlTerm) -> serde_json::Value {
    use serde_json::{Value, json};

    match term {
        ErlTerm::Nil => json!({"t": "nil"}),
        ErlTerm::Integer(n) => json!({"t": "int", "v": n}),
        ErlTerm::BigInt(s) => json!({"t": "bigint", "v": s}),
        ErlTerm::Float(f) => {
            if f.is_finite() {
                json!({"t": "float", "v": f})
            } else {
                // NaN / Inf are not representable as JSON numbers.
                let s = if f.is_nan() { "nan" } else if *f > 0.0 { "inf" } else { "-inf" };
                json!({"t": "float", "v": s})
            }
        }
        ErlTerm::Atom(s) => json!({"t": "atom", "v": s}),
        ErlTerm::Pid(s) => json!({"t": "pid", "v": s}),
        ErlTerm::Port(s) => json!({"t": "port", "v": s}),
        ErlTerm::Binary(bytes) => {
            if !bytes.is_empty() && bytes.iter().all(|&b| is_latin1_printable(b as u32)) {
                let s: String = bytes.iter().map(|&b| b as char).collect();
                json!({"t": "bin", "str": s})
            } else {
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                json!({"t": "bin", "hex": hex})
            }
        }
        ErlTerm::InfoString(s) => json!({"t": "info", "v": s}),
        ErlTerm::ExternalTerm(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            json!({"t": "etf", "hex": hex})
        }
        ErlTerm::NotInDump(_addr) => json!({"t": "missing", "v": "(dump_truncated)"}),
        ErlTerm::Cons(_, _) => {
            let (elems, tail) = flatten_list(term);
            // Compact representation for printable char-code lists (Erlang strings).
            if matches!(tail, ErlTerm::Nil) {
                if let Some(codes) = try_as_char_codes(&elems) {
                    let s: String = codes.iter().filter_map(|&c| char::from_u32(c)).collect();
                    return json!({"t": "str", "v": s});
                }
            }
            let elems_json: Vec<Value> = elems.iter().map(|e| term_to_json(e)).collect();
            let tail_json = if matches!(tail, ErlTerm::Nil) {
                Value::Null
            } else {
                term_to_json(tail)
            };
            json!({"t": "list", "elems": elems_json, "tail": tail_json})
        }
        ErlTerm::Tuple(elems) => {
            let elems_json: Vec<Value> = elems.iter().map(term_to_json).collect();
            json!({"t": "tuple", "elems": elems_json})
        }
        ErlTerm::Map(pairs) => {
            let pairs_json: Vec<Value> = pairs
                .iter()
                .map(|(k, v)| json!({"k": term_to_json(k), "v": term_to_json(v)}))
                .collect();
            json!({"t": "map", "pairs": pairs_json})
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn print(term: &ErlTerm) -> String {
        let mut buf = Vec::new();
        print_term(term, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn test_printable_chars() {
        assert!(is_latin1_printable(32)); // space
        assert!(is_latin1_printable(65)); // 'A'
        assert!(is_latin1_printable(126)); // '~'
        assert!(is_latin1_printable(10)); // \n
        assert!(is_latin1_printable(9)); // \t
        assert!(is_latin1_printable(27)); // \e
        assert!(is_latin1_printable(160)); // NBSP
        assert!(is_latin1_printable(255)); // ÿ
        // NOT printable:
        assert!(!is_latin1_printable(0));
        assert!(!is_latin1_printable(7)); // BEL — NOT in OTP list
        assert!(!is_latin1_printable(31));
        assert!(!is_latin1_printable(127)); // DEL
        assert!(!is_latin1_printable(128));
        assert!(!is_latin1_printable(159));
    }

    #[test]
    fn test_nil() {
        assert_eq!(print(&ErlTerm::Nil), "[]");
    }

    #[test]
    fn test_integer() {
        assert_eq!(print(&ErlTerm::Integer(42)), "42");
        assert_eq!(print(&ErlTerm::Integer(-1)), "-1");
    }

    #[test]
    fn test_atom_no_quote() {
        assert_eq!(print(&ErlTerm::Atom("ok".into())), "ok");
        assert_eq!(print(&ErlTerm::Atom("true".into())), "true");
        assert_eq!(print(&ErlTerm::Atom("hello_world".into())), "hello_world");
    }

    #[test]
    fn test_atom_needs_quote() {
        assert_eq!(print(&ErlTerm::Atom("Hello".into())), "'Hello'");
        assert_eq!(print(&ErlTerm::Atom("".into())), "''");
        assert_eq!(print(&ErlTerm::Atom("if".into())), "'if'");
        assert_eq!(print(&ErlTerm::Atom("my-atom".into())), "'my-atom'");
    }

    #[test]
    fn test_list_as_string() {
        let hello = make_list("hello");
        assert_eq!(print(&hello), "\"hello\"");
    }

    #[test]
    fn test_list_with_newline() {
        let term = cons(ErlTerm::Integer(104), // 'h'
                   cons(ErlTerm::Integer(10),  // '\n'
                   ErlTerm::Nil));
        assert_eq!(print(&term), "\"h\\n\"");
    }

    #[test]
    fn test_list_not_string_due_to_bell() {
        // 7 = BEL, not printable in OTP's latin1 list
        let term = cons(ErlTerm::Integer(104),
                   cons(ErlTerm::Integer(7),
                   ErlTerm::Nil));
        assert_eq!(print(&term), "[104,7]");
    }

    #[test]
    fn test_list_not_string_has_atom() {
        let term = cons(ErlTerm::Atom("foo".into()), ErlTerm::Nil);
        assert_eq!(print(&term), "[foo]");
    }

    #[test]
    fn test_binary_string() {
        let term = ErlTerm::Binary(b"hello".to_vec());
        assert_eq!(print(&term), "<<\"hello\">>");
    }

    #[test]
    fn test_binary_bytes() {
        let term = ErlTerm::Binary(vec![0, 1, 255]);
        assert_eq!(print(&term), "<<0,1,255>>");
    }

    #[test]
    fn test_empty_binary() {
        assert_eq!(print(&ErlTerm::Binary(vec![])), "<<>>");
    }

    #[test]
    fn test_tuple() {
        let t = ErlTerm::Tuple(vec![ErlTerm::Atom("ok".into()), ErlTerm::Integer(1)]);
        assert_eq!(print(&t), "{ok,1}");
    }

    #[test]
    fn test_map() {
        let m = ErlTerm::Map(vec![(ErlTerm::Atom("a".into()), ErlTerm::Integer(1))]);
        assert_eq!(print(&m), "#{a => 1}");
    }

    #[test]
    fn test_improper_list() {
        let t = cons(ErlTerm::Integer(1), ErlTerm::Integer(2));
        assert_eq!(print(&t), "[1|2]");
    }

    fn cons(h: ErlTerm, t: ErlTerm) -> ErlTerm {
        ErlTerm::Cons(Box::new(h), Box::new(t))
    }

    fn make_list(s: &str) -> ErlTerm {
        let mut t = ErlTerm::Nil;
        for c in s.chars().rev() {
            t = cons(ErlTerm::Integer(c as i64), t);
        }
        t
    }
}
