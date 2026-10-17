use crate::Result;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
pub enum Probe {
    Begin,
    End,
    Interval(Duration),
    Perf {
        kind: u32,
        config: u64,
        period: u64,
        frequency: bool,
    },
}

pub const SOFTWARE: &[(&str, u64)] = &[
    ("cpu-clock", 0),
    ("task-clock", 1),
    ("page-faults", 2),
    ("faults", 2),
    ("context-switches", 3),
    ("cs", 3),
    ("cpu-migrations", 4),
    ("minor-faults", 5),
    ("major-faults", 6),
    ("alignment-faults", 7),
    ("emulation-faults", 8),
];
pub const HARDWARE: &[(&str, u64)] = &[
    ("cpu-cycles", 0),
    ("cycles", 0),
    ("instructions", 1),
    ("cache-references", 2),
    ("cache-misses", 3),
    ("branch-instructions", 4),
    ("branches", 4),
    ("branch-misses", 5),
    ("bus-cycles", 6),
    ("stalled-cycles-frontend", 7),
    ("stalled-cycles-backend", 8),
    ("ref-cycles", 9),
];

impl Probe {
    pub fn parse(text: &str) -> Result<Self> {
        let parts: Vec<_> = text.split(':').collect();
        match parts.as_slice() {
            ["BEGIN"] => Ok(Self::Begin),
            ["END"] => Ok(Self::End),
            [provider @ ("interval" | "profile"), unit, amount] => {
                let amount = positive(amount)?;
                if *unit == "hz" {
                    if amount > 1_000_000_000 {
                        return Err("frequency must be at most 1000000000 Hz".into());
                    }
                    if *provider == "profile" {
                        return Ok(Self::Perf {
                            kind: 1,
                            config: 0,
                            period: amount,
                            frequency: true,
                        });
                    }
                    return Ok(Self::Interval(Duration::from_nanos(1_000_000_000 / amount)));
                }
                let scale = match *unit {
                    "ns" => 1,
                    "us" => 1000,
                    "ms" => 1_000_000,
                    "s" => 1_000_000_000,
                    _ => return Err(format!("unknown time unit '{unit}'")),
                };
                let ns = amount
                    .checked_mul(scale)
                    .ok_or("probe period overflows u64")?;
                if *provider == "interval" {
                    Ok(Self::Interval(Duration::from_nanos(ns)))
                } else {
                    Ok(Self::Perf {
                        kind: 1,
                        config: 0,
                        period: ns,
                        frequency: false,
                    })
                }
            }
            [provider @ ("software" | "hardware"), event]
            | [provider @ ("software" | "hardware"), event, _] => {
                let (kind, events) = if *provider == "software" {
                    (1, SOFTWARE)
                } else {
                    (0, HARDWARE)
                };
                let config = events
                    .iter()
                    .find(|(name, _)| name == event)
                    .map(|(_, id)| *id)
                    .ok_or_else(|| format!("unknown {provider} event '{event}'; see --list"))?;
                let period = if parts.len() == 3 {
                    positive(parts[2])?
                } else if kind == 0 || config <= 1 {
                    1_000_000
                } else {
                    1
                };
                Ok(Self::Perf {
                    kind,
                    config,
                    period,
                    frequency: false,
                })
            }
            _ => Err(format!(
                "unsupported probe '{text}'; see --list (kernel probes and BPF are not supported)"
            )),
        }
    }
}

fn positive(s: &str) -> Result<u64> {
    let n = s
        .parse::<u64>()
        .map_err(|_| format!("expected a positive integer, got '{s}'"))?;
    if n == 0 {
        Err("probe period/frequency must be positive".into())
    } else {
        Ok(n)
    }
}

#[derive(Clone, Debug)]
pub struct Clause {
    pub probes: Vec<(String, Probe)>,
    pub predicate: Option<Expr>,
    pub body: Vec<Stmt>,
}
#[derive(Clone, Debug)]
pub enum Expr {
    Number(i64),
    String(String),
    Builtin(String),
    Local(String),
    Map(String, Vec<Expr>),
    Call(String, Vec<Expr>),
    Unary(String, Box<Expr>),
    Binary(String, Box<Expr>, Box<Expr>),
}
#[derive(Clone, Debug)]
pub enum Stmt {
    Assign(Expr, Expr),
    Increment(Expr, i64),
    Call(String, Vec<Expr>),
    If(Expr, Vec<Stmt>, Vec<Stmt>),
}

#[derive(Clone, Debug)]
enum TokenKind {
    Word(String),
    Number(i64),
    String(String),
    Symbol(String),
    Eof,
}
#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

fn lex(src: &str) -> Result<Vec<Token>> {
    let bytes = src.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            i += 2;
            while i + 1 < bytes.len() && !bytes[i..].starts_with(b"*/") {
                i += 1;
            }
            if i + 1 >= bytes.len() {
                return Err(diagnostic(src, start, "unterminated comment"));
            }
            i += 2;
            continue;
        }
        let kind = if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            TokenKind::Word(src[start..i].into())
        } else if bytes[i].is_ascii_digit() {
            i += 1;
            if bytes[start] == b'0' && i < bytes.len() && bytes[i] == b'x' {
                i += 1;
                let digits = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
                let n = u64::from_str_radix(&src[digits..i], 16).map_err(|_| {
                    diagnostic(src, start, "invalid/overflowing hexadecimal integer")
                })?;
                TokenKind::Number(n as i64)
            } else {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                TokenKind::Number(
                    src[start..i]
                        .parse::<i64>()
                        .map_err(|_| diagnostic(src, start, "integer exceeds i64"))?,
                )
            }
        } else if bytes[i] == b'"' {
            i += 1;
            let mut out = String::new();
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                    if i == bytes.len() {
                        break;
                    }
                    out.push(match bytes[i] {
                        b'n' => '\n',
                        b't' => '\t',
                        b'r' => '\r',
                        b'\\' => '\\',
                        b'"' => '"',
                        _ => return Err(diagnostic(src, i, "unsupported string escape")),
                    });
                    i += 1;
                } else {
                    let ch = src[i..].chars().next().unwrap();
                    if ch == '\0' {
                        return Err(diagnostic(src, i, "NUL is not allowed in strings"));
                    }
                    out.push(ch);
                    i += ch.len_utf8();
                }
            }
            if i == bytes.len() {
                return Err(diagnostic(src, start, "unterminated string"));
            }
            i += 1;
            TokenKind::String(out)
        } else {
            let two = bytes
                .get(i..i + 2)
                .and_then(|s| std::str::from_utf8(s).ok());
            if two.is_some_and(|s| {
                [
                    "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "++", "--", "+=", "-=",
                ]
                .contains(&s)
            }) {
                i += 2;
            } else if b"{}()[];,:/@$+-*%=!<>~&|^".contains(&bytes[i]) {
                i += 1;
            } else {
                return Err(diagnostic(src, i, "unexpected character"));
            }
            TokenKind::Symbol(src[start..i].into())
        };
        tokens.push(Token {
            kind,
            start,
            end: i,
        });
    }
    tokens.push(Token {
        kind: TokenKind::Eof,
        start: i,
        end: i,
    });
    Ok(tokens)
}

fn diagnostic(src: &str, pos: usize, message: &str) -> String {
    let line = src[..pos].bytes().filter(|b| *b == b'\n').count() + 1;
    let col = src[..pos].rsplit('\n').next().unwrap_or("").chars().count() + 1;
    format!("{line}:{col}: {message}")
}

struct Parser<'a> {
    src: &'a str,
    tokens: Vec<Token>,
    at: usize,
    depth: usize,
}
pub fn parse(src: &str) -> Result<Vec<Clause>> {
    let mut p = Parser {
        src,
        tokens: lex(src)?,
        at: 0,
        depth: 0,
    };
    let mut clauses = Vec::new();
    while !matches!(p.token().kind, TokenKind::Eof) {
        let mut probes = Vec::new();
        loop {
            let start = p.token().start;
            while !p.is("{")
                && !p.is("/")
                && !p.is(",")
                && !matches!(p.token().kind, TokenKind::Eof)
            {
                p.at += 1;
            }
            let end = if p.at == 0 {
                start
            } else {
                p.tokens[p.at.saturating_sub(1)].end
            };
            let name: String = src[start..end.max(start)]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            probes.push((
                name.clone(),
                Probe::parse(&name).map_err(|e| diagnostic(src, start, &e))?,
            ));
            if !p.eat(",") {
                break;
            }
        }
        let predicate = if p.eat("/") {
            let e = p.expr(0)?;
            p.expect("/")?;
            Some(e)
        } else {
            None
        };
        let body = p.block()?;
        clauses.push(Clause {
            probes,
            predicate,
            body,
        });
    }
    if clauses.is_empty() {
        return Err("script has no probes".into());
    }
    Ok(clauses)
}

impl Parser<'_> {
    fn token(&self) -> &Token {
        &self.tokens[self.at]
    }
    fn is(&self, s: &str) -> bool {
        matches!(&self.token().kind, TokenKind::Symbol(v) | TokenKind::Word(v) if v == s)
    }
    fn eat(&mut self, s: &str) -> bool {
        if self.is(s) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn error(&self, s: &str) -> String {
        diagnostic(self.src, self.token().start, s)
    }
    fn expect(&mut self, s: &str) -> Result<()> {
        if self.eat(s) {
            Ok(())
        } else {
            Err(self.error(&format!("expected '{s}'")))
        }
    }
    fn word(&mut self) -> Result<String> {
        if let TokenKind::Word(w) = self.token().kind.clone() {
            self.at += 1;
            Ok(w)
        } else {
            Err(self.error("expected identifier"))
        }
    }
    fn block(&mut self) -> Result<Vec<Stmt>> {
        self.depth += 1;
        if self.depth > 128 {
            return Err(self.error("nesting exceeds 128 levels"));
        }
        self.expect("{")?;
        let mut stmts = Vec::new();
        while !self.eat("}") {
            if self.eat("if") {
                self.expect("(")?;
                let e = self.expr(0)?;
                self.expect(")")?;
                let yes = self.block()?;
                let no = if self.eat("else") {
                    self.block()?
                } else {
                    Vec::new()
                };
                stmts.push(Stmt::If(e, yes, no));
                continue;
            }
            let lhs = self.expr(0)?;
            let stmt = if self.eat("=") {
                Stmt::Assign(lhs, self.expr(0)?)
            } else if self.eat("++") {
                Stmt::Increment(lhs, 1)
            } else if self.eat("--") {
                Stmt::Increment(lhs, -1)
            } else if self.is("+=") || self.is("-=") {
                let op = if self.eat("+=") {
                    "+"
                } else {
                    self.at += 1;
                    "-"
                };
                let rhs = self.expr(0)?;
                Stmt::Assign(
                    lhs.clone(),
                    Expr::Binary(op.into(), Box::new(lhs), Box::new(rhs)),
                )
            } else if let Expr::Call(name, args) = lhs {
                Stmt::Call(name, args)
            } else {
                return Err(self.error("expected assignment, increment, or function call"));
            };
            if !self.is("}") {
                self.expect(";")?;
            } else {
                self.eat(";");
            }
            stmts.push(stmt);
        }
        self.depth -= 1;
        Ok(stmts)
    }
    fn expr(&mut self, min: u8) -> Result<Expr> {
        self.depth += 1;
        if self.depth > 128 {
            return Err(self.error("nesting exceeds 128 levels"));
        }
        let mut lhs = if self.is("-") || self.is("!") || self.is("~") || self.is("+") {
            let op = self.src[self.token().start..self.token().end].into();
            self.at += 1;
            Expr::Unary(op, Box::new(self.expr(11)?))
        } else if self.eat("(") {
            let e = self.expr(0)?;
            self.expect(")")?;
            e
        } else if self.eat("$") {
            Expr::Local(self.word()?)
        } else if self.eat("@") {
            let name = if matches!(self.token().kind, TokenKind::Word(_)) {
                self.word()?
            } else {
                String::new()
            };
            let keys = if self.eat("[") {
                self.args("]")?
            } else {
                Vec::new()
            };
            Expr::Map(name, keys)
        } else {
            let kind = self.token().kind.clone();
            match kind {
                TokenKind::Number(n) => {
                    self.at += 1;
                    Expr::Number(n)
                }
                TokenKind::String(s) => {
                    self.at += 1;
                    Expr::String(s)
                }
                TokenKind::Word(w) => {
                    self.at += 1;
                    if self.eat("(") {
                        Expr::Call(w, self.args(")")?)
                    } else {
                        Expr::Builtin(w)
                    }
                }
                _ => return Err(self.error("expected expression")),
            }
        };
        let mut operators = 0;
        while let TokenKind::Symbol(op) = &self.token().kind {
            // A predicate's closing slash is followed by its block, unlike division.
            if op == "/"
                && matches!(&self.tokens[self.at + 1].kind, TokenKind::Symbol(s) if s == "{")
            {
                break;
            }
            let prec = match op.as_str() {
                "||" => 1,
                "&&" => 2,
                "|" => 3,
                "^" => 4,
                "&" => 5,
                "==" | "!=" => 6,
                "<" | "<=" | ">" | ">=" => 7,
                "<<" | ">>" => 8,
                "+" | "-" => 9,
                "*" | "/" | "%" => 10,
                _ => break,
            };
            if prec < min {
                break;
            }
            operators += 1;
            if operators > 128 {
                return Err(self.error("expression exceeds 128 operators"));
            }
            let op = op.clone();
            self.at += 1;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(self.expr(prec + 1)?));
        }
        self.depth -= 1;
        Ok(lhs)
    }
    fn args(&mut self, end: &str) -> Result<Vec<Expr>> {
        let mut args = Vec::new();
        if self.eat(end) {
            return Ok(args);
        }
        loop {
            args.push(self.expr(0)?);
            if args.len() > 16 {
                return Err(self.error("at most 16 arguments/keys are supported"));
            }
            if self.eat(end) {
                return Ok(args);
            }
            self.expect(",")?;
        }
    }
}
