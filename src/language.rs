use crate::Result;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
pub enum Probe {
    Begin,
    End,
    Interval(Duration),
    Wait(Duration),
    Wakeup(Duration),
    OffCpu,
    Uprobe {
        path: String,
        function: String,
        ret: bool,
    },
    Watchpoint {
        address: u64,
        length: u64,
        access: u32,
    },
    Syscall {
        enter: bool,
        number: Option<i64>,
    },
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
        if let Some(rest) = text.strip_prefix("usdt:") {
            let Self::Uprobe { path, function, .. } = Self::parse(&format!("uprobe:{rest}"))?
            else {
                unreachable!()
            };
            if !function.contains(':') {
                return Err("usdt requires PATH:PROVIDER:NAME".into());
            }
            return Ok(Self::Uprobe {
                path,
                function: format!("__usdt__{function}"),
                ret: false,
            });
        }
        if let Some((rest, ret)) = text
            .strip_prefix("uprobe:")
            .map(|rest| (rest, false))
            .or_else(|| text.strip_prefix("uretprobe:").map(|rest| (rest, true)))
        {
            let mut quoted = false;
            let mut escaped = false;
            let mut split = None;
            for (index, c) in rest.char_indices() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if c == '\\' && quoted {
                    escaped = true;
                    continue;
                }
                if c == '"' {
                    quoted = !quoted;
                } else if c == ':' && !quoted {
                    split = Some(index);
                    break;
                }
            }
            let split = split.ok_or("uprobe requires PATH:SYMBOL or PATH:0xFILE_OFFSET")?;
            let component = |raw: &str| -> Result<String> {
                if raw.starts_with('"') {
                    let tokens = lex(raw)?;
                    if tokens.len() == 2 {
                        if let TokenKind::String(value) = &tokens[0].kind {
                            return Ok(value.clone());
                        }
                    }
                    return Err("invalid quoted uprobe component".into());
                }
                Ok(raw.to_string())
            };
            let path = component(&rest[..split])?;
            let function = component(&rest[split + 1..])?;
            if function.starts_with("__sdt__") || function.starts_with("__usdt__") {
                return Err("reserved internal probe encoding; use usdt:PATH:PROVIDER:NAME".into());
            }
            if path.is_empty() || function.is_empty() {
                return Err("uprobe needs a nonempty path and function".into());
            }
            return Ok(Self::Uprobe {
                path,
                function,
                ret,
            });
        }
        let parts: Vec<_> = text.split(':').collect();
        match parts.as_slice() {
            ["BEGIN"] => Ok(Self::Begin),
            ["END"] => Ok(Self::End),
            ["offcpu"] => Ok(Self::OffCpu),
            ["syscall", direction, name] if *direction == "enter" || *direction == "exit" => {
                let number = if *name == "*" {
                    None
                } else {
                    Some(crate::syscall::number(name).ok_or_else(|| {
                        format!("unknown syscall '{name}'; use a native syscall number or '*'")
                    })?)
                };
                Ok(Self::Syscall {
                    enter: *direction == "enter",
                    number,
                })
            }
            ["watchpoint", address, length, mode] => {
                let address = unsigned(address)?;
                let length = unsigned(length)?;
                let access = match *mode {
                    "r" => 1,
                    "w" => 2,
                    "rw" => 3,
                    "x" => 4,
                    _ => return Err("watchpoint access must be r, w, rw, or x".into()),
                };
                if ![1, 2, 4, 8].contains(&length) || address == 0 || address % length != 0 {
                    return Err("watchpoint needs a nonzero, naturally aligned address and length 1, 2, 4, or 8".into());
                }
                Ok(Self::Watchpoint {
                    address,
                    length,
                    access,
                })
            }
            ["raw", config] | ["raw", config, _] => Ok(Self::Perf {
                kind: 4,
                config: unsigned(config)?,
                period: if parts.len() == 3 {
                    positive(parts[2])?
                } else {
                    1_000_000
                },
                frequency: false,
            }),
            ["pmu", name, config] | ["pmu", name, config, _] => {
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                {
                    return Err("invalid PMU name".into());
                }
                let kind =
                    std::fs::read_to_string(format!("/sys/bus/event_source/devices/{name}/type"))
                        .map_err(|e| format!("PMU {name}: {e}"))?
                        .trim()
                        .parse::<u32>()
                        .map_err(|e| e.to_string())?;
                Ok(Self::Perf {
                    kind,
                    config: unsigned(config)?,
                    period: if parts.len() == 4 {
                        positive(parts[3])?
                    } else {
                        1_000_000
                    },
                    frequency: false,
                })
            }
            ["cache", cache, operation, result] | ["cache", cache, operation, result, _] => {
                let cache = match *cache {
                    "l1d" => 0,
                    "l1i" => 1,
                    "ll" => 2,
                    "dtlb" => 3,
                    "itlb" => 4,
                    "branch" => 5,
                    "node" => 6,
                    _ => {
                        return Err(
                            "unknown cache; use l1d, l1i, ll, dtlb, itlb, branch, or node".into(),
                        );
                    }
                };
                let op = match *operation {
                    "read" => 0,
                    "write" => 1,
                    "prefetch" => 2,
                    _ => return Err("cache operation must be read, write, or prefetch".into()),
                };
                let result = match *result {
                    "access" => 0,
                    "miss" => 1,
                    _ => return Err("cache result must be access or miss".into()),
                };
                Ok(Self::Perf {
                    kind: 3,
                    config: cache | op << 8 | result << 16,
                    period: if parts.len() == 5 {
                        positive(parts[4])?
                    } else {
                        1_000_000
                    },
                    frequency: false,
                })
            }
            [
                provider @ ("interval" | "profile" | "wait" | "wakeup"),
                unit,
                amount,
            ] => {
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
                    let period = Duration::from_nanos(1_000_000_000 / amount);
                    if *provider == "wait" || *provider == "wakeup" {
                        if period < Duration::from_millis(1) {
                            return Err("wait snapshots require intervals of at least 1 ms".into());
                        }
                        return Ok(if *provider == "wakeup" {
                            Self::Wakeup(period)
                        } else {
                            Self::Wait(period)
                        });
                    }
                    return Ok(Self::Interval(period));
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
                if *provider == "wait" || *provider == "wakeup" {
                    if ns < 1_000_000 {
                        return Err("wait snapshots require intervals of at least 1 ms".into());
                    }
                    return Ok(if *provider == "wakeup" {
                        Self::Wakeup(Duration::from_nanos(ns))
                    } else {
                        Self::Wait(Duration::from_nanos(ns))
                    });
                }
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

impl Probe {
    pub fn is_perf(&self) -> bool {
        matches!(
            self,
            Self::Perf { .. } | Self::Watchpoint { .. } | Self::OffCpu | Self::Uprobe { .. }
        )
    }
}
fn unsigned(text: &str) -> Result<u64> {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        text.parse::<u64>().map_err(|e| e.to_string())
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
    Array(String, Box<Expr>),
    Inline(Vec<(String, Expr)>, Box<Expr>),
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
    Repeat(u32, Vec<Stmt>),
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
            } else if b"{}()[];,:./@$+-*%=!<>~&|^".contains(&bytes[i]) {
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
    functions: std::collections::BTreeMap<String, (Vec<String>, Expr)>,
    expanded: usize,
}
pub fn parse(src: &str) -> Result<Vec<Clause>> {
    let mut p = Parser {
        src,
        tokens: lex(src)?,
        at: 0,
        depth: 0,
        functions: Default::default(),
        expanded: 0,
    };
    let mut clauses = Vec::new();
    while !matches!(p.token().kind, TokenKind::Eof) {
        if p.eat("fn") {
            let name = p.word()?;
            p.expect("(")?;
            let mut parameters = Vec::new();
            if !p.eat(")") {
                loop {
                    p.expect("$")?;
                    let parameter = p.word()?;
                    if parameters.contains(&parameter) {
                        return Err(p.error("duplicate function parameter"));
                    }
                    parameters.push(parameter);
                    if parameters.len() > 16 {
                        return Err(p.error("function has more than 16 parameters"));
                    }
                    if p.eat(")") {
                        break;
                    }
                    p.expect(",")?;
                }
            }
            p.expect("=")?;
            let expression = p.expr(0)?;
            p.expect(";")?;
            if p.functions.len() >= 128
                || p.functions.insert(name, (parameters, expression)).is_some()
            {
                return Err(p.error("too many or duplicate function definitions"));
            }
            continue;
        }
        let mut probes = Vec::new();
        loop {
            let start = p.token().start;
            let is_uprobe = matches!(&p.token().kind,TokenKind::Word(name) if name=="uprobe"||name=="uretprobe"||name=="usdt");
            let mut colons = 0;
            while !p.is("{")
                && !(p.is("/") && (!is_uprobe || colons >= 2))
                && !p.is(",")
                && !matches!(p.token().kind, TokenKind::Eof)
            {
                if p.is(":") {
                    colons += 1;
                }
                p.at += 1;
            }
            let end = if p.at == 0 {
                start
            } else {
                p.tokens[p.at.saturating_sub(1)].end
            };
            let mut quoted = false;
            let mut escaped = false;
            let name: String = src[start..end.max(start)]
                .chars()
                .filter(|c| {
                    if escaped {
                        escaped = false;
                        return true;
                    }
                    if *c == '\\' && quoted {
                        escaped = true;
                        return true;
                    }
                    if *c == '"' {
                        quoted = !quoted;
                        return true;
                    }
                    quoted || !c.is_whitespace()
                })
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
            if self.eat("repeat") {
                self.expect("(")?;
                let count = match self.expr(0)? {
                    Expr::Number(n) if (1..=1024).contains(&n) => n as u32,
                    _ => return Err(self.error("repeat requires a constant count from 1 to 1024")),
                };
                self.expect(")")?;
                stmts.push(Stmt::Repeat(count, self.block()?));
                continue;
            }
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
            let name = self.word()?;
            if self.eat("[") {
                let index = self.expr(0)?;
                self.expect("]")?;
                Expr::Array(name, Box::new(index))
            } else {
                Expr::Local(name)
            }
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
                        let args = self.args(")")?;
                        if let Some((parameters, body)) = self.functions.get(&w) {
                            if args.len() != parameters.len() {
                                return Err(self.error("function argument count mismatch"));
                            }
                            fn cost(e: &Expr) -> usize {
                                match e {
                                    Expr::Inline(args, body) => {
                                        1 + args.iter().map(|(_, e)| cost(e)).sum::<usize>()
                                            + cost(body)
                                    }
                                    Expr::Call(_, args) | Expr::Map(_, args) => {
                                        1 + args.iter().map(cost).sum::<usize>()
                                    }
                                    Expr::Unary(_, e) | Expr::Array(_, e) => 1 + cost(e),
                                    Expr::Binary(_, a, b) => 1 + cost(a) + cost(b),
                                    _ => 1,
                                }
                            }
                            self.expanded = self.expanded.saturating_add(cost(body));
                            if self.expanded > 50_000 {
                                return Err(
                                    self.error("expanded function expression limit exceeded")
                                );
                            }
                            Expr::Inline(
                                parameters.iter().cloned().zip(args).collect(),
                                Box::new(body.clone()),
                            )
                        } else {
                            Expr::Call(w, args)
                        }
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

#[cfg(test)]
mod new_probe_tests {
    use super::*;
    #[test]
    fn function_paths_names_and_predicates() {
        let clauses=parse(r#"uprobe:"/a path/libfoo.so":"ns::work(int)" / arg0 > 0 / { @x++; } uretprobe:/tmp/a.so:work { @x++; }"#).unwrap();
        assert_eq!(clauses.len(), 2);
        assert!(clauses[0].predicate.is_some());
        assert!(
            matches!(&clauses[0].probes[0].1,Probe::Uprobe {path,function,ret:false} if path=="/a path/libfoo.so"&&function=="ns::work(int)")
        );
        assert!(
            matches!(&clauses[1].probes[0].1,Probe::Uprobe {path,function,ret:true} if path=="/tmp/a.so"&&function=="work")
        );
        assert!(Probe::parse("uprobe:/path").is_err());
        assert!(Probe::parse("uprobe::foo").is_err());
    }
}
