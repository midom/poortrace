//! Conservative effects analysis for normal-mode ptrace handler scheduling.
//! New helpers require an explicit review before they may run after resumption.
use crate::language::{Clause, Expr, Stmt};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn clauses(clauses: &[Clause]) -> Vec<bool> {
    clauses
        .iter()
        .map(|clause| {
            let mut analysis = Analysis {
                clause,
                functions: BTreeMap::new(),
                visiting: BTreeSet::new(),
            };
            clause
                .predicate
                .as_ref()
                .is_none_or(|expr| analysis.expr(expr))
                && analysis.stmts(&clause.body)
        })
        .collect()
}

struct Analysis<'a> {
    clause: &'a Clause,
    functions: BTreeMap<String, bool>,
    visiting: BTreeSet<String>,
}
impl Analysis<'_> {
    fn expr(&mut self, expr: &Expr) -> bool {
        match expr {
            Expr::Number(_) | Expr::Float(_) | Expr::String(_) | Expr::Local(_) => true,
            Expr::Builtin(name) => {
                crate::builtins::constant(name).is_some()
                    || matches!(
                        name.as_str(),
                        "true"
                            | "false"
                            | "pid"
                            | "tid"
                            | "cpu"
                            | "nsecs"
                            | "ip"
                            | "period"
                            | "comm"
                            | "probe"
                            | "addr"
                            | "offcpu_ns"
                            | "preempt"
                            | "sysno"
                            | "retval"
                            | "latency"
                            | "syscall"
                            | "ustack"
                            | "arg0"
                            | "arg1"
                            | "arg2"
                            | "arg3"
                            | "arg4"
                            | "arg5"
                    )
            }
            Expr::Tuple(values) | Expr::Map(_, values) => values.iter().all(|e| self.expr(e)),
            Expr::Array(_, index) | Expr::Unary(_, index) => self.expr(index),
            Expr::Inline(bindings, body) => {
                bindings.iter().all(|(_, e)| self.expr(e)) && self.expr(body)
            }
            Expr::Binary(_, a, b) => self.expr(a) && self.expr(b),
            Expr::Conditional(a, b, c) => self.expr(a) && self.expr(b) && self.expr(c),
            Expr::Call(name, args) => {
                if let Some((_, body)) = self.clause.functions.get(name) {
                    if !args.iter().all(|e| self.expr(e)) {
                        return false;
                    }
                    if let Some(safe) = self.functions.get(name) {
                        return *safe;
                    }
                    // Recursive functions stay conservative; this also bounds
                    // analysis independently of native invocation fuel.
                    if !self.visiting.insert(name.clone()) {
                        return false;
                    }
                    let safe = self.expr(body);
                    self.visiting.remove(name);
                    self.functions.insert(name.clone(), safe);
                    return safe;
                }
                let safe = matches!(
                    name.as_str(),
                    "count"
                        | "sum"
                        | "min"
                        | "max"
                        | "avg"
                        | "stats"
                        | "tseries"
                        | "hist"
                        | "lhist"
                        | "ustack"
                        | "dw_ustack"
                        | "reg"
                        | "has_key"
                        | "find"
                        | "delete"
                        | "len"
                        | "strlen"
                        | "strcontains"
                        | "startswith"
                        | "endswith"
                        | "strcat"
                        | "substr"
                        | "strcap"
                        | "strstr"
                        | "bswap"
                        | "uptr"
                        | "signal_name"
                        | "syscall_name"
                        | "u8"
                        | "u16"
                        | "u32"
                        | "u64"
                        | "i8"
                        | "i16"
                        | "i32"
                        | "i64"
                        | "f32"
                        | "f64"
                        | "is_array"
                        | "is_integer"
                        | "is_unsigned_integer"
                        | "is_str"
                        | "is_ptr"
                        | "is_literal"
                        | "is_err"
                        | "assert_str"
                );
                safe && args.iter().enumerate().all(|(index, e)| {
                    // Stack format keywords are compiler options, not reads.
                    index == 0 && matches!(name.as_str(), "ustack" | "dw_ustack")
                        && matches!(e, Expr::Builtin(mode) if matches!(mode.as_str(), "raw" | "perf" | "bpftrace"))
                        || self.expr(e)
                })
            }
        }
    }
    fn stmts(&mut self, statements: &[Stmt]) -> bool {
        statements.iter().all(|statement| match statement {
            Stmt::Assign(a, b) => self.expr(a) && self.expr(b),
            Stmt::Increment(a, _) => self.expr(a),
            Stmt::If(condition, yes, no) => {
                self.expr(condition) && self.stmts(yes) && self.stmts(no)
            }
            Stmt::Repeat(_, body) | Stmt::For(_, _, _, body) => self.stmts(body),
            Stmt::While(condition, body) => self.expr(condition) && self.stmts(body),
            Stmt::Call(name, args) => {
                matches!(
                    name.as_str(),
                    "printf"
                        | "print"
                        | "clear"
                        | "zero"
                        | "delete"
                        | "static_assert"
                        | "assert_str"
                ) && args.iter().all(|e| self.expr(e))
            }
        })
    }
}
