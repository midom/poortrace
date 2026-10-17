use crate::{
    Result,
    language::{self, Clause, Expr, Probe, Stmt},
    llvm::{Engine, Handler},
    runtime::{Aggregate, Event, Format, MapSpec, State, Type},
};
use std::collections::{BTreeMap, BTreeSet};

pub struct Program {
    origin: std::sync::Arc<()>,
    pub clauses: Vec<Clause>,
    specs: Vec<MapSpec>,
    formats: Vec<Format>,
    pub ir: String,
    handlers: Vec<Handler>,
    ustack: bool,
    branches: bool,
    _engine: Engine,
}
impl Program {
    pub fn compile(source: &str) -> Result<Self> {
        if source.len() > 256 * 1024 {
            return Err("script exceeds 256 KiB".into());
        }
        let clauses = language::parse(source)?;
        let mut generator = Generator::default();
        for clause in &clauses {
            generator.declare_maps(&clause.body)?;
        }
        for (i, clause) in clauses.iter().enumerate() {
            generator.function(i, clause)?;
        }
        let ir = format!(
            "{}\n{}\n{}",
            PRELUDE, generator.globals, generator.functions
        );
        let (engine, handlers) = Engine::compile(&ir, clauses.len())?;
        Ok(Self {
            origin: std::sync::Arc::new(()),
            clauses,
            specs: generator.specs,
            formats: generator.formats,
            ir,
            handlers,
            ustack: generator.ustack,
            branches: generator.branches,
            _engine: engine,
        })
    }
    pub fn invoke(&self, clause: usize, state: &mut State<'_>, event: &Event<'_>) {
        // State metadata must correspond to this compiled program's callback ABI.
        assert!(
            std::sync::Arc::ptr_eq(&state.origin, &self.origin),
            "State belongs to a different Program"
        );
        state.stack_strings.clear();
        // Handler lifetime is bounded by the Engine held by this Program. Event
        // strings stay alive throughout this synchronous invocation.
        unsafe {
            (self.handlers[clause])(state, event);
        }
    }
    pub fn has_perf(&self) -> bool {
        self.clauses
            .iter()
            .any(|c| c.probes.iter().any(|(_, p)| p.is_perf()))
    }
    pub fn has_syscalls(&self) -> bool {
        self.clauses.iter().any(|c| {
            c.probes
                .iter()
                .any(|(_, p)| matches!(p, Probe::Syscall { .. }))
        })
    }
    pub fn needs_branches(&self) -> bool {
        self.branches
    }
    pub fn needs_ustack(&self) -> bool {
        self.ustack
    }
    pub fn state<'a>(&self, writer: impl std::io::Write + 'a) -> State<'a> {
        State::new(
            self.origin.clone(),
            self.specs.clone(),
            self.formats.clone(),
            writer,
        )
    }
}

const PRELUDE: &str = "
%Event = type { i64, i64, i64, i64, i64, i64, ptr, ptr, ptr, i64, i64, i64, i64, i64, i64, i64, [6 x i64], ptr, ptr, i64 }
declare void @pt_map_update(ptr, i64, ptr, i64, i64, i64)
declare i64 @pt_map_get(ptr, i64, ptr, i64)
declare void @pt_printf(ptr, i64, ptr)
declare void @pt_map_action(ptr, i64, i64)
declare void @pt_exit(ptr)
declare i64 @pt_stopped(ptr)
declare i64 @pt_streq(ptr, ptr)
declare i64 @pt_ustack(ptr, ptr, i64)
declare i64 @pt_helper(ptr, ptr, i64, i64, i64)
";

#[derive(Default)]
struct Generator {
    specs: Vec<MapSpec>,
    ids: BTreeMap<String, usize>,
    formats: Vec<Format>,
    globals: String,
    functions: String,
    next_string: usize,
    body: String,
    next: usize,
    current: String,
    locals: BTreeMap<String, String>,
    ustack: bool,
    branches: bool,
}
struct Value {
    reg: String,
    ty: Type,
}
impl Generator {
    fn emit(&mut self, line: impl AsRef<str>) {
        self.body.push_str("  ");
        self.body.push_str(line.as_ref());
        self.body.push('\n');
    }
    fn value(&mut self, expr: impl AsRef<str>, ty: Type) -> Value {
        let reg = format!("%r{}", self.next);
        self.next += 1;
        self.emit(format!("{reg} = {}", expr.as_ref()));
        Value { reg, ty }
    }
    fn label_name(&mut self) -> String {
        let s = format!("l{}", self.next);
        self.next += 1;
        s
    }
    fn label(&mut self, name: &str) {
        self.body.push_str(&format!("{name}:\n"));
        self.current = name.into();
    }
    fn numeric(&mut self, e: &Expr) -> Result<String> {
        let v = self.expr(e)?;
        if v.ty != Type::Number {
            return Err("expected an integer expression".into());
        }
        Ok(v.reg)
    }
    fn infer(e: &Expr) -> Type {
        match e {
            Expr::String(_) => Type::String,
            Expr::Builtin(n) if n == "comm" || n == "probe" || n == "syscall" => Type::String,
            Expr::Builtin(n) | Expr::Call(n, _) if n == "ustack" || n == "branches" => Type::Stack,
            Expr::Call(n, _) if matches!(n.as_str(), "usym" | "str" | "buf") => Type::String,
            _ => Type::Number,
        }
    }
    fn aggregate(rhs: &Expr) -> Result<(Aggregate, Option<&Expr>)> {
        if let Expr::Call(name, args) = rhs {
            let agg = match name.as_str() {
                "count" => Aggregate::Count,
                "sum" => Aggregate::Sum,
                "min" => Aggregate::Min,
                "max" => Aggregate::Max,
                "avg" => Aggregate::Avg,
                "hist" => Aggregate::Hist,
                "lhist" => Aggregate::Lhist,
                _ => return Ok((Aggregate::Set, Some(rhs))),
            };
            if args.len()
                != if agg == Aggregate::Count {
                    0
                } else if agg == Aggregate::Lhist {
                    4
                } else {
                    1
                }
            {
                return Err(format!("wrong number of arguments to {name}()"));
            }
            Ok((agg, args.first()))
        } else {
            Ok((Aggregate::Set, Some(rhs)))
        }
    }
    fn declare_map(
        &mut self,
        lhs: &Expr,
        agg: Aggregate,
        linear: Option<(i64, i64, i64)>,
    ) -> Result<()> {
        if let Expr::Map(name, keys) = lhs {
            let types: Vec<_> = keys.iter().map(Self::infer).collect();
            if let Some(id) = self.ids.get(name) {
                let old = &self.specs[*id];
                if old.keys != types || old.aggregate != agg || old.linear != linear {
                    return Err(format!("inconsistent key types or aggregation for @{name}"));
                }
            } else {
                self.ids.insert(name.clone(), self.specs.len());
                self.specs.push(MapSpec {
                    name: name.clone(),
                    keys: types,
                    aggregate: agg,
                    linear,
                });
            }
        }
        Ok(())
    }
    fn declare_maps(&mut self, stmts: &[Stmt]) -> Result<()> {
        for stmt in stmts {
            match stmt {
                Stmt::Assign(lhs, rhs) => {
                    let agg = if matches!(lhs, Expr::Map(..)) {
                        Self::aggregate(rhs)?.0
                    } else {
                        Aggregate::Set
                    };
                    let linear = if agg == Aggregate::Lhist {
                        let Expr::Call(_, args) = rhs else {
                            unreachable!()
                        };
                        let constants: Vec<_> = args[1..]
                            .iter()
                            .map(|e| match e {
                                Expr::Number(n) => Some(*n),
                                Expr::Unary(op, e) if op == "-" => {
                                    if let Expr::Number(n) = &**e {
                                        Some(n.wrapping_neg())
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            })
                            .collect();
                        let [Some(min), Some(max), Some(step)] = constants.as_slice() else {
                            return Err("lhist bounds must be integer constants".into());
                        };
                        if min >= max
                            || *step <= 0
                            || (*max as i128 - *min as i128 + *step as i128 - 1) / *step as i128
                                > 1024
                        {
                            return Err(
                                "lhist requires min < max, step > 0, and at most 1024 buckets"
                                    .into(),
                            );
                        }
                        Some((*min, *max, *step))
                    } else {
                        None
                    };
                    self.declare_map(lhs, agg, linear)?;
                }
                Stmt::Increment(lhs, _) => self.declare_map(lhs, Aggregate::Set, None)?,
                Stmt::If(_, yes, no) => {
                    self.declare_maps(yes)?;
                    self.declare_maps(no)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
    fn function(&mut self, id: usize, clause: &Clause) -> Result<()> {
        self.body.clear();
        self.locals.clear();
        self.next = 0;
        self.body.push_str(&format!(
            "define void @probe_{id}(ptr %state, ptr %event) {{\n"
        ));
        self.label("entry");
        let mut locals = BTreeSet::new();
        fn collect(stmts: &[Stmt], out: &mut BTreeSet<String>) {
            for s in stmts {
                match s {
                    Stmt::Assign(Expr::Local(n), _) | Stmt::Increment(Expr::Local(n), _) => {
                        out.insert(n.clone());
                    }
                    Stmt::If(_, y, n) => {
                        collect(y, out);
                        collect(n, out);
                    }
                    _ => {}
                }
            }
        }
        collect(&clause.body, &mut locals);
        for (i, name) in locals.iter().enumerate() {
            let reg = format!("%local{i}");
            self.emit(format!("{reg} = alloca i64"));
            self.emit(format!("store i64 0, ptr {reg}"));
            self.locals.insert(name.clone(), reg);
        }
        if let Some(p) = &clause.predicate {
            let v = self.numeric(p)?;
            let cond = self.value(format!("icmp ne i64 {v}, 0"), Type::Number).reg;
            let next = self.label_name();
            self.emit(format!("br i1 {cond}, label %{next}, label %return"));
            self.label(&next);
        }
        self.stmts(&clause.body)?;
        self.emit("br label %return");
        self.label("return");
        self.emit("ret void");
        self.body.push_str("}\n");
        self.functions.push_str(&self.body);
        Ok(())
    }
    fn keys(&mut self, name: &str, keys: &[Expr]) -> Result<(usize, String)> {
        let id = *self
            .ids
            .get(name)
            .ok_or_else(|| format!("map @{name} is never assigned"))?;
        if keys.len() != self.specs[id].keys.len() {
            return Err(format!("wrong number of keys for @{name}"));
        }
        let array = self
            .value(
                format!("alloca [{} x {{ i64, i64 }}]", keys.len().max(1)),
                Type::Number,
            )
            .reg;
        for (i, e) in keys.iter().enumerate() {
            let v = self.expr(e)?;
            if v.ty != self.specs[id].keys[i] {
                return Err(format!("wrong key type for @{name}"));
            }
            for (field, value) in [(0, v.reg), (1, (v.ty as u64).to_string())] {
                let ptr = self
                    .value(
                        format!("getelementptr {{ i64, i64 }}, ptr {array}, i64 {i}, i32 {field}"),
                        Type::Number,
                    )
                    .reg;
                self.emit(format!("store i64 {value}, ptr {ptr}"));
            }
        }
        Ok((id, array))
    }
    fn expr(&mut self, expr: &Expr) -> Result<Value> {
        match expr {
            Expr::Number(n) => Ok(Value {
                reg: n.to_string(),
                ty: Type::Number,
            }),
            Expr::String(s) => {
                let id = self.next_string;
                self.next_string += 1;
                let mut bytes = String::new();
                for b in s.bytes().chain(std::iter::once(0)) {
                    bytes.push_str(&format!("\\{b:02X}"));
                }
                self.globals.push_str(&format!(
                    "@str{id} = private unnamed_addr constant [{} x i8] c\"{bytes}\"\n",
                    s.len() + 1
                ));
                Ok(self.value(format!("ptrtoint ptr @str{id} to i64"), Type::String))
            }
            Expr::Builtin(name) => {
                if name == "ustack" {
                    return self.stack(127);
                }
                if name == "branches" {
                    self.branches = true;
                    return self.helper(10, "0".into(), 0, Type::Stack);
                }
                if let Some(index) = name
                    .strip_prefix("arg")
                    .and_then(|v| v.parse::<usize>().ok())
                    .filter(|i| *i < 6)
                {
                    let pointer = self
                        .value(
                            format!("getelementptr %Event, ptr %event, i32 0, i32 16, i32 {index}"),
                            Type::Number,
                        )
                        .reg;
                    return Ok(self.value(format!("load i64, ptr {pointer}"), Type::Number));
                }
                if name == "true" || name == "false" {
                    return Ok(Value {
                        reg: if name == "true" { "1" } else { "0" }.into(),
                        ty: Type::Number,
                    });
                }
                let index = match name.as_str() {
                    "pid" => 0,
                    "tid" => 1,
                    "cpu" => 2,
                    "nsecs" => 3,
                    "ip" => 4,
                    "period" => 5,
                    "comm" => 6,
                    "probe" => 7,
                    "addr" => 10,
                    "offcpu_ns" => 11,
                    "preempt" => 12,
                    "sysno" => 13,
                    "retval" => 14,
                    "latency" => 15,
                    "syscall" => 17,
                    _ => return Err(format!("unknown builtin '{name}'")),
                };
                let ptr = self
                    .value(
                        format!("getelementptr %Event, ptr %event, i32 0, i32 {index}"),
                        Type::Number,
                    )
                    .reg;
                if index < 6 || (10..=15).contains(&index) {
                    Ok(self.value(format!("load i64, ptr {ptr}"), Type::Number))
                } else {
                    let p = self.value(format!("load ptr, ptr {ptr}"), Type::String).reg;
                    Ok(self.value(format!("ptrtoint ptr {p} to i64"), Type::String))
                }
            }
            Expr::Local(name) => {
                let ptr = self
                    .locals
                    .get(name)
                    .ok_or_else(|| format!("local ${name} is never assigned"))?
                    .clone();
                Ok(self.value(format!("load i64, ptr {ptr}"), Type::Number))
            }
            Expr::Map(name, keys) => {
                let (id, array) = self.keys(name, keys)?;
                if matches!(self.specs[id].aggregate, Aggregate::Hist | Aggregate::Lhist) {
                    return Err("hist() maps can only be used with print/clear".into());
                }
                Ok(self.value(
                    format!(
                        "call i64 @pt_map_get(ptr %state, i64 {id}, ptr {array}, i64 {})",
                        keys.len()
                    ),
                    Type::Number,
                ))
            }
            Expr::Call(name, args)
                if matches!(
                    name.as_str(),
                    "usym" | "str" | "buf" | "read_u8" | "read_u16" | "read_u32" | "read_u64"
                ) =>
            {
                let op = match name.as_str() {
                    "usym" => 0,
                    "str" => 1,
                    "buf" => 2,
                    "read_u8" => 3,
                    "read_u16" => 4,
                    "read_u32" => 5,
                    _ => 6,
                };
                let length = match args.as_slice() {
                    [_] if op == 1 => 256,
                    [_] if op != 2 => 0,
                    [_, Expr::Number(n)] if (op == 1 || op == 2) && (1..=4096).contains(n) => *n,
                    _ => {
                        return Err(format!(
                            "{name} requires an address and, for str/buf, a constant length from 1 to 4096"
                        ));
                    }
                };
                let address = self.numeric(&args[0])?;
                self.helper(
                    op,
                    address,
                    length,
                    if op >= 3 { Type::Number } else { Type::String },
                )
            }
            Expr::Call(name, args) if name == "ustack" => {
                let depth = match args.as_slice() {
                    [] => 127,
                    [Expr::Number(n)] if (1..=127).contains(n) => *n,
                    _ => {
                        return Err(
                            "ustack() accepts an optional constant depth from 1 to 127".into()
                        );
                    }
                };
                self.stack(depth)
            }
            Expr::Call(name, _) => Err(format!(
                "{name}() cannot be used here; aggregations must be assigned directly to maps"
            )),
            Expr::Unary(op, e) => {
                let v = self.numeric(e)?;
                match op.as_str() {
                    "+" => Ok(Value {
                        reg: v,
                        ty: Type::Number,
                    }),
                    "-" => Ok(self.value(format!("sub i64 0, {v}"), Type::Number)),
                    "~" => Ok(self.value(format!("xor i64 {v}, -1"), Type::Number)),
                    "!" => {
                        let c = self.value(format!("icmp eq i64 {v}, 0"), Type::Number).reg;
                        Ok(self.value(format!("zext i1 {c} to i64"), Type::Number))
                    }
                    _ => unreachable!(),
                }
            }
            Expr::Binary(op, lhs, rhs) if op == "&&" || op == "||" => {
                let v = self.numeric(lhs)?;
                let c = self.value(format!("icmp ne i64 {v}, 0"), Type::Number).reg;
                let from = self.current.clone();
                let next = self.label_name();
                let done = self.label_name();
                let (yes, no) = if op == "&&" {
                    (&next, &done)
                } else {
                    (&done, &next)
                };
                self.emit(format!("br i1 {c}, label %{yes}, label %{no}"));
                self.label(&next);
                let v = self.numeric(rhs)?;
                let c = self.value(format!("icmp ne i64 {v}, 0"), Type::Number).reg;
                let v = self.value(format!("zext i1 {c} to i64"), Type::Number).reg;
                let rhs_from = self.current.clone();
                self.emit(format!("br label %{done}"));
                self.label(&done);
                Ok(self.value(
                    format!(
                        "phi i64 [ {}, %{from} ], [ {v}, %{rhs_from} ]",
                        if op == "&&" { 0 } else { 1 }
                    ),
                    Type::Number,
                ))
            }
            Expr::Binary(op, lhs, rhs) => {
                let a = self.expr(lhs)?;
                let b = self.expr(rhs)?;
                if a.ty != b.ty {
                    return Err("cannot mix strings and integers".into());
                }
                if a.ty != Type::Number {
                    if op != "==" && op != "!=" {
                        return Err("strings support only == and !=".into());
                    }
                    let a = self
                        .value(format!("inttoptr i64 {} to ptr", a.reg), Type::String)
                        .reg;
                    let b = self
                        .value(format!("inttoptr i64 {} to ptr", b.reg), Type::String)
                        .reg;
                    let v = self.value(
                        format!("call i64 @pt_streq(ptr {a}, ptr {b})"),
                        Type::Number,
                    );
                    return if op == "==" {
                        Ok(v)
                    } else {
                        Ok(self.value(format!("xor i64 {}, 1", v.reg), Type::Number))
                    };
                }
                let a = a.reg;
                let mut b = b.reg;
                let opcode = match op.as_str() {
                    "+" => "add",
                    "-" => "sub",
                    "*" => "mul",
                    "&" => "and",
                    "|" => "or",
                    "^" => "xor",
                    "<<" | ">>" => {
                        b = self.value(format!("and i64 {b}, 63"), Type::Number).reg;
                        if op == "<<" { "shl" } else { "ashr" }
                    }
                    "/" | "%" => {
                        let zero = self.value(format!("icmp eq i64 {b}, 0"), Type::Number).reg;
                        let min = self
                            .value(
                                format!("icmp eq i64 {a}, -9223372036854775808"),
                                Type::Number,
                            )
                            .reg;
                        let neg = self.value(format!("icmp eq i64 {b}, -1"), Type::Number).reg;
                        let overflow = self.value(format!("and i1 {min}, {neg}"), Type::Number).reg;
                        let bad = self
                            .value(format!("or i1 {zero}, {overflow}"), Type::Number)
                            .reg;
                        let divisor = self
                            .value(format!("select i1 {bad}, i64 1, i64 {b}"), Type::Number)
                            .reg;
                        let v = self
                            .value(
                                format!(
                                    "{} i64 {a}, {divisor}",
                                    if op == "/" { "sdiv" } else { "srem" }
                                ),
                                Type::Number,
                            )
                            .reg;
                        let fallback = if op == "/" {
                            "-9223372036854775808"
                        } else {
                            "0"
                        };
                        let v = self
                            .value(
                                format!("select i1 {overflow}, i64 {fallback}, i64 {v}"),
                                Type::Number,
                            )
                            .reg;
                        return Ok(
                            self.value(format!("select i1 {zero}, i64 0, i64 {v}"), Type::Number)
                        );
                    }
                    cmp => {
                        let predicate = match cmp {
                            "==" => "eq",
                            "!=" => "ne",
                            "<" => "slt",
                            "<=" => "sle",
                            ">" => "sgt",
                            ">=" => "sge",
                            _ => unreachable!(),
                        };
                        let c = self
                            .value(format!("icmp {predicate} i64 {a}, {b}"), Type::Number)
                            .reg;
                        return Ok(self.value(format!("zext i1 {c} to i64"), Type::Number));
                    }
                };
                Ok(self.value(format!("{opcode} i64 {a}, {b}"), Type::Number))
            }
        }
    }
    fn stmts(&mut self, stmts: &[Stmt]) -> Result<()> {
        for s in stmts {
            match s {
                Stmt::Assign(Expr::Map(name, keys), rhs) => {
                    let (agg, expr) = Self::aggregate(rhs)?;
                    let value = if let Some(e) = expr {
                        self.numeric(e)?
                    } else {
                        "1".into()
                    };
                    let (id, array) = self.keys(name, keys)?;
                    self.emit(format!("call void @pt_map_update(ptr %state, i64 {id}, ptr {array}, i64 {}, i64 {value}, i64 {})", keys.len(), agg as u64));
                }
                Stmt::Assign(Expr::Local(name), rhs) => {
                    let value = self.numeric(rhs)?;
                    self.emit(format!("store i64 {value}, ptr {}", self.locals[name]));
                }
                Stmt::Assign(..) => {
                    return Err("assignment requires a local ($name) or map (@name)".into());
                }
                Stmt::Increment(Expr::Map(name, keys), amount) => {
                    let (id, array) = self.keys(name, keys)?;
                    self.emit(format!("call void @pt_map_update(ptr %state, i64 {id}, ptr {array}, i64 {}, i64 {amount}, i64 2)", keys.len()));
                }
                Stmt::Increment(Expr::Local(name), amount) => {
                    let v = self.numeric(&Expr::Local(name.clone()))?;
                    let next = self
                        .value(format!("add i64 {v}, {amount}"), Type::Number)
                        .reg;
                    self.emit(format!("store i64 {next}, ptr {}", self.locals[name]));
                }
                Stmt::Increment(..) => return Err("increment requires a local or map".into()),
                Stmt::If(e, yes, no) => {
                    let v = self.numeric(e)?;
                    let c = self.value(format!("icmp ne i64 {v}, 0"), Type::Number).reg;
                    let y = self.label_name();
                    let n = self.label_name();
                    let done = self.label_name();
                    self.emit(format!("br i1 {c}, label %{y}, label %{n}"));
                    self.label(&y);
                    self.stmts(yes)?;
                    self.emit(format!("br label %{done}"));
                    self.label(&n);
                    self.stmts(no)?;
                    self.emit(format!("br label %{done}"));
                    self.label(&done);
                }
                Stmt::Call(name, args) => match name.as_str() {
                    "printf" => {
                        let Some(Expr::String(format)) = args.first() else {
                            return Err("printf requires a literal format string".into());
                        };
                        let format = Format::parse(format)?;
                        if args.len() - 1 != format.types.len() {
                            return Err("printf argument count does not match format".into());
                        }
                        let array = self
                            .value(
                                format!("alloca [{} x i64]", format.types.len().max(1)),
                                Type::Number,
                            )
                            .reg;
                        for (i, (expr, ty)) in args[1..].iter().zip(&format.types).enumerate() {
                            let v = self.expr(expr)?;
                            if v.ty != *ty && !(v.ty == Type::Stack && *ty == Type::String) {
                                return Err(format!(
                                    "printf argument {} has the wrong type",
                                    i + 1
                                ));
                            }
                            let ptr = self
                                .value(
                                    format!("getelementptr i64, ptr {array}, i64 {i}"),
                                    Type::Number,
                                )
                                .reg;
                            self.emit(format!("store i64 {}, ptr {ptr}", v.reg));
                        }
                        let id = self.formats.len();
                        self.formats.push(format);
                        self.emit(format!(
                            "call void @pt_printf(ptr %state, i64 {id}, ptr {array})"
                        ));
                    }
                    "print" | "clear" => {
                        let [Expr::Map(map, keys)] = args.as_slice() else {
                            return Err(format!("{name} requires one whole map"));
                        };
                        if !keys.is_empty() {
                            return Err(format!("{name} requires a whole map without keys"));
                        }
                        let id = self
                            .ids
                            .get(map)
                            .ok_or_else(|| format!("map @{map} is never assigned"))?;
                        self.emit(format!(
                            "call void @pt_map_action(ptr %state, i64 {id}, i64 {})",
                            if name == "print" { 0 } else { 1 }
                        ));
                    }
                    "exit" if args.is_empty() => self.emit("call void @pt_exit(ptr %state)"),
                    _ => return Err(format!("unknown function or invalid arguments: {name}()")),
                },
            }
            let v = self
                .value("call i64 @pt_stopped(ptr %state)", Type::Number)
                .reg;
            let c = self.value(format!("icmp ne i64 {v}, 0"), Type::Number).reg;
            let next = self.label_name();
            self.emit(format!("br i1 {c}, label %return, label %{next}"));
            self.label(&next);
        }
        Ok(())
    }
    fn helper(&mut self, op: u64, address: String, length: i64, ty: Type) -> Result<Value> {
        Ok(self.value(
            format!(
                "call i64 @pt_helper(ptr %state, ptr %event, i64 {op}, i64 {address}, i64 {length})"
            ),
            ty,
        ))
    }
    fn stack(&mut self, depth: i64) -> Result<Value> {
        self.ustack = true;
        Ok(self.value(
            format!("call i64 @pt_ustack(ptr %state, ptr %event, i64 {depth})"),
            Type::Stack,
        ))
    }
}
