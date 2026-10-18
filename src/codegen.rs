use crate::{
    Result,
    language::{self, Clause, Expr, Probe, Stmt},
    llvm::{Engine, Handler},
    runtime::{Aggregate, Event, Format, MapSpec, State, Type},
};
use std::collections::{BTreeMap, BTreeSet};

pub struct Program {
    pub source: String,
    origin: std::sync::Arc<()>,
    pub clauses: Vec<Clause>,
    specs: Vec<MapSpec>,
    formats: Vec<Format>,
    pub ir: String,
    handlers: Vec<Handler>,
    ustack: bool,
    kstack: bool,
    jsstack: bool,
    branches: bool,
    _engine: Engine,
}
impl Program {
    pub fn compile(source: &str) -> Result<Self> {
        if source.len() > 256 * 1024 {
            return Err("script exceeds 256 KiB".into());
        }
        let clauses = language::parse(source)?;
        let mut generator = Generator {
            definitions: clauses
                .first()
                .map(|c| (*c.functions).clone())
                .unwrap_or_default(),
            ..Default::default()
        };
        for clause in &clauses {
            generator.local_types(&clause.body)?;
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
            source: source.into(),
            origin: std::sync::Arc::new(()),
            clauses,
            specs: generator.specs,
            formats: generator.formats,
            ir,
            handlers,
            ustack: generator.ustack,
            kstack: generator.kstack,
            jsstack: generator.jsstack,
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
        let mut recorded = state
            .recorder
            .as_ref()
            .map(|_| crate::recording::Saved::capture(clause, state.stopped, event));
        if let Some(saved) = &mut recorded {
            saved.capture_raw(state.js_snapshot.as_ref());
            saved.trace_fields = state.trace_fields.clone();
            saved.memory = state.captured_memory.clone();
            saved.kernel_stack = state.kernel_frames.clone();
        }
        state.journal.clear();
        state.stack_strings.clear();
        state.fuel = 4096;
        state.recursion_depth = 0;
        state.recursion_cost = 0;
        state.scratch.clear();
        state.iterations.clear();
        // Handler lifetime is bounded by the Engine held by this Program. Event
        // strings stay alive throughout this synchronous invocation.
        unsafe {
            (self.handlers[clause])(state, event);
        }
        if let Some(recorded) = &mut recorded {
            recorded.helpers = std::mem::take(&mut state.journal);
            if let Some(recorder) = &mut state.recorder {
                if let Err(e) = recorder.event(recorded) {
                    state.fail(e);
                }
            }
        }
        if !state.replay_lookup && state.replay.as_ref().is_some_and(|queue| !queue.is_empty()) {
            state.fail("recording has unused helper results".into());
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
    pub fn needs_jsstack(&self) -> bool {
        self.jsstack
    }
    pub fn needs_kstack(&self) -> bool {
        self.kstack
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
    definitions: BTreeMap<String, (Vec<String>, Expr)>,
    native_functions: BTreeMap<(String, Vec<Type>), (String, Type)>,
    specs: Vec<MapSpec>,
    ids: BTreeMap<String, usize>,
    formats: Vec<Format>,
    globals: String,
    functions: String,
    next_string: usize,
    body: String,
    allocations: String,
    next: usize,
    current: String,
    locals: BTreeMap<String, String>,
    local_types: BTreeMap<String, Type>,
    arrays: BTreeMap<String, u32>,
    ustack: bool,
    kstack: bool,
    jsstack: bool,
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
        if expr.as_ref().starts_with("alloca ") {
            self.allocations
                .push_str(&format!("  {reg} = {}\n", expr.as_ref()));
        } else {
            self.emit(format!("{reg} = {}", expr.as_ref()));
        }
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
    fn truth(&mut self, expression: &Expr) -> Result<String> {
        let value = self.expr(expression)?;
        if value.ty == Type::Float {
            let raw = self.float_operand(value)?;
            let test = self
                .value(format!("fcmp une double {raw}, 0.0"), Type::Number)
                .reg;
            Ok(self
                .value(format!("zext i1 {test} to i64"), Type::Number)
                .reg)
        } else if value.ty == Type::Number {
            Ok(value.reg)
        } else {
            Err("condition requires a number".into())
        }
    }
    fn infer(&self, e: &Expr) -> Type {
        Self::infer_with(e, &self.local_types)
    }
    fn infer_with(e: &Expr, types: &BTreeMap<String, Type>) -> Type {
        match e {
            Expr::String(_) => Type::String,
            Expr::Conditional(_, yes, no) => {
                let yes = Self::infer_with(yes, types);
                let no = Self::infer_with(no, types);
                if yes == Type::Float || no == Type::Float {
                    Type::Float
                } else if yes == Type::String || no == Type::String {
                    Type::String
                } else if yes == Type::Stack || no == Type::Stack {
                    Type::Stack
                } else {
                    yes
                }
            }
            Expr::Call(name, _) if types.contains_key(&format!("fn::{name}")) => {
                types[&format!("fn::{name}")]
            }
            Expr::Float(_) => Type::Float,
            Expr::Call(name, _) if matches!(name.as_str(), "f64" | "f32" | "fieldf") => Type::Float,
            Expr::Unary(op, value) if matches!(op.as_str(), "+" | "-") => {
                Self::infer_with(value, types)
            }
            Expr::Binary(op, lhs, rhs)
                if matches!(op.as_str(), "+" | "-" | "*" | "/" | "%")
                    && (Self::infer_with(lhs, types) == Type::Float
                        || Self::infer_with(rhs, types) == Type::Float) =>
            {
                Type::Float
            }
            Expr::Inline(arguments, body) => {
                let mut scope = types.clone();
                let arguments: Vec<_> = arguments
                    .iter()
                    .map(|(name, arg)| (name.clone(), Self::infer_with(arg, types)))
                    .collect();
                scope.extend(arguments);
                Self::infer_with(body, &scope)
            }
            Expr::Local(name) => types.get(name).copied().unwrap_or(Type::Number),
            Expr::Array(name, _) => types
                .get(&format!("[{name}]"))
                .copied()
                .unwrap_or(Type::Number),
            Expr::Map(name, _) => types
                .get(&format!("@{name}"))
                .copied()
                .unwrap_or(Type::Number),
            Expr::Builtin(n)
                if n == "goroutines"
                    || n == "managedstacks"
                    || n == "comm"
                    || n == "probe"
                    || n == "syscall"
                    || n == "wait_reason" =>
            {
                Type::String
            }
            Expr::Builtin(n) | Expr::Call(n, _)
                if matches!(
                    n.as_str(),
                    "kstack" | "asyncstack" | "jstack" | "dotnetstack" | "wasmstack"
                ) || n == "ustack"
                    || n == "branches"
                    || n == "pystack"
                    || n == "jsstack"
                    || n == "gostack" =>
            {
                Type::Stack
            }
            Expr::Call(n, _)
                if matches!(
                    n.as_str(),
                    "usym"
                        | "str"
                        | "buf"
                        | "strcat"
                        | "substr"
                        | "fieldstr"
                        | "value"
                        | "args"
                        | "args_native"
                        | "args_as"
                        | "goroutines"
                        | "managedstacks"
                        | "farg"
                        | "tpstr"
                        | "ksym"
                        | "kfieldstr"
                ) =>
            {
                Type::String
            }
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
        value_type: Type,
        float_linear: Option<(u64, u64, u64)>,
    ) -> Result<()> {
        if let Expr::Map(name, keys) = lhs {
            let types: Vec<_> = keys.iter().map(|key| self.infer(key)).collect();
            if let Some(id) = self.ids.get(name) {
                let old = &self.specs[*id];
                if old.keys != types
                    || old.aggregate != agg
                    || old.linear != linear
                    || old.value_type != value_type
                    || old.float_linear != float_linear
                {
                    return Err(format!("inconsistent key types or aggregation for @{name}"));
                }
            } else {
                self.ids.insert(name.clone(), self.specs.len());
                self.specs.push(MapSpec {
                    name: name.clone(),
                    keys: types,
                    aggregate: agg,
                    linear,
                    value_type,
                    float_linear,
                });
                self.local_types.insert(format!("@{name}"), value_type);
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
                    let mut float_linear = None;
                    if agg == Aggregate::Lhist {
                        let Expr::Call(_, args) = rhs else {
                            unreachable!()
                        };
                        if self.infer(&args[0]) == Type::Float {
                            fn constant(value: &Expr) -> Option<f64> {
                                match value {
                                    Expr::Number(n) => Some(*n as f64),
                                    Expr::Float(n) => Some(*n),
                                    Expr::Unary(op, n) if op == "-" => constant(n).map(|n| -n),
                                    Expr::Unary(op, n) if op == "+" => constant(n),
                                    _ => None,
                                }
                            }
                            let bounds = args[1..].iter().map(constant).collect::<Vec<_>>();
                            let [Some(min), Some(max), Some(step)] = bounds.as_slice() else {
                                return Err("floating lhist bounds must be finite constants".into());
                            };
                            let buckets = ((*max - *min) / *step).ceil();
                            if !min.is_finite()
                                || !max.is_finite()
                                || !step.is_finite()
                                || min >= max
                                || *step <= 0.0
                                || !buckets.is_finite()
                                || buckets > 1024.0
                                || *min + *step <= *min
                                || *max - *step >= *max
                            {
                                return Err("floating lhist requires finite min < max, positive step, and at most 1024 buckets".into());
                            }
                            float_linear = Some((min.to_bits(), max.to_bits(), step.to_bits()));
                        }
                    }
                    let linear = if agg == Aggregate::Lhist && float_linear.is_none() {
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
                    let value_type = if matches!(lhs, Expr::Map(..)) {
                        Self::aggregate(rhs)?
                            .1
                            .map(|e| self.infer(e))
                            .unwrap_or(Type::Number)
                    } else {
                        Type::Number
                    };
                    if !matches!(value_type, Type::Number | Type::Float) {
                        return Err("map values require numbers".into());
                    }
                    self.declare_map(lhs, agg, linear, value_type, float_linear)?;
                }
                Stmt::Increment(lhs, _) => {
                    let ty = if let Expr::Map(name, _) = lhs {
                        self.ids
                            .get(name)
                            .map(|id| self.specs[*id].value_type)
                            .unwrap_or(Type::Number)
                    } else {
                        Type::Number
                    };
                    self.declare_map(lhs, Aggregate::Set, None, ty, None)?;
                }
                Stmt::Repeat(_, body) | Stmt::While(_, body) => self.declare_maps(body)?,
                Stmt::For(key, value, map, body) => {
                    if let Some(spec) = self.ids.get(map).map(|id| &self.specs[*id]) {
                        for (name, ty) in key.iter().zip(&spec.keys) {
                            self.local_types.insert(name.clone(), *ty);
                        }
                    }
                    let value_type = self
                        .ids
                        .get(map)
                        .map(|id| self.specs[*id].value_type)
                        .unwrap_or(Type::Number);
                    self.local_types.insert(value.clone(), value_type);
                    self.declare_maps(body)?;
                }
                Stmt::If(_, yes, no) => {
                    self.declare_maps(yes)?;
                    self.declare_maps(no)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
    fn local_types(&mut self, body: &[Stmt]) -> Result<()> {
        self.local_types.clear();
        for spec in &self.specs {
            self.local_types
                .insert(format!("@{}", spec.name), spec.value_type);
        }
        fn iterators(
            body: &[Stmt],
            ids: &BTreeMap<String, usize>,
            specs: &[MapSpec],
            types: &mut BTreeMap<String, Type>,
        ) {
            for stmt in body {
                match stmt {
                    Stmt::For(key, value, map, body) => {
                        if let Some(spec) = ids.get(map).map(|id| &specs[*id]) {
                            for (name, ty) in key.iter().zip(&spec.keys) {
                                types.insert(name.clone(), *ty);
                            }
                        }
                        types.insert(
                            value.clone(),
                            ids.get(map)
                                .map(|id| specs[*id].value_type)
                                .unwrap_or(Type::Number),
                        );
                        iterators(body, ids, specs, types);
                    }
                    Stmt::Repeat(_, body) | Stmt::While(_, body) => {
                        iterators(body, ids, specs, types)
                    }
                    Stmt::If(_, yes, no) => {
                        iterators(yes, ids, specs, types);
                        iterators(no, ids, specs, types);
                    }
                    _ => {}
                }
            }
        }
        iterators(body, &self.ids, &self.specs, &mut self.local_types);
        fn collect<'a>(body: &'a [Stmt], out: &mut Vec<(String, &'a Expr)>) {
            for stmt in body {
                match stmt {
                    Stmt::Assign(Expr::Local(n), rhs) => out.push((n.clone(), rhs)),
                    Stmt::Assign(Expr::Array(n, _), rhs) => out.push((format!("[{n}]"), rhs)),
                    Stmt::If(_, y, n) => {
                        collect(y, out);
                        collect(n, out);
                    }
                    Stmt::Repeat(_, body) | Stmt::While(_, body) | Stmt::For(_, _, _, body) => {
                        collect(body, out)
                    }
                    _ => {}
                }
            }
        }
        let mut assignments = Vec::new();
        collect(body, &mut assignments);
        for _ in 0..128 {
            let mut changed = false;
            for (name, rhs) in &assignments {
                let ty = self.infer(rhs);
                if ty != Type::Number && self.local_types.get(name) != Some(&ty) {
                    self.local_types.insert(name.clone(), ty);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        for (name, rhs) in assignments {
            if self.local_types.get(&name).copied().unwrap_or(Type::Number) != self.infer(rhs) {
                return Err(format!("inconsistent local type for ${name}"));
            }
        }
        Ok(())
    }
    fn function(&mut self, id: usize, clause: &Clause) -> Result<()> {
        self.local_types(&clause.body)?;
        self.body.clear();
        self.allocations.clear();
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
                    Stmt::For(key, value, _, body) => {
                        out.extend(key.iter().cloned());
                        out.insert(value.clone());
                        collect(body, out);
                    }
                    Stmt::Repeat(_, body) | Stmt::While(_, body) => collect(body, out),
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
            let initial = if self.local_types.get(name).copied().unwrap_or(Type::Number)
                != Type::String
                && self.local_types.get(name).copied().unwrap_or(Type::Number) != Type::Stack
            {
                "0".into()
            } else {
                self.expr(&Expr::String(String::new()))?.reg
            };
            self.emit(format!("store i64 {initial}, ptr {reg}"));
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
        self.functions.push_str(&self.body.replacen(
            "entry:\n",
            &format!("entry:\n{}", self.allocations),
            1,
        ));
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
            Expr::Float(n) => Ok(Value {
                reg: n.to_bits().to_string(),
                ty: Type::Float,
            }),
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
                if name == "managedstacks" {
                    return self.helper(154, "0".into(), 127, Type::String);
                }
                if name == "goroutines" {
                    return self.helper(53, "128".into(), 32, Type::String);
                }
                if name == "kstack" {
                    self.kstack = true;
                    return self.helper(120, "127".into(), 0, Type::Stack);
                }
                if let Some(op) = match name.as_str() {
                    "asyncstack" => Some(150),
                    "jstack" => Some(151),
                    "dotnetstack" => Some(152),
                    "wasmstack" => Some(153),
                    _ => None,
                } {
                    return self.helper(op, "0".into(), 127, Type::Stack);
                }
                if name == "wait_reason" {
                    return self.helper(70, "0".into(), 0, Type::String);
                }
                if name == "gostack" {
                    self.jsstack = true;
                    return self.helper(52, "0".into(), 127, Type::Stack);
                }
                if name == "jsstack" {
                    self.jsstack = true;
                    return self.helper(51, "0".into(), 127, Type::Stack);
                }
                if name == "pystack" {
                    return self.helper(50, "0".into(), 127, Type::Stack);
                }
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
                let ty = self.local_types.get(name).copied().unwrap_or(Type::Number);
                Ok(self.value(format!("load i64, ptr {ptr}"), ty))
            }
            Expr::Array(name, index) => {
                let encoded = self.array_index(name, index)?;
                Ok(self.value(
                    format!(
                        "call i64 @pt_helper(ptr %state, ptr %event, i64 30, i64 {encoded}, i64 0)"
                    ),
                    self.infer(expr),
                ))
            }
            Expr::Inline(arguments, body) => {
                let mut saved = Vec::new();
                let mut values = Vec::new();
                for (name, arg) in arguments {
                    let value = self.expr(arg)?;
                    values.push((name.clone(), value));
                }
                for (name, value) in values {
                    let ptr = self.value("alloca i64", Type::Number).reg;
                    self.emit(format!("store i64 {}, ptr {ptr}", value.reg));
                    saved.push((
                        name.clone(),
                        self.locals.insert(name.clone(), ptr),
                        self.local_types.insert(name, value.ty),
                    ));
                }
                let result = self.expr(body);
                for (name, ptr, ty) in saved {
                    if let Some(ptr) = ptr {
                        self.locals.insert(name.clone(), ptr);
                    } else {
                        self.locals.remove(&name);
                    }
                    if let Some(ty) = ty {
                        self.local_types.insert(name, ty);
                    } else {
                        self.local_types.remove(&name);
                    }
                }
                result
            }
            Expr::Conditional(condition, yes, no) => {
                let test = self.truth(condition)?;
                let test = self
                    .value(format!("icmp ne i64 {test},0"), Type::Number)
                    .reg;
                let yes_label = self.label_name();
                let no_label = self.label_name();
                let done = self.label_name();
                self.emit(format!("br i1 {test},label %{yes_label},label %{no_label}"));
                let target = self.infer(expr);
                self.label(&yes_label);
                let mut yes = self.expr(yes)?;
                if target == Type::Float && yes.ty == Type::Number {
                    let raw = self.float_operand(yes)?;
                    yes = self.value(format!("bitcast double {raw} to i64"), Type::Float);
                }
                let yes_end = self.current.clone();
                self.emit(format!("br label %{done}"));
                self.label(&no_label);
                let mut no = self.expr(no)?;
                if target == Type::Float && no.ty == Type::Number {
                    let raw = self.float_operand(no)?;
                    no = self.value(format!("bitcast double {raw} to i64"), Type::Float);
                }
                if yes.ty != no.ty {
                    return Err("conditional branches must have compatible types".into());
                }
                let no_end = self.current.clone();
                self.emit(format!("br label %{done}"));
                self.label(&done);
                Ok(self.value(
                    format!("phi i64 [{},%{yes_end}],[{},%{no_end}]", yes.reg, no.reg),
                    yes.ty,
                ))
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
                    self.specs[id].value_type,
                ))
            }
            Expr::Call(name, args) if self.definitions.contains_key(name) => {
                self.native_call(name, args)
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
            Expr::Call(name, args)
                if name == "kstack"
                    || matches!(
                        name.as_str(),
                        "asyncstack" | "jstack" | "dotnetstack" | "wasmstack" | "managedstacks"
                    ) =>
            {
                let depth = match args.as_slice() {
                    [] => 127,
                    [Expr::Number(n)] if (1..=127).contains(n) => *n,
                    _ => return Err("stack helper depth must be a constant from1to127".into()),
                };
                if name == "kstack" {
                    self.kstack = true;
                    self.helper(120, depth.to_string(), 0, Type::Stack)
                } else {
                    let op = match name.as_str() {
                        "asyncstack" => 150,
                        "jstack" => 151,
                        "dotnetstack" => 152,
                        "wasmstack" => 153,
                        _ => 154,
                    };
                    self.helper(
                        op,
                        "0".into(),
                        depth,
                        if op == 154 { Type::String } else { Type::Stack },
                    )
                }
            }
            Expr::Call(name, args) if name == "ksym" => {
                let [address] = args.as_slice() else {
                    return Err("ksym requires one address".into());
                };
                let address = self.numeric(address)?;
                self.helper(121, address, 0, Type::String)
            }
            Expr::Call(name, args)
                if matches!(
                    name.as_str(),
                    "btf_sizeof" | "btf_offsetof" | "kfield" | "kfieldstr"
                ) =>
            {
                let read = matches!(name.as_str(), "kfield" | "kfieldstr");
                let start = usize::from(read);
                let address = if read {
                    self.numeric(args.first().ok_or("kernel field requires address")?)?
                } else {
                    "0".into()
                };
                let (ty, field) = match &args[start..] {
                    [Expr::String(ty)] if name == "btf_sizeof" => (ty.as_str(), ""),
                    [Expr::String(ty), Expr::String(field)] if name != "btf_sizeof" => {
                        (ty.as_str(), field.as_str())
                    }
                    _ => return Err("BTF helpers require literal type and field names".into()),
                };
                let descriptor = serde_json::to_string(&(ty, field)).map_err(|e| e.to_string())?;
                let pointer = self.expr(&Expr::String(descriptor))?.reg;
                let op = match name.as_str() {
                    "btf_sizeof" => 122,
                    "btf_offsetof" => 123,
                    "kfield" => 124,
                    _ => 125,
                };
                Ok(self.value(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 {op}, i64 {address}, i64 {pointer})"),if name=="kfieldstr"{Type::String}else{Type::Number}))
            }
            Expr::Call(name, args) if name == "goroutines" => {
                let (depth, limit) = match args.as_slice() {
                    [] => (32, 128),
                    [Expr::Number(depth), Expr::Number(limit)]
                        if (1..=127).contains(depth) && (1..=1024).contains(limit) =>
                    {
                        (*depth, *limit)
                    }
                    _ => {
                        return Err(
                            "goroutines() accepts constant depth1..127 and limit1..1024".into()
                        );
                    }
                };
                self.helper(53, limit.to_string(), depth, Type::String)
            }
            Expr::Call(name, args) if name == "args_as" => {
                let (path, signature) = match args.as_slice() {
                    [Expr::String(signature)] => ("", signature.as_str()),
                    [Expr::String(path), Expr::String(signature)] => {
                        (path.as_str(), signature.as_str())
                    }
                    _ => {
                        return Err(
                            "args_as requires a literal C ABI signature and optional ELF path"
                                .into(),
                        );
                    }
                };
                let descriptor =
                    serde_json::to_string(&(path, signature)).map_err(|e| e.to_string())?;
                let pointer = self.expr(&Expr::String(descriptor))?.reg;
                Ok(self.value(
                    format!(
                        "call i64 @pt_helper(ptr %state,ptr %event,i64 115,i64 0,i64 {pointer})"
                    ),
                    Type::String,
                ))
            }
            Expr::Call(name, args) if name == "args_native" => {
                let (path, function) = match args.as_slice() {
                    [] => ("", ""),
                    [Expr::String(path), Expr::String(function)] => {
                        (path.as_str(), function.as_str())
                    }
                    _ => {
                        return Err(
                            "args_native() accepts optional literal ELF path/function".into()
                        );
                    }
                };
                let descriptor =
                    serde_json::to_string(&(path, function)).map_err(|e| e.to_string())?;
                let pointer = self.expr(&Expr::String(descriptor))?.reg;
                Ok(self.value(
                    format!(
                        "call i64 @pt_helper(ptr %state,ptr %event,i64 114,i64 0,i64 {pointer})"
                    ),
                    Type::String,
                ))
            }
            Expr::Call(name, args) if name == "args" => {
                let (path, function) = match args.as_slice() {
                    [] => ("", ""),
                    [Expr::String(path), Expr::String(function)] => {
                        (path.as_str(), function.as_str())
                    }
                    _ => {
                        return Err(
                            "args() accepts an optional literal ELF path and function name".into(),
                        );
                    }
                };
                let descriptor =
                    serde_json::to_string(&(path, function, "")).map_err(|e| e.to_string())?;
                let descriptor = self.expr(&Expr::String(descriptor))?.reg;
                Ok(self.value(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 46, i64 0, i64 {descriptor})"),Type::String))
            }
            Expr::Call(name, args) if name == "farg" || name == "sarg" => {
                let (index, bits) = match args.as_slice() {
                    [Expr::Number(index)] if name == "sarg" && (0..16).contains(index) => {
                        (*index, 0)
                    }
                    [Expr::Number(index), Expr::String(ty)]
                        if name == "farg"
                            && (0..8).contains(index)
                            && (ty == "f32" || ty == "f64") =>
                    {
                        (*index, if ty == "f32" { 32 } else { 64 })
                    }
                    _ => return Err(
                        "use sarg(0..15) or farg(0..7, \"f32\"/\"f64\") at a function ptrace stop"
                            .into(),
                    ),
                };
                self.helper(
                    if name == "farg" { 60 } else { 61 },
                    index.to_string(),
                    bits,
                    if name == "farg" {
                        Type::String
                    } else {
                        Type::Number
                    },
                )
            }
            Expr::Call(name, args) if matches!(name.as_str(), "tp" | "tpstr") => {
                let [Expr::String(field)] = args.as_slice() else {
                    return Err("tp/tpstr require one literal field name".into());
                };
                if field.is_empty() || field.len() > 256 {
                    return Err("invalid tracepoint field name".into());
                }
                let pointer = self.expr(&Expr::String(field.clone()))?.reg;
                self.helper(
                    if name == "tp" { 80 } else { 81 },
                    pointer,
                    0,
                    if name == "tp" {
                        Type::Number
                    } else {
                        Type::String
                    },
                )
            }
            Expr::Call(name, args)
                if matches!(
                    name.as_str(),
                    "field" | "fieldf" | "fieldstr" | "value" | "offsetof" | "sizeof"
                ) =>
            {
                let read = matches!(name.as_str(), "field" | "fieldstr" | "fieldf" | "value");
                let address = if read {
                    let arg = args.first().ok_or("field requires an address")?;
                    self.numeric(arg)?
                } else {
                    "0".into()
                };
                let descriptors = &args[usize::from(read)..];
                let (path, ty, field) = match descriptors {
                    [Expr::String(ty)] if name == "sizeof" || name == "value" => {
                        ("", ty.as_str(), "")
                    }
                    [Expr::String(ty), Expr::String(field)] if name != "sizeof" => {
                        ("", ty.as_str(), field.as_str())
                    }
                    [Expr::String(path), Expr::String(ty)]
                        if name == "sizeof" || name == "value" =>
                    {
                        (path.as_str(), ty.as_str(), "")
                    }
                    [Expr::String(path), Expr::String(ty), Expr::String(field)]
                        if name != "sizeof" =>
                    {
                        (path.as_str(), ty.as_str(), field.as_str())
                    }
                    _ => {
                        return Err(format!(
                            "invalid {name} descriptor: use literal type/field names and an optional ELF path"
                        ));
                    }
                };
                let descriptor =
                    serde_json::to_string(&(path, ty, field)).map_err(|e| e.to_string())?;
                let descriptor = self.expr(&Expr::String(descriptor))?.reg;
                let op = match name.as_str() {
                    "field" => 40,
                    "offsetof" => 41,
                    "sizeof" => 42,
                    "fieldf" => 44,
                    "value" => 45,
                    _ => 43,
                };
                Ok(self.value(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 {op}, i64 {address}, i64 {descriptor})"),if name=="fieldstr" || name=="value" {Type::String}else if name=="fieldf" {Type::Float}else{Type::Number}))
            }
            Expr::Call(name, args)
                if matches!(
                    name.as_str(),
                    "strlen" | "strcontains" | "startswith" | "endswith" | "strcat" | "substr"
                ) =>
            {
                let op = match name.as_str() {
                    "strlen" => 11,
                    "strcontains" => 12,
                    "startswith" => 13,
                    "endswith" => 14,
                    "strcat" => 15,
                    _ => 16,
                };
                let needed = if op == 11 {
                    1
                } else if op == 16 {
                    3
                } else {
                    2
                };
                if args.len() != needed {
                    return Err(format!("invalid arguments for {name}"));
                }
                let first = self.expr(&args[0])?;
                if first.ty != Type::String {
                    return Err(format!("{name} requires strings"));
                }
                let second = if op == 11 {
                    "0".into()
                } else if op == 16 {
                    let [_, Expr::Number(start), Expr::Number(length)] = args.as_slice() else {
                        return Err("substr requires constant start and length".into());
                    };
                    if !(0..=4096).contains(start) || !(0..=4096).contains(length) {
                        return Err("substr bounds must be 0..4096".into());
                    }
                    (((*start as u64) << 32) | *length as u64).to_string()
                } else {
                    let value = self.expr(&args[1])?;
                    if value.ty != Type::String {
                        return Err(format!("{name} requires strings"));
                    }
                    value.reg
                };
                Ok(self.value(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 {op}, i64 {}, i64 {second})",first.reg),if op>=15 {Type::String}else{Type::Number}))
            }
            Expr::Call(name, args) if matches!(name.as_str(), "f64" | "f32") => {
                let [arg] = args.as_slice() else {
                    return Err("floating-point cast requires one argument".into());
                };
                let value = self.expr(arg)?;
                let mut raw = self.float_operand(value)?;
                if name == "f32" {
                    let narrow = self
                        .value(format!("fptrunc double {raw} to float"), Type::Float)
                        .reg;
                    raw = self
                        .value(format!("fpext float {narrow} to double"), Type::Float)
                        .reg;
                }
                Ok(self.value(format!("bitcast double {raw} to i64"), Type::Float))
            }
            Expr::Call(name, args)
                if matches!(
                    name.as_str(),
                    "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64"
                ) =>
            {
                let [arg] = args.as_slice() else {
                    return Err("cast requires one integer".into());
                };
                let input = self.expr(arg)?;
                let value = if input.ty == Type::Float {
                    self.helper(
                        110,
                        input.reg,
                        i64::from(name.starts_with('u')),
                        Type::Number,
                    )?
                    .reg
                } else if input.ty == Type::Number {
                    input.reg
                } else {
                    return Err("integer cast requires a number".into());
                };
                let bits = name[1..].parse::<u32>().unwrap();
                if bits == 64 {
                    return Ok(Value {
                        reg: value,
                        ty: Type::Number,
                    });
                }
                let small = self
                    .value(format!("trunc i64 {value} to i{bits}"), Type::Number)
                    .reg;
                Ok(self.value(
                    format!(
                        "{} i{bits} {small} to i64",
                        if name.starts_with('i') {
                            "sext"
                        } else {
                            "zext"
                        }
                    ),
                    Type::Number,
                ))
            }
            Expr::Call(name, args)
                if name == "ustack"
                    || name == "pystack"
                    || name == "jsstack"
                    || name == "gostack" =>
            {
                let depth = match args.as_slice() {
                    [] => 127,
                    [Expr::Number(n)] if (1..=127).contains(n) => *n,
                    _ => {
                        return Err(format!(
                            "{name}() accepts an optional constant depth from 1 to 127"
                        ));
                    }
                };
                if name == "gostack" {
                    self.jsstack = true;
                    self.helper(52, "0".into(), depth, Type::Stack)
                } else if name == "jsstack" {
                    self.jsstack = true;
                    self.helper(51, "0".into(), depth, Type::Stack)
                } else if name == "pystack" {
                    self.helper(50, "0".into(), depth, Type::Stack)
                } else {
                    self.stack(depth)
                }
            }
            Expr::Call(name, _) => Err(format!(
                "{name}() cannot be used here; aggregations must be assigned directly to maps"
            )),
            Expr::Unary(op, e) => {
                if self.infer(e) == Type::Float {
                    let value = self.expr(e)?;
                    let raw = self.float_operand(value)?;
                    return match op.as_str() {
                        "+" => Ok(self.value(format!("bitcast double {raw} to i64"), Type::Float)),
                        "-" => {
                            let neg = self.value(format!("fneg double {raw}"), Type::Float).reg;
                            Ok(self.value(format!("bitcast double {neg} to i64"), Type::Float))
                        }
                        "!" => {
                            let test = self
                                .value(format!("fcmp oeq double {raw}, 0.0"), Type::Number)
                                .reg;
                            Ok(self.value(format!("zext i1 {test} to i64"), Type::Number))
                        }
                        _ => Err("bitwise operations require integers".into()),
                    };
                }
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
                let v = self.truth(lhs)?;
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
                let v = self.truth(rhs)?;
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
                if a.ty == Type::Float || b.ty == Type::Float {
                    let a = self.float_operand(a)?;
                    let b = self.float_operand(b)?;
                    if op == "%" {
                        let a = self
                            .value(format!("bitcast double {a} to i64"), Type::Number)
                            .reg;
                        let b = self
                            .value(format!("bitcast double {b} to i64"), Type::Number)
                            .reg;
                        return Ok(self.value(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 111, i64 {a}, i64 {b})"),Type::Float));
                    }
                    let opcode = match op.as_str() {
                        "+" => "fadd",
                        "-" => "fsub",
                        "*" => "fmul",
                        "/" => "fdiv",
                        "%" => "frem",
                        comparison => {
                            let predicate = match comparison {
                                "==" => "oeq",
                                "!=" => "une",
                                "<" => "olt",
                                "<=" => "ole",
                                ">" => "ogt",
                                ">=" => "oge",
                                _ => return Err("bitwise operations require integers".into()),
                            };
                            let comparison = self
                                .value(format!("fcmp {predicate} double {a}, {b}"), Type::Number)
                                .reg;
                            return Ok(
                                self.value(format!("zext i1 {comparison} to i64"), Type::Number)
                            );
                        }
                    };
                    let value = self
                        .value(format!("{opcode} double {a}, {b}"), Type::Float)
                        .reg;
                    return Ok(self.value(format!("bitcast double {value} to i64"), Type::Float));
                }
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
    fn native_call(&mut self, name: &str, args: &[Expr]) -> Result<Value> {
        let (parameters, expression) = self
            .definitions
            .get(name)
            .cloned()
            .ok_or("unknown expression function")?;
        if parameters.len() != args.len() {
            return Err("expression function argument count mismatch".into());
        }
        let values = args
            .iter()
            .map(|arg| self.expr(arg))
            .collect::<Result<Vec<_>>>()?;
        let key = (
            name.to_owned(),
            values.iter().map(|v| v.ty).collect::<Vec<_>>(),
        );
        let (symbol, result) = if let Some(instance) = self.native_functions.get(&key) {
            instance.clone()
        } else {
            if self.native_functions.len() >= 256 {
                return Err("native expression function specialization limit exceeded".into());
            }
            let symbol = format!("expr_fn_{}", self.native_functions.len());
            let saved = (
                std::mem::take(&mut self.body),
                std::mem::take(&mut self.allocations),
                self.next,
                std::mem::take(&mut self.current),
                std::mem::take(&mut self.locals),
                std::mem::take(&mut self.local_types),
            );
            for spec in &self.specs {
                self.local_types
                    .insert(format!("@{}", spec.name), spec.value_type);
            }
            for (parameter, value) in parameters.iter().zip(&values) {
                self.local_types.insert(parameter.clone(), value.ty);
            }
            let result = self.infer(&expression);
            self.local_types.insert(format!("fn::{name}"), result);
            self.native_functions
                .insert(key.clone(), (symbol.clone(), result));
            self.next = 0;
            let signature = (0..parameters.len())
                .map(|n| format!(",i64 %arg{n}"))
                .collect::<String>();
            self.body = format!("define i64 @{symbol}(ptr %state,ptr %event{signature}) {{\n");
            self.label("entry");
            for (n, parameter) in parameters.iter().enumerate() {
                let pointer = self.value("alloca i64", Type::Number).reg;
                self.emit(format!("store i64 %arg{n},ptr {pointer}"));
                self.locals.insert(parameter.clone(), pointer);
            }
            let frame_cost = format!("FRAME_COST_{symbol}");
            let entered = self.helper(130, frame_cost.clone(), 0, Type::Number)?.reg;
            let entered = self
                .value(format!("icmp ne i64 {entered},0"), Type::Number)
                .reg;
            let valid = self.label_name();
            let denied = self.label_name();
            self.emit(format!("br i1 {entered},label %{valid},label %{denied}"));
            self.label(&denied);
            let fallback = if matches!(result, Type::String | Type::Stack) {
                self.expr(&Expr::String(String::new()))?.reg
            } else {
                "0".into()
            };
            self.emit(format!("ret i64 {fallback}"));
            self.label(&valid);
            let output = self.expr(&expression)?;
            if output.ty != result {
                return Err("recursive function return type must be consistent".into());
            }
            self.helper(131, frame_cost.clone(), 0, Type::Number)?;
            self.emit(format!("ret i64 {}", output.reg));
            self.body.push_str("}\n");
            // Conservative native-frame accounting bounds recursion even when an
            // expression creates many hoisted allocas or LLVM spills SSA values.
            let cost = 4096usize
                .saturating_add(self.allocations.len().saturating_mul(8))
                .saturating_add(self.next.saturating_mul(32));
            if cost > 128 * 1024 {
                return Err(
                    "recursive expression function exceeds native frame complexity budget".into(),
                );
            }
            self.body = self.body.replace(&frame_cost, &cost.to_string());
            if self.functions.len().saturating_add(self.body.len()) > 8 * 1024 * 1024 {
                return Err("native expression function IR exceeds8MiB".into());
            }
            self.functions.push_str(&self.body.replacen(
                "entry:\n",
                &format!("entry:\n{}", self.allocations),
                1,
            ));
            self.body = saved.0;
            self.allocations = saved.1;
            self.next = saved.2;
            self.current = saved.3;
            self.locals = saved.4;
            self.local_types = saved.5;
            (symbol, result)
        };
        let arguments = values
            .iter()
            .map(|v| format!(",i64 {}", v.reg))
            .collect::<String>();
        Ok(self.value(
            format!("call i64 @{symbol}(ptr %state,ptr %event{arguments})"),
            result,
        ))
    }
    fn float_operand(&mut self, value: Value) -> Result<String> {
        match value.ty {
            Type::Float => Ok(self
                .value(format!("bitcast i64 {} to double", value.reg), Type::Float)
                .reg),
            Type::Number => Ok(self
                .value(format!("sitofp i64 {} to double", value.reg), Type::Float)
                .reg),
            _ => Err("floating-point expressions require numbers".into()),
        }
    }
    fn array_index(&mut self, name: &str, index: &Expr) -> Result<String> {
        if self.locals.contains_key(name) {
            return Err(format!("${name} cannot be both a scalar and an array"));
        }
        if self.arrays.len() >= 128 && !self.arrays.contains_key(name) {
            return Err("local array limit (128) exceeded".into());
        }
        let next = self.arrays.len() as u32;
        let id = *self.arrays.entry(name.into()).or_insert(next);
        let index = self.numeric(index)?;
        let valid = self
            .value(format!("icmp ult i64 {index}, 256"), Type::Number)
            .reg;
        let safe = self
            .value(
                format!("select i1 {valid}, i64 {index}, i64 4294967295"),
                Type::Number,
            )
            .reg;
        Ok(self
            .value(
                format!("or i64 {safe}, {}", (id as u64) << 32),
                Type::Number,
            )
            .reg)
    }
    fn stmts(&mut self, stmts: &[Stmt]) -> Result<()> {
        for s in stmts {
            match s {
                Stmt::Assign(Expr::Map(name, keys), rhs) => {
                    let (agg, expr) = Self::aggregate(rhs)?;
                    let value = if let Some(e) = expr {
                        let value = self.expr(e)?;
                        if !matches!(value.ty, Type::Number | Type::Float) {
                            return Err("map value requires a number".into());
                        }
                        value.reg
                    } else {
                        "1".into()
                    };
                    let (id, array) = self.keys(name, keys)?;
                    self.emit(format!("call void @pt_map_update(ptr %state, i64 {id}, ptr {array}, i64 {}, i64 {value}, i64 {})", keys.len(), agg as u64));
                }
                Stmt::Assign(Expr::Array(name, index), rhs) => {
                    let value = self.expr(rhs)?;
                    if !matches!(value.ty, Type::Number | Type::Float)
                        || value.ty
                            != self
                                .local_types
                                .get(&format!("[{name}]"))
                                .copied()
                                .unwrap_or(Type::Number)
                    {
                        return Err("local arrays require consistent numeric element types".into());
                    }
                    let value = value.reg;
                    let encoded = self.array_index(name, index)?;
                    self.emit(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 31, i64 {encoded}, i64 {value})"));
                }
                Stmt::Assign(Expr::Local(name), rhs) => {
                    let value = self.expr(rhs)?;
                    if value.ty != self.local_types.get(name).copied().unwrap_or(Type::Number) {
                        return Err(format!("inconsistent local type for ${name}"));
                    }
                    self.emit(format!(
                        "store i64 {}, ptr {}",
                        value.reg, self.locals[name]
                    ));
                }
                Stmt::Assign(..) => {
                    return Err("assignment requires a local ($name) or map (@name)".into());
                }
                Stmt::Increment(Expr::Map(name, keys), amount) => {
                    let (id, array) = self.keys(name, keys)?;
                    let amount = if self.specs[id].value_type == Type::Float {
                        (*amount as f64).to_bits() as i64
                    } else {
                        *amount
                    };
                    self.emit(format!("call void @pt_map_update(ptr %state, i64 {id}, ptr {array}, i64 {}, i64 {amount}, i64 2)", keys.len()));
                }
                Stmt::Increment(Expr::Array(name, index), amount) => {
                    let encoded = self.array_index(name, index)?;
                    let old=self.value(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 30, i64 {encoded}, i64 0)"),Type::Number).reg;
                    let next =
                        if self.infer(&Expr::Array(name.clone(), index.clone())) == Type::Float {
                            let number = self
                                .value(format!("bitcast i64 {old} to double"), Type::Float)
                                .reg;
                            let constant = self
                                .value(format!("sitofp i64 {amount} to double"), Type::Float)
                                .reg;
                            let sum = self
                                .value(format!("fadd double {number}, {constant}"), Type::Float)
                                .reg;
                            self.value(format!("bitcast double {sum} to i64"), Type::Float)
                                .reg
                        } else {
                            self.value(format!("add i64 {old}, {amount}"), Type::Number)
                                .reg
                        };
                    self.emit(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 31, i64 {encoded}, i64 {next})"));
                }
                Stmt::Increment(Expr::Local(name), amount) => {
                    if self.local_types.get(name) == Some(&Type::Float) {
                        let next = self
                            .expr(&Expr::Binary(
                                "+".into(),
                                Box::new(Expr::Local(name.clone())),
                                Box::new(Expr::Float(*amount as f64)),
                            ))?
                            .reg;
                        self.emit(format!("store i64 {next}, ptr {}", self.locals[name]));
                        continue;
                    }
                    let v = self.numeric(&Expr::Local(name.clone()))?;
                    let next = self
                        .value(format!("add i64 {v}, {amount}"), Type::Number)
                        .reg;
                    self.emit(format!("store i64 {next}, ptr {}", self.locals[name]));
                }
                Stmt::Increment(..) => return Err("increment requires a local or map".into()),
                Stmt::For(key, value, map, body) => {
                    let id = *self
                        .ids
                        .get(map)
                        .ok_or_else(|| format!("map @{map} is never assigned"))?;
                    let spec = &self.specs[id];
                    if spec.keys.len() != key.len()
                        || matches!(spec.aggregate, Aggregate::Hist | Aggregate::Lhist)
                    {
                        return Err("map iteration requires matching key destructuring and a scalar aggregation".into());
                    }
                    if key.iter().zip(&spec.keys).any(|(name, ty)| {
                        self.local_types.get(name).copied().unwrap_or(Type::Number) != *ty
                    }) || self.local_types.get(value).copied().unwrap_or(Type::Number)
                        != spec.value_type
                    {
                        return Err("map iteration local type mismatch".into());
                    }
                    let snapshot = self.helper(90, id.to_string(), 0, Type::Number)?.reg;
                    let count = self.helper(93, snapshot.clone(), 0, Type::Number)?.reg;
                    let index = self.value("alloca i64", Type::Number).reg;
                    self.emit(format!("store i64 0, ptr {index}"));
                    let head = self.label_name();
                    let loop_body = self.label_name();
                    let done = self.label_name();
                    self.emit(format!("br label %{head}"));
                    self.label(&head);
                    let n = self
                        .value(format!("load i64, ptr {index}"), Type::Number)
                        .reg;
                    let test = self
                        .value(format!("icmp ult i64 {n}, {count}"), Type::Number)
                        .reg;
                    self.emit(format!("br i1 {test}, label %{loop_body}, label %{done}"));
                    self.label(&loop_body);
                    let fuel = self.helper(20, "0".into(), 0, Type::Number)?.reg;
                    let allowed = self
                        .value(format!("icmp ne i64 {fuel}, 0"), Type::Number)
                        .reg;
                    let valid = self.label_name();
                    self.emit(format!("br i1 {allowed}, label %{valid}, label %return"));
                    self.label(&valid);
                    let row = self.value(format!("shl i64 {n}, 32"), Type::Number).reg;
                    for (index, name) in key.iter().enumerate() {
                        let encoded = self
                            .value(format!("or i64 {row}, {index}"), Type::Number)
                            .reg;
                        let item=self.value(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 91, i64 {snapshot}, i64 {encoded})"),Type::Number).reg;
                        let pointer = self.locals[name].clone();
                        self.emit(format!("store i64 {item}, ptr {pointer}"));
                    }
                    let item=self.value(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 92, i64 {snapshot}, i64 {n})"),Type::Number).reg;
                    let pointer = self.locals[value].clone();
                    self.emit(format!("store i64 {item}, ptr {pointer}"));
                    self.stmts(body)?;
                    let next = self.value(format!("add i64 {n}, 1"), Type::Number).reg;
                    self.emit(format!("store i64 {next}, ptr {index}"));
                    self.emit(format!("br label %{head}"));
                    self.label(&done);
                }
                Stmt::While(condition, body) => {
                    let head = self.label_name();
                    let loop_body = self.label_name();
                    let done = self.label_name();
                    self.emit(format!("br label %{head}"));
                    self.label(&head);
                    let value = self.truth(condition)?;
                    let test = self
                        .value(format!("icmp ne i64 {value}, 0"), Type::Number)
                        .reg;
                    self.emit(format!("br i1 {test}, label %{loop_body}, label %{done}"));
                    self.label(&loop_body);
                    let fuel = self.helper(20, "0".into(), 0, Type::Number)?.reg;
                    let allowed = self
                        .value(format!("icmp ne i64 {fuel}, 0"), Type::Number)
                        .reg;
                    let valid = self.label_name();
                    self.emit(format!("br i1 {allowed}, label %{valid}, label %return"));
                    self.label(&valid);
                    self.stmts(body)?;
                    self.emit(format!("br label %{head}"));
                    self.label(&done);
                }
                Stmt::Repeat(count, body) => {
                    let counter = self.value("alloca i64", Type::Number).reg;
                    self.emit(format!("store i64 {count}, ptr {counter}"));
                    let head = self.label_name();
                    let loop_body = self.label_name();
                    let done = self.label_name();
                    self.emit(format!("br label %{head}"));
                    self.label(&head);
                    let n = self
                        .value(format!("load i64, ptr {counter}"), Type::Number)
                        .reg;
                    let c = self.value(format!("icmp ne i64 {n}, 0"), Type::Number).reg;
                    self.emit(format!("br i1 {c}, label %{loop_body}, label %{done}"));
                    self.label(&loop_body);
                    let fuel = self.helper(20, "0".into(), 0, Type::Number)?.reg;
                    let allowed = self
                        .value(format!("icmp ne i64 {fuel}, 0"), Type::Number)
                        .reg;
                    let valid = self.label_name();
                    self.emit(format!("br i1 {allowed}, label %{valid}, label %return"));
                    self.label(&valid);
                    self.stmts(body)?;
                    let next = self.value(format!("sub i64 {n}, 1"), Type::Number).reg;
                    self.emit(format!("store i64 {next}, ptr {counter}"));
                    self.emit(format!("br label %{head}"));
                    self.label(&done);
                }
                Stmt::If(e, yes, no) => {
                    let v = self.truth(e)?;
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
                    "time" => {
                        let format = match args.as_slice() {
                            [] => "%H:%M:%S\n",
                            [Expr::String(format)] => format,
                            _ => {
                                return Err(
                                    "time requires no arguments or one literal format string"
                                        .into(),
                                );
                            }
                        };
                        if format.len() > 1024 || format.contains('\0') {
                            return Err("time format must be at most 1024 bytes without NUL".into());
                        }
                        let descriptor = self.expr(&Expr::String(format.into()))?.reg;
                        let value = self.value(format!("call i64 @pt_helper(ptr %state, ptr %event, i64 160, i64 0, i64 {descriptor})"), Type::String);
                        self.output_value("%s", value)?;
                    }
                    "delete" => {
                        let [Expr::Map(name, keys)] = args.as_slice() else {
                            return Err("delete requires one map entry".into());
                        };
                        let (id, array) = self.keys(name, keys)?;
                        self.emit(format!("call void @pt_map_update(ptr %state, i64 {id}, ptr {array}, i64 {}, i64 0, i64 8)",keys.len()));
                    }
                    "print" if !matches!(args.as_slice(), [Expr::Map(_, keys)] if keys.is_empty()) =>
                    {
                        let [expr] = args.as_slice() else {
                            return Err("print requires one value or whole map".into());
                        };
                        let value = self.expr(expr)?;
                        let format = match value.ty {
                            Type::Number => "%d\n",
                            Type::Float => "%g\n",
                            Type::String | Type::Stack => "%s\n",
                        };
                        self.output_value(format, value)?;
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
    fn output_value(&mut self, format: &str, value: Value) -> Result<()> {
        let format = Format::parse(format)?;
        let id = self.formats.len();
        self.formats.push(format);
        let array = self.value("alloca i64", Type::Number).reg;
        self.emit(format!("store i64 {}, ptr {array}", value.reg));
        self.emit(format!(
            "call void @pt_printf(ptr %state, i64 {id}, ptr {array})"
        ));
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
