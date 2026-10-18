use crate::Result;
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString, c_char},
    io::Write,
};

#[repr(C)]
pub struct Event<'a> {
    pub pid: u64,
    pub tid: u64,
    pub cpu: u64,
    pub nsecs: u64,
    pub ip: u64,
    pub period: u64,
    pub(crate) comm: *const c_char,
    pub(crate) probe: *const c_char,
    stack: *const u64,
    stack_len: u64,
    pub addr: u64,
    pub offcpu_ns: u64,
    pub preempt: u64,
    pub sysno: u64,
    pub retval: i64,
    pub latency: u64,
    pub args: [u64; 6],
    pub(crate) syscall: *const c_char,
    branches: *const crate::perf::Branch,
    branch_len: u64,
    lifetime: std::marker::PhantomData<&'a CStr>,
}
impl<'a> Event<'a> {
    pub fn new(comm: &'a CStr, probe: &'a CStr) -> Self {
        Self {
            pid: 0,
            tid: 0,
            cpu: 0,
            nsecs: 0,
            ip: 0,
            period: 0,
            comm: comm.as_ptr(),
            probe: probe.as_ptr(),
            stack: [].as_ptr(),
            stack_len: 0,
            addr: 0,
            offcpu_ns: 0,
            preempt: 0,
            sysno: 0,
            retval: 0,
            latency: 0,
            args: [0; 6],
            syscall: c"".as_ptr(),
            branches: [].as_ptr(),
            branch_len: 0,
            lifetime: std::marker::PhantomData,
        }
    }
    pub fn stack_frames(&self) -> &[u64] {
        unsafe { std::slice::from_raw_parts(self.stack, self.stack_len as usize) }
    }
    pub fn branch_records(&self) -> &[crate::perf::Branch] {
        unsafe { std::slice::from_raw_parts(self.branches, self.branch_len as usize) }
    }
    pub fn with_syscall(mut self, name: &'a CStr) -> Self {
        self.syscall = name.as_ptr();
        self
    }
    pub fn with_branches(mut self, branches: &'a [crate::perf::Branch]) -> Self {
        self.branches = branches.as_ptr();
        self.branch_len = branches.len() as u64;
        self
    }
    pub fn with_ustack(mut self, frames: &'a [u64]) -> Self {
        self.stack = frames.as_ptr();
        self.stack_len = frames.len() as u64;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u64)]
pub enum Type {
    Number = 0,
    String = 1,
    Stack = 2,
    Float = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Aggregate {
    Set,
    Count,
    Sum,
    Min,
    Max,
    Avg,
    Hist,
    Lhist,
    Stats = 9,
    Tseries = 10,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapSpec {
    pub name: String,
    pub keys: Vec<Type>,
    pub aggregate: Aggregate,
    pub linear: Option<(i64, i64, i64)>,
    pub float_linear: Option<(u64, u64, u64)>,
    pub value_type: Type,
    pub histogram_precision: u8,
    pub series: Option<(u64, usize, Aggregate)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatPart {
    Text(String),
    Value {
        conversion: char,
        width: usize,
        precision: Option<usize>,
        left: bool,
        zero: bool,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Format {
    pub parts: Vec<FormatPart>,
    pub types: Vec<Type>,
}
impl Format {
    pub fn parse(format: &str) -> Result<Self> {
        let mut chars = format.chars().peekable();
        let mut parts = Vec::new();
        let mut text = String::new();
        let mut types = Vec::new();
        while let Some(c) = chars.next() {
            if c != '%' {
                text.push(c);
                continue;
            }
            if chars.peek() == Some(&'%') {
                chars.next();
                text.push('%');
                continue;
            }
            if !text.is_empty() {
                parts.push(FormatPart::Text(std::mem::take(&mut text)));
            }
            let left = chars.peek() == Some(&'-');
            if left {
                chars.next();
            }
            let zero = chars.peek() == Some(&'0');
            if zero {
                chars.next();
            }
            let mut width = 0usize;
            while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
                chars.next();
                width = width * 10 + d as usize;
                if width > 200 {
                    return Err("printf width must be at most 200".into());
                }
            }
            let precision = if chars.peek() == Some(&'.') {
                chars.next();
                let mut value = 0usize;
                while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
                    chars.next();
                    value = value * 10 + d as usize;
                    if value > 200 {
                        return Err("printf precision must be at most 200".into());
                    }
                }
                Some(value)
            } else {
                None
            };
            if chars.peek() == Some(&'l') {
                chars.next();
                if chars.peek() == Some(&'l') {
                    chars.next();
                }
            }
            let conversion = chars.next().ok_or("incomplete printf conversion")?;
            types.push(match conversion {
                's' => Type::String,
                'f' | 'e' | 'g' => Type::Float,
                'd' | 'i' | 'u' | 'x' | 'X' | 'o' | 'c' | 'p' => Type::Number,
                _ => return Err(format!("unsupported printf conversion %{conversion}")),
            });
            if precision.is_some() && !matches!(conversion, 'f' | 'e' | 'g') {
                return Err(
                    "printf precision currently requires a floating-point conversion".into(),
                );
            }
            parts.push(FormatPart::Value {
                conversion,
                width,
                precision,
                left,
                zero,
            });
        }
        if !text.is_empty() {
            parts.push(FormatPart::Text(text));
        }
        Ok(Self { parts, types })
    }
    pub(crate) fn render(&self, args: &[u64]) -> String {
        let mut out = String::new();
        let mut at = 0;
        for part in &self.parts {
            match part {
                FormatPart::Text(t) => out.push_str(t),
                FormatPart::Value {
                    conversion,
                    width,
                    precision,
                    left,
                    zero,
                } => {
                    let v = args[at];
                    at += 1;
                    let s = match conversion {
                        's' => string(v),
                        'f' => format!("{:.*}", precision.unwrap_or(6), f64::from_bits(v)),
                        'e' => format!("{:.*e}", precision.unwrap_or(6), f64::from_bits(v)),
                        'g' => significant(f64::from_bits(v), precision.unwrap_or(6).max(1)),
                        'd' | 'i' => (v as i64).to_string(),
                        'u' => v.to_string(),
                        'x' => format!("{v:x}"),
                        'X' => format!("{v:X}"),
                        'o' => format!("{v:o}"),
                        'p' => format!("0x{v:x}"),
                        'c' => char::from_u32(v as u32).unwrap_or('\u{fffd}').to_string(),
                        _ => unreachable!(),
                    };
                    let pad = width.saturating_sub(s.chars().count());
                    if *left {
                        out.push_str(&s);
                        out.extend(std::iter::repeat_n(' ', pad));
                    } else if *zero && s.starts_with('-') {
                        out.push('-');
                        out.extend(std::iter::repeat_n('0', pad));
                        out.push_str(&s[1..]);
                    } else if *zero && s.starts_with("0x") {
                        out.push_str("0x");
                        out.extend(std::iter::repeat_n('0', pad));
                        out.push_str(&s[2..]);
                    } else {
                        out.extend(std::iter::repeat_n(if *zero { '0' } else { ' ' }, pad));
                        out.push_str(&s);
                    }
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Key {
    Number(i64),
    Float(u64),
    String(String),
    Stack(String),
}
#[derive(Clone, Debug, Default)]
struct Cell {
    floating: f64,
    value: i64,
    total: i128,
    count: u64,
    buckets: BTreeMap<i32, u64>,
    series: BTreeMap<u64, (i128, u64, i64)>,
}
impl Cell {
    fn floating(&self, agg: Aggregate) -> f64 {
        if matches!(agg, Aggregate::Avg | Aggregate::Stats) {
            self.floating / self.count.max(1) as f64
        } else {
            self.floating
        }
    }
    fn bits(&self, spec: &MapSpec) -> i64 {
        if spec.value_type == Type::Float {
            self.floating(spec.aggregate).to_bits() as i64
        } else {
            self.number(spec.aggregate)
        }
    }
    fn number(&self, agg: Aggregate) -> i64 {
        if matches!(agg, Aggregate::Avg | Aggregate::Stats) {
            (self.total / self.count.max(1) as i128) as i64
        } else {
            self.value
        }
    }
}

/// Native stack algorithm, independent of whether raw stack bytes are archived.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StackMode {
    #[default]
    FramePointer,
    Dwarf,
}

pub struct State<'a> {
    pub(crate) origin: std::sync::Arc<()>,
    maps: Vec<BTreeMap<Vec<Key>, Cell>>,
    pub(crate) specs: Vec<MapSpec>,
    pub(crate) formats: Vec<Format>,
    writer: Box<dyn Write + 'a>,
    pub stopped: bool,
    pub exit_code: i32,
    pub exit_set: bool,
    pub allow_unsafe: bool,
    pub unwatched: std::collections::BTreeSet<u64>,
    pub child_pid: Option<u64>,
    pub(crate) target_starts: BTreeMap<u32, u64>,
    pub script_args: BTreeMap<String, String>,
    pub(crate) first_event_ns: Option<u64>,
    pub(crate) pending_signals: Vec<crate::builtins::DeferredSignal>,
    series_points: usize,
    pub error: Option<String>,
    pub max_entries: usize,
    pub(crate) stack_strings: Vec<CString>,
    pub(crate) fuel: u32,
    pub(crate) recursion_depth: u32,
    pub(crate) recursion_cost: u64,
    pub(crate) iterations: Vec<Vec<(Vec<Key>, i64)>>,
    pub(crate) scratch: BTreeMap<u32, Vec<u64>>,
    pub(crate) symbols: crate::symbols::Symbolizer,
    pub stack_mode: StackMode,
    python: crate::python::Reader,
    javascript: crate::javascript::Reader,
    golang: crate::golang::Reader,
    pub kernel_frames: Vec<u64>,
    pub captured_memory: Vec<crate::recording::MemoryRegion>,
    pub capture_requests: Vec<crate::capture::MemoryRequest>,
    pub replay_memory: Vec<crate::recording::MemoryRegion>,
    pub(crate) kernel_symbols: crate::kernel::Symbols,
    pub(crate) btf: crate::btf::Reader,
    pub managed: crate::managed_bridge::Reader,
    pub trace_fields: crate::kernel::Fields,
    pub(crate) replay_lookup: bool,
    pub js_snapshot: Option<(crate::perf::UserRegs, Vec<u8>)>,
    pub register_snapshot: Option<crate::perf::UserRegs>,
    /// Set only while handlers execute under a verified stopped-target pause.
    pub target_paused: bool,
    types: crate::types::Reader,
    native_args: crate::native_args::Reader,
    pub report: crate::report::Options,
    pub wait_reason: Option<String>,
    pub recorder: Option<crate::recording::Recorder>,
    pub(crate) journal: Vec<crate::recording::Helper>,
    pub(crate) replay: Option<std::collections::VecDeque<crate::recording::Helper>>,
}
impl<'a> State<'a> {
    pub(crate) fn new(
        origin: std::sync::Arc<()>,
        specs: Vec<MapSpec>,
        formats: Vec<Format>,
        writer: impl Write + 'a,
    ) -> Self {
        Self {
            origin,
            maps: vec![BTreeMap::new(); specs.len()],
            specs,
            formats,
            writer: Box::new(writer),
            stopped: false,
            exit_code: 0,
            exit_set: false,
            allow_unsafe: false,
            unwatched: std::collections::BTreeSet::new(),
            child_pid: None,
            target_starts: BTreeMap::new(),
            script_args: BTreeMap::new(),
            first_event_ns: None,
            pending_signals: Vec::new(),
            series_points: 0,
            error: None,
            max_entries: 65536,
            stack_strings: Vec::new(),
            fuel: 4096,
            recursion_depth: 0,
            recursion_cost: 0,
            scratch: BTreeMap::new(),
            iterations: Vec::new(),
            symbols: crate::symbols::Symbolizer::default(),
            stack_mode: StackMode::default(),
            python: crate::python::Reader::default(),
            javascript: crate::javascript::Reader::default(),
            golang: crate::golang::Reader::default(),
            kernel_frames: Vec::new(),
            captured_memory: Vec::new(),
            capture_requests: Vec::new(),
            replay_memory: Vec::new(),
            kernel_symbols: crate::kernel::Symbols::default(),
            btf: crate::btf::Reader::default(),
            managed: crate::managed_bridge::Reader::default(),
            js_snapshot: None,
            register_snapshot: None,
            target_paused: false,
            trace_fields: Default::default(),
            replay_lookup: false,
            types: crate::types::Reader::default(),
            native_args: crate::native_args::Reader::default(),
            report: crate::report::Options::default(),
            wait_reason: None,
            recorder: None,
            journal: Vec::new(),
            replay: None,
        }
    }
    fn write(&mut self, text: &str) {
        if self.error.is_some() {
            return;
        }
        if let Err(e) = self.writer.write_all(text.as_bytes()) {
            self.fail(format!("output: {e}"));
        }
    }
    pub(crate) fn fail(&mut self, e: String) {
        if self.error.is_none() {
            self.error = Some(e);
        }
        self.stopped = true;
    }
    /// Deliver queued, identity-bound signal requests after breakpoint rearming
    /// or detachment. Replay never creates these requests.
    pub fn deliver_signals(&mut self) -> Result<()> {
        if let Some(error) = &self.error {
            self.pending_signals.clear();
            return Err(error.clone());
        }
        for request in std::mem::take(&mut self.pending_signals) {
            if let Err(error) = request.deliver() {
                self.fail(error.clone());
                return Err(error);
            }
        }
        Ok(())
    }
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().map_err(|e| format!("output: {e}"))?;
        match &self.error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
    pub fn capture_event_memory(&mut self, event: &Event<'_>) {
        self.captured_memory.clear();
        match crate::capture::capture(
            &self.capture_requests,
            event,
            self.js_snapshot.as_ref().map(|(regs, _)| regs.sp),
        ) {
            Ok(memory) => self.captured_memory = memory,
            Err(error) => self.fail(error),
        }
    }
    /// Pin the observed process start identity before accepting live metadata.
    pub fn register_target_identity(&mut self, pid: u32) -> Result<()> {
        let started = crate::managed_bridge::start_ticks(pid)?;
        if self
            .target_starts
            .get(&pid)
            .is_some_and(|old| *old != started)
        {
            return Err(format!("PID {pid} changed identity"));
        }
        if self.target_starts.len() >= 4096 && !self.target_starts.contains_key(&pid) {
            return Err("target identity limit (4096) exceeded".into());
        }
        self.target_starts.insert(pid, started);
        Ok(())
    }
    pub fn has_target_identity(&self, pid: u32) -> bool {
        self.target_starts.contains_key(&pid)
    }
    pub fn configure_btf(&mut self, path: std::path::PathBuf) {
        self.btf.configure(path);
    }
    pub fn unwind_sample(&mut self, sample: &crate::perf::Sample) -> Vec<u64> {
        if self.recorder.is_some() {
            self.js_snapshot = sample.regs.map(|regs| (regs, sample.stack.clone()));
        }
        match self.stack_mode {
            StackMode::FramePointer => crate::symbols::frame_pointer_stack(sample),
            StackMode::Dwarf => self.symbols.unwind(sample),
        }
    }
    pub fn replay_helpers(&mut self, helpers: Vec<crate::recording::Helper>) {
        self.replay = Some(helpers.into());
        self.replay_lookup = false;
    }
    pub fn replay_captured_helpers(&mut self, helpers: Vec<crate::recording::Helper>) {
        self.replay = Some(helpers.into());
        self.replay_lookup = true;
    }
    pub fn live_snapshot(&mut self) {
        if unsafe { libc::isatty(1) } == 1 {
            self.write("\x1b[2J\x1b[H");
        }
        self.print_all();
    }
    pub fn clear_all(&mut self) {
        self.series_points = 0;
        for map in &mut self.maps {
            map.clear();
        }
    }
    fn rows(&self, ids: impl Iterator<Item = usize>) -> Vec<crate::report::Row> {
        let mut rows = Vec::new();
        for id in ids {
            let spec = &self.specs[id];
            for (keys, cell) in &self.maps[id] {
                let keys = keys
                    .iter()
                    .map(|key| match key {
                        Key::Float(value) => crate::report::Key {
                            kind: "float".into(),
                            value: float_key_value(*value).to_string(),
                        },
                        Key::Number(value) => crate::report::Key {
                            kind: "number".into(),
                            value: value.to_string(),
                        },
                        Key::String(value) => crate::report::Key {
                            kind: "string".into(),
                            value: value.clone(),
                        },
                        Key::Stack(value) => crate::report::Key {
                            kind: "stack".into(),
                            value: value.clone(),
                        },
                    })
                    .collect();
                let buckets = cell
                    .buckets
                    .iter()
                    .map(|(bucket, count)| {
                        (
                            bucket_label(*bucket, spec),
                            (*count).min(i64::MAX as u64) as i64,
                        )
                    })
                    .collect();
                rows.push(crate::report::Row {
                    stats: (spec.aggregate==Aggregate::Stats).then(|| if spec.value_type==Type::Float {serde_json::json!({"count":cell.count,"total":cell.floating,"average":cell.floating(spec.aggregate)})}else{serde_json::json!({"count":cell.count,"total":cell.total,"average":cell.number(spec.aggregate)})}),
                    series:cell.series.iter().map(|(time,(sum,count,last))|(*time,if spec.series.is_some_and(|(_,_,agg)|agg==Aggregate::Avg){(*sum/(*count).max(1) as i128) as i64}else{*last})).collect(),
                    map: spec.name.clone(),
                    keys,
                    value: if spec.value_type == Type::Float {
                        0
                    } else {
                        cell.number(spec.aggregate)
                    },
                    float_value: (spec.value_type == Type::Float
                        && !matches!(spec.aggregate, Aggregate::Hist | Aggregate::Lhist))
                    .then(|| cell.floating(spec.aggregate)),
                    buckets,
                });
            }
        }
        rows
    }
    pub fn render_report(&self) -> Result<String> {
        crate::report::render(&self.rows(0..self.maps.len()), &self.report)
    }
    pub fn print_all(&mut self) {
        if !self.report.format.is_empty()
            || self.report.top.is_some()
            || self.report.percent
            || self.report.rate
            || !self.report.baseline.is_empty()
        {
            match self.render_report() {
                Ok(text) => self.write(&text),
                Err(error) => self.fail(error),
            }
            return;
        }
        for i in 0..self.maps.len() {
            self.print_map(i);
        }
    }
    fn print_map(&mut self, id: usize) {
        let mut out = String::new();
        let spec = &self.specs[id];
        for (keys, cell) in &self.maps[id] {
            out.push('@');
            out.push_str(&spec.name);
            if !keys.is_empty() {
                out.push('[');
                for (i, k) in keys.iter().enumerate() {
                    if i != 0 {
                        out.push_str(", ");
                    }
                    match k {
                        Key::Number(n) => out.push_str(&n.to_string()),
                        Key::Float(value) => out.push_str(&float_key_value(*value).to_string()),
                        Key::String(s) => out.push_str(&format!("{s:?}")),
                        Key::Stack(s) => {
                            out.push('\n');
                            out.push_str(s);
                        }
                    }
                }
                out.push(']');
            }
            out.push_str(": ");
            if spec.aggregate == Aggregate::Stats {
                if spec.value_type == Type::Float {
                    out.push_str(&format!(
                        "count {}, average {}, total {}\n",
                        cell.count,
                        cell.floating(spec.aggregate),
                        cell.floating
                    ));
                } else {
                    out.push_str(&format!(
                        "count {}, average {}, total {}\n",
                        cell.count,
                        cell.number(spec.aggregate),
                        cell.total
                    ));
                }
            } else if spec.aggregate == Aggregate::Tseries {
                out.push('\n');
                for (timestamp, (sum, count, last)) in &cell.series {
                    let value = if spec.series.is_some_and(|(_, _, agg)| agg == Aggregate::Avg) {
                        (*sum / (*count).max(1) as i128) as i64
                    } else {
                        *last
                    };
                    out.push_str(&format!("  {timestamp}: {value}\n"));
                }
            } else if matches!(spec.aggregate, Aggregate::Hist | Aggregate::Lhist) {
                out.push('\n');
                for (bucket, count) in &cell.buckets {
                    let label = bucket_label(*bucket, spec);
                    out.push_str(&format!("  {label}: {count}\n"));
                }
            } else {
                if spec.value_type == Type::Float {
                    out.push_str(&format!("{}\n", cell.floating(spec.aggregate)));
                } else {
                    out.push_str(&format!("{}\n", cell.number(spec.aggregate)));
                }
            }
        }
        self.write(&out);
    }
}

fn significant(value: f64, precision: usize) -> String {
    if !value.is_finite() || value == 0.0 {
        return value.to_string();
    }
    let scientific = format!("{:.*e}", precision - 1, value);
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent_value = exponent.parse::<i32>().unwrap_or(0);
    let trim = |text: &str| {
        if text.contains('.') {
            text.trim_end_matches('0').trim_end_matches('.').to_owned()
        } else {
            text.to_owned()
        }
    };
    if exponent_value < -4 || exponent_value >= precision as i32 {
        format!("{}e{exponent}", trim(mantissa))
    } else {
        trim(&format!(
            "{:.*}",
            (precision as i32 - 1 - exponent_value).max(0) as usize,
            value
        ))
    }
}

fn string(raw: u64) -> String {
    // Pointers originate from JIT constants, Event strings, or State stack_strings.
    unsafe {
        CStr::from_ptr(raw as *const c_char)
            .to_string_lossy()
            .into_owned()
    }
}
#[repr(C)]
pub(crate) struct RawKey {
    pub value: u64,
    pub kind: u64,
}
fn float_key_value(ordered: u64) -> f64 {
    f64::from_bits(if ordered & (1 << 63) != 0 {
        ordered ^ (1 << 63)
    } else {
        !ordered
    })
}
unsafe fn keys(raw: *const RawKey, len: u64) -> Result<Vec<Key>> {
    unsafe { std::slice::from_raw_parts(raw, len as usize) }
        .iter()
        .map(|key| {
            Ok(match key.kind {
                0 => Key::Number(key.value as i64),
                1 => Key::String(string(key.value)),
                2 => Key::Stack(string(key.value)),
                3 => {
                    let value = f64::from_bits(key.value);
                    if !value.is_finite() {
                        return Err("floating-point map keys must be finite".into());
                    }
                    let bits = if value == 0.0 { 0 } else { key.value };
                    Key::Float(if bits & (1 << 63) != 0 {
                        !bits
                    } else {
                        bits ^ (1 << 63)
                    })
                }
                _ => return Err("invalid map key type".into()),
            })
        })
        .collect()
}

// These callbacks have a fixed ABI shared with generated LLVM IR. They never unwind
// intentionally; script errors are saved in State and observed by the event loop.
pub(crate) unsafe extern "C" fn map_update(
    state: *mut State<'_>,
    id: u64,
    raw: *const RawKey,
    len: u64,
    value: i64,
    op: u64,
) {
    let state = unsafe { &mut *state };
    let key = match unsafe { keys(raw, len) } {
        Ok(key) => key,
        Err(error) => {
            state.fail(error);
            return;
        }
    };
    let linear = state.specs[id as usize].linear;
    let map = &mut state.maps[id as usize];
    if op == 8 {
        if let Some(cell) = map.remove(&key) {
            state.series_points = state.series_points.saturating_sub(cell.series.len());
        }
        return;
    }
    if !map.contains_key(&key) && map.len() >= state.max_entries {
        state.fail(format!(
            "map @{} reached the {} entry limit",
            state.specs[id as usize].name, state.max_entries
        ));
        return;
    }
    let cell = map.entry(key).or_default();
    if state.specs[id as usize].value_type == Type::Float {
        let value = f64::from_bits(value as u64);
        if !value.is_finite() {
            state.fail("floating-point map value must remain finite".into());
            return;
        }
        if matches!(op, 6 | 7) {
            let bin = if op == 6 {
                if value < 0.0 {
                    -1
                } else if value == 0.0 {
                    0
                } else {
                    let bits = value.to_bits();
                    let exponent = ((bits >> 52) & 0x7ff) as i32;
                    let exponent = if exponent == 0 {
                        63 - (bits & ((1u64 << 52) - 1)).leading_zeros() as i32 - 1074
                    } else {
                        exponent - 1023
                    };
                    exponent + 1076
                }
            } else {
                let Some((min, max, step)) = state.specs[id as usize].float_linear else {
                    state.fail("missing floating histogram bounds".into());
                    return;
                };
                let (min, max, step) = (
                    f64::from_bits(min),
                    f64::from_bits(max),
                    f64::from_bits(step),
                );
                if value < min {
                    -1
                } else if value >= max {
                    ((max - min) / step).ceil().max(1.0) as i32
                } else {
                    (((value - min) / step).floor() as i32)
                        .clamp(0, (((max - min) / step).ceil().max(1.0) as i32) - 1)
                }
            };
            let count = cell.buckets.entry(bin).or_default();
            *count = count.saturating_add(1);
            cell.count = cell.count.saturating_add(1);
            return;
        }
        let result = match op {
            0 => value,
            2 | 5 | 9 => cell.floating + value,
            3 => {
                if cell.count == 0 {
                    value
                } else {
                    cell.floating.min(value)
                }
            }
            4 => {
                if cell.count == 0 {
                    value
                } else {
                    cell.floating.max(value)
                }
            }
            _ => {
                state.fail("unsupported floating-point aggregation".into());
                return;
            }
        };
        if !value.is_finite() || !result.is_finite() {
            state.fail("floating-point map value must remain finite".into());
            return;
        }
        cell.floating = result;
        cell.count = cell.count.saturating_add(1);
        return;
    }
    match op {
        0 => cell.value = value,
        1 | 2 => cell.value = cell.value.wrapping_add(value),
        3 => {
            cell.value = if cell.count == 0 {
                value
            } else {
                cell.value.min(value)
            }
        }
        4 => {
            cell.value = if cell.count == 0 {
                value
            } else {
                cell.value.max(value)
            }
        }
        5 | 9 => cell.total = cell.total.wrapping_add(value as i128),
        6 => {
            let bin = if value < 0 {
                -1
            } else if value == 0 {
                0
            } else {
                let power = 63 - (value as u64).leading_zeros();
                let parts = 1u128 << state.specs[id as usize].histogram_precision;
                let base = 1u128 << power;
                let sub = (((value as u128) - base) * parts / base) as i32;
                (power as i32) * (parts as i32) + sub + 1
            };
            *cell.buckets.entry(bin).or_default() += 1;
        }
        7 => {
            let (min, max, step) = linear.unwrap();
            let bin = if value < min {
                -1
            } else if value >= max {
                ((max as i128 - min as i128 + step as i128 - 1) / step as i128) as i32
            } else {
                ((value as i128 - min as i128) / step as i128) as i32
            };
            *cell.buckets.entry(bin).or_default() += 1;
        }
        10 => {
            state.fail("tseries requires its timestamp-aware update path".into());
            return;
        }
        _ => {
            state.fail("invalid aggregate operation".into());
            return;
        }
    }
    cell.count = cell.count.saturating_add(1);
}
pub(crate) unsafe extern "C" fn map_get(
    state: *mut State<'_>,
    id: u64,
    raw: *const RawKey,
    len: u64,
) -> i64 {
    let state = unsafe { &mut *state };
    let key = match unsafe { keys(raw, len) } {
        Ok(key) => key,
        Err(error) => {
            state.fail(error);
            return 0;
        }
    };
    state.maps[id as usize]
        .get(&key)
        .map(|c| c.bits(&state.specs[id as usize]))
        .unwrap_or(0)
}
pub(crate) unsafe extern "C" fn print(state: *mut State<'_>, id: u64, args: *const u64) {
    let state = unsafe { &mut *state };
    let format = &state.formats[id as usize];
    let args = unsafe { std::slice::from_raw_parts(args, format.types.len()) };
    let text = format.render(args);
    state.write(&text);
}
pub(crate) unsafe extern "C" fn map_action(state: *mut State<'_>, id: u64, action: u64) {
    let state = unsafe { &mut *state };
    if action == 0 {
        state.print_map(id as usize);
    } else if action == 1 {
        state.series_points = state.series_points.saturating_sub(
            state.maps[id as usize]
                .values()
                .map(|cell| cell.series.len())
                .sum::<usize>(),
        );
        state.maps[id as usize].clear();
    } else if action == 2 {
        for cell in state.maps[id as usize].values_mut() {
            state.series_points = state.series_points.saturating_sub(cell.series.len());
            *cell = Cell::default();
        }
    }
}
pub(crate) unsafe extern "C" fn stop(state: *mut State<'_>) {
    unsafe {
        (*state).stopped = true;
    }
}
pub(crate) unsafe extern "C" fn stopped(state: *mut State<'_>) -> u64 {
    unsafe { (*state).stopped as u64 }
}
pub(crate) unsafe extern "C" fn streq(a: *const c_char, b: *const c_char) -> u64 {
    unsafe { (CStr::from_ptr(a).to_bytes() == CStr::from_ptr(b).to_bytes()) as u64 }
}

unsafe fn ustack_inner(state: *mut State<'_>, event: *const Event<'_>, depth: u64) -> u64 {
    let state = unsafe { &mut *state };
    let event = unsafe { &*event };
    let frames =
        unsafe { std::slice::from_raw_parts(event.stack, (event.stack_len.min(depth)) as usize) };
    let text = state.symbols.stack(event.pid as u32, frames);
    // ELF names and proc paths can contain NULs. Keep them out of the C ABI.
    let text = CString::new(text.replace('\0', "\\0")).unwrap();
    let pointer = text.as_ptr() as u64;
    state.stack_strings.push(text);
    pointer
}

fn bucket_label(bucket: i32, spec: &MapSpec) -> String {
    if let Some((min, max, step)) = spec.float_linear {
        let (min, max, step) = (
            f64::from_bits(min),
            f64::from_bits(max),
            f64::from_bits(step),
        );
        if bucket < 0 {
            return format!("(-inf, {})", significant(min, 17));
        }
        let lower = min + bucket as f64 * step;
        if lower >= max || bucket >= ((max - min) / step).ceil().max(1.0) as i32 {
            return format!("[{}, +inf)", significant(max, 17));
        }
        return format!(
            "[{}, {})",
            significant(lower, 17),
            significant((lower + step).min(max), 17)
        );
    }
    if spec.value_type == Type::Float && spec.aggregate == Aggregate::Hist {
        return match bucket {
            -1 => "(-inf, 0)".into(),
            0 => "[0, 0]".into(),
            bucket => {
                let exponent = bucket - 1076;
                let power = |exp: i32| {
                    if exp > 1023 {
                        f64::INFINITY
                    } else if exp >= -1022 {
                        f64::from_bits(((exp + 1023) as u64) << 52)
                    } else {
                        f64::from_bits(1u64 << (exp + 1074))
                    }
                };
                let lower = power(exponent);
                let upper = power(exponent + 1);
                format!(
                    "[{}, {})",
                    significant(lower, 15),
                    if upper.is_finite() {
                        significant(upper, 15)
                    } else {
                        "+inf".into()
                    }
                )
            }
        };
    }
    if let Some((min, max, step)) = spec.linear {
        if bucket < 0 {
            return format!("(-inf, {min})");
        }
        let lower = min as i128 + bucket as i128 * step as i128;
        if lower >= max as i128 {
            return format!("[{max}, +inf)");
        }
        return format!("[{lower}, {})", (lower + step as i128).min(max as i128));
    }
    match bucket {
        -1 => "(-inf, 0)".into(),
        0 => "[0, 1)".into(),
        n => {
            let parts = 1u128 << spec.histogram_precision;
            let power = ((n - 1) as u128 / parts) as u32;
            let sub = (n - 1) as u128 % parts;
            let base = 1u128 << power;
            format!(
                "[{}, {})",
                base + base * sub / parts,
                base + base * (sub + 1) / parts
            )
        }
    }
}

unsafe fn helper_inner(
    state: *mut State<'_>,
    event: *const Event<'_>,
    op: u64,
    value: u64,
    length: u64,
) -> u64 {
    let state = unsafe { &mut *state };
    let event = unsafe { &*event };
    let result: Result<String> = match op {
        160 => {
            let format = unsafe { CStr::from_ptr(length as *const c_char) };
            (|| -> Result<String> {
                if format.to_bytes().len() > 1024 {
                    return Err("time format exceeds 1024 bytes".into());
                }
                if format.to_bytes().is_empty() {
                    return Ok(String::new());
                }
                let mut now: libc::timespec = unsafe { std::mem::zeroed() };
                if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) } != 0 {
                    return Err(format!("time: {}", std::io::Error::last_os_error()));
                }
                let mut local: libc::tm = unsafe { std::mem::zeroed() };
                if unsafe { libc::localtime_r(&now.tv_sec, &mut local) }.is_null() {
                    return Err("time: local calendar conversion failed".into());
                }
                // A literal prefix distinguishes valid empty output (e.g. a
                // locale's empty zone name) from strftime's overflow result.
                let mut prefixed = vec![b' '];
                prefixed.extend_from_slice(format.to_bytes());
                let prefixed = CString::new(prefixed).unwrap();
                let mut output = [0u8; 4097];
                let written = unsafe {
                    libc::strftime(
                        output.as_mut_ptr().cast(),
                        output.len(),
                        prefixed.as_ptr(),
                        &local,
                    )
                };
                if written == 0 {
                    return Err("time formatting failed or output exceeds 4095 bytes".into());
                }
                Ok(String::from_utf8_lossy(&output[1..written]).into_owned())
            })()
        }
        115 => {
            let descriptor = unsafe { CStr::from_ptr(length as *const c_char) }.to_string_lossy();
            (|| -> Result<String> {
                let (path, signature): (String, String) =
                    serde_json::from_str(&descriptor).map_err(|e| e.to_string())?;
                let probe = unsafe { CStr::from_ptr(event.probe) }.to_string_lossy();
                let crate::language::Probe::Uprobe {
                    path: default_path,
                    ret: false,
                    ..
                } = crate::language::Probe::parse(&probe)?
                else {
                    return Err("args_as requires a stopped user function entry probe".into());
                };
                crate::arguments::format_explicit(
                    &mut state.types,
                    event.pid as u32,
                    event.tid as u32,
                    if path.is_empty() {
                        &default_path
                    } else {
                        &path
                    },
                    &signature,
                )
            })()
        }
        114 => {
            let descriptor = unsafe { CStr::from_ptr(length as *const c_char) }.to_string_lossy();
            (|| -> Result<String> {
                let (path, function): (String, String) =
                    serde_json::from_str(&descriptor).map_err(|e| e.to_string())?;
                let probe = unsafe { CStr::from_ptr(event.probe) }.to_string_lossy();
                let crate::language::Probe::Uprobe {
                    path: default_path,
                    function: default_function,
                    ret: false,
                } = crate::language::Probe::parse(&probe)?
                else {
                    return Err("args_native requires a stopped user function probe".into());
                };
                state.native_args.format(
                    event.pid as u32,
                    event.tid as u32,
                    if path.is_empty() {
                        &default_path
                    } else {
                        &path
                    },
                    if function.is_empty() {
                        &default_function
                    } else {
                        &function
                    },
                )
            })()
        }
        130 => {
            if state.stopped {
                return 0;
            }
            if state.recursion_depth >= 64
                || state.fuel == 0
                || state.recursion_cost.saturating_add(value) > 512 * 1024
            {
                state.fail(
                    "expression function exceeded recursion depth64, shared invocation fuel4096, or native frame budget512KiB"
                        .into(),
                );
                return 0;
            }
            state.recursion_depth += 1;
            state.recursion_cost += value;
            state.fuel -= 1;
            return 1;
        }
        131 => {
            state.recursion_depth = state.recursion_depth.saturating_sub(1);
            state.recursion_cost = state.recursion_cost.saturating_sub(value);
            return 0;
        }
        120 => Ok(state
            .kernel_symbols
            .stack(&state.kernel_frames[..state.kernel_frames.len().min(value as usize)])),
        121 => Ok(state.kernel_symbols.symbol(value)),
        122..=125 => {
            let descriptor = unsafe { CStr::from_ptr(length as *const c_char) }.to_string_lossy();
            let result = (|| -> Result<String> {
                let (ty, field): (String, String) =
                    serde_json::from_str(&descriptor).map_err(|e| e.to_string())?;
                if op == 125 {
                    return state.btf.field_string(value, &ty, &field);
                }
                let result = match op {
                    122 => state.btf.size_of(&ty),
                    123 => state.btf.offset_of(&ty, &field),
                    _ => state.btf.field(value, &ty, &field),
                }?;
                Ok(result.to_string())
            })();
            if op == 125 {
                result
            } else {
                return match result {
                    Ok(value) => value.parse::<u64>().unwrap_or(0),
                    Err(error) => {
                        state.fail(error);
                        0
                    }
                };
            }
        }
        150..=154 => {
            let runtime = match op {
                150 => "async",
                151 => "java",
                152 => "dotnet",
                153 => "wasm",
                _ => "all",
            };
            Ok(state
                .managed
                .stack(
                    event.pid as u32,
                    if op == 154 { 0 } else { event.tid as u32 },
                    runtime,
                    length as usize,
                )
                .unwrap_or_else(|error| {
                    format!(
                        "    <{runtime} stack unavailable: {}>\n",
                        error.replace(['\n', '\r'], "?")
                    )
                }))
        }
        111 => return (f64::from_bits(value) % f64::from_bits(length)).to_bits(),
        110 => {
            return if length == 1 {
                f64::from_bits(value) as u64
            } else {
                (f64::from_bits(value) as i64) as u64
            };
        }
        90 => {
            if state.iterations.len() >= 4096 {
                state.fail("map iteration snapshot limit exceeded".into());
                return 0;
            }
            let Some(map) = state.maps.get(value as usize) else {
                state.fail("invalid map iteration".into());
                return 0;
            };
            if state
                .iterations
                .iter()
                .map(Vec::len)
                .sum::<usize>()
                .saturating_add(map.len().min(4097))
                > 65536
            {
                state.fail("map iteration snapshot entry limit exceeded".into());
                return 0;
            }
            let spec = &state.specs[value as usize];
            let snapshot = map
                .iter()
                .take(4097)
                .map(|(keys, cell)| (keys.clone(), cell.bits(spec)))
                .collect();
            let id = state.iterations.len();
            state.iterations.push(snapshot);
            return id as u64;
        }
        91..=93 => {
            let Some(snapshot) = state.iterations.get(value as usize) else {
                state.fail("invalid map iteration snapshot".into());
                return 0;
            };
            if op == 93 {
                return snapshot.len() as u64;
            }
            let row = if op == 91 { length >> 32 } else { length };
            let Some((keys, number)) = snapshot.get(row as usize) else {
                state.fail("invalid map iteration index".into());
                return 0;
            };
            if op == 92 {
                return *number as u64;
            }
            let Some(key) = keys.get((length & 0xffff_ffff) as usize) else {
                state.fail("invalid map iteration key index".into());
                return 0;
            };
            match key {
                Key::Number(number) => return *number as u64,
                Key::Float(value) => return float_key_value(*value).to_bits(),
                Key::String(text) | Key::Stack(text) => Ok(text.clone()),
            }
        }

        0 => Ok(state.symbols.symbol(event.pid as u32, value)),
        1 => crate::memory::read(event.pid as u32, value, length as usize, true).map(|bytes| {
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        }),
        2 => crate::memory::read(event.pid as u32, value, length as usize, false).map(|bytes| {
            bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        }),
        3..=6 => {
            let size = 1 << (op - 3);
            return match crate::memory::read(event.pid as u32, value, size, false) {
                Ok(bytes) => {
                    let mut raw = [0; 8];
                    raw[..size].copy_from_slice(&bytes);
                    match size {
                        1 => raw[0] as u64,
                        2 => u16::from_ne_bytes(raw[..2].try_into().unwrap()) as u64,
                        4 => u32::from_ne_bytes(raw[..4].try_into().unwrap()) as u64,
                        _ => u64::from_ne_bytes(raw),
                    }
                }
                Err(error) => {
                    state.fail(error);
                    0
                }
            };
        }
        70 => Ok(state
            .wait_reason
            .clone()
            .unwrap_or_else(|| "<no wait snapshot>".into())),
        60 => {
            match crate::functions::floating_argument(
                event.tid as i32,
                value as usize,
                length == 32,
            ) {
                Ok(bits) => Ok(if length == 32 {
                    f32::from_bits(bits as u32).to_string()
                } else {
                    f64::from_bits(bits).to_string()
                }),
                Err(error) => Err(error),
            }
        }
        61 => {
            let result = (|| -> Result<u64> {
                let regs = crate::functions::user_registers(event.tid as i32)?;
                #[cfg(target_arch = "x86_64")]
                let skip = 1;
                #[cfg(target_arch = "aarch64")]
                let skip = 0;
                let address = regs
                    .sp
                    .checked_add((value + skip) * 8)
                    .ok_or("stack argument overflow")?;
                let bytes = crate::memory::read(event.tid as u32, address, 8, false)?;
                Ok(u64::from_ne_bytes(bytes.try_into().unwrap()))
            })();
            return match result {
                Ok(value) => value,
                Err(error) => {
                    state.fail(error);
                    0
                }
            };
        }
        40..=46 => {
            let descriptor = unsafe { CStr::from_ptr(length as *const c_char) }.to_string_lossy();
            let result = (|| -> Result<u64> {
                let (path, name, field): (String, String, String) =
                    serde_json::from_str(&descriptor).map_err(|e| e.to_string())?;
                if op == 46 {
                    let probe = unsafe { CStr::from_ptr(event.probe) }.to_string_lossy();
                    let crate::language::Probe::Uprobe {
                        path: default_path,
                        function: default_function,
                        ret: false,
                    } = crate::language::Probe::parse(&probe)?
                    else {
                        return Err("args() requires a ptrace function entry probe".into());
                    };
                    let path = if path.is_empty() {
                        &default_path
                    } else {
                        &path
                    };
                    let function = if name.is_empty() {
                        &default_function
                    } else {
                        &name
                    };
                    let text = crate::arguments::format(
                        &mut state.types,
                        event.pid as u32,
                        event.tid as u32,
                        path,
                        function,
                    )?;
                    let text = CString::new(text.replace('\0', "\\0")).unwrap();
                    let pointer = text.as_ptr() as u64;
                    state.stack_strings.push(text);
                    return Ok(pointer);
                }
                if op == 45 {
                    let text = state
                        .types
                        .describe(event.pid as u32, &path, &name, value)?;
                    let text = CString::new(text.replace('\0', "\\0")).unwrap();
                    let pointer = text.as_ptr() as u64;
                    state.stack_strings.push(text);
                    return Ok(pointer);
                }
                let layout = state.types.layout(event.pid as u32, &path, &name, &field)?;
                if op == 41 {
                    if !layout.dereferences.is_empty() || layout.bits.is_some() {
                        return Err(
                            "offsetof requires an addressable member without pointer traversal"
                                .into(),
                        );
                    }
                    return Ok(layout.offset);
                }
                if op == 42 {
                    return Ok(layout.size);
                }
                if !layout.scalar
                    || !(1..=8).contains(&layout.size)
                    || (layout.bits.is_none() && ![1, 2, 4, 8].contains(&layout.size))
                {
                    return Err("field reads require a 1/2/4/8-byte scalar".into());
                }
                let mut address = value;
                for offset in &layout.dereferences {
                    let pointer = crate::memory::read(
                        event.pid as u32,
                        address
                            .checked_add(*offset)
                            .ok_or("pointer member address overflow")?,
                        8,
                        false,
                    )?;
                    address = u64::from_ne_bytes(pointer.try_into().unwrap());
                    if address == 0 {
                        return Err("null pointer in DWARF field traversal".into());
                    }
                }
                let bytes = crate::memory::read(
                    event.pid as u32,
                    address
                        .checked_add(layout.offset)
                        .ok_or("field address overflow")?,
                    layout.size as usize,
                    false,
                )?;
                let mut raw = [0; 8];
                raw[..bytes.len()].copy_from_slice(&bytes);
                let mut value = u64::from_ne_bytes(raw);
                let width = if let Some((shift, bits)) = layout.bits {
                    value >>= shift;
                    if bits < 64 {
                        value &= (1u64 << bits) - 1;
                    }
                    bits as u64
                } else {
                    layout.size * 8
                };
                if op == 44 {
                    return Ok(if layout.float && layout.size == 4 {
                        (f32::from_bits(value as u32) as f64).to_bits()
                    } else if layout.float && layout.size == 8 {
                        value
                    } else if layout.signed {
                        (((value << (64 - width)) as i64 >> (64 - width)) as f64).to_bits()
                    } else {
                        (value as f64).to_bits()
                    });
                }
                if op == 43 {
                    let text = if layout.float && layout.size == 4 {
                        f32::from_bits(value as u32).to_string()
                    } else if layout.float && layout.size == 8 {
                        f64::from_bits(value).to_string()
                    } else if layout.signed {
                        ((value << (64 - width)) as i64 >> (64 - width)).to_string()
                    } else {
                        value.to_string()
                    };
                    let text = CString::new(text).unwrap();
                    let ptr = text.as_ptr() as u64;
                    state.stack_strings.push(text);
                    return Ok(ptr);
                }
                if layout.float {
                    return Err("use fieldstr for floating-point fields".into());
                }
                Ok(if layout.signed && width < 64 {
                    ((value << (64 - width)) as i64 >> (64 - width)) as u64
                } else {
                    value
                })
            })();
            return match result {
                Ok(value) => value,
                Err(error) => {
                    state.fail(error);
                    if op == 43 || op == 45 || op == 46 {
                        let empty = CString::default();
                        let ptr = empty.as_ptr() as u64;
                        state.stack_strings.push(empty);
                        ptr
                    } else {
                        0
                    }
                }
            };
        }
        80 | 81 => {
            let name = unsafe { CStr::from_ptr(value as *const c_char) }.to_string_lossy();
            match state.trace_fields.get(name.as_ref()) {
                Some(crate::kernel::Value::Integer(number)) if op == 80 => return *number,
                Some(crate::kernel::Value::Integer(number)) => Ok(number.to_string()),
                Some(crate::kernel::Value::String(text)) if op == 81 => {
                    Ok(text.chars().take(4096).collect())
                }
                Some(_) => {
                    Err("tp requires a numeric tracepoint field; use tpstr for strings".into())
                }
                None => Err(format!("tracepoint field '{name}' unavailable")),
            }
        }
        53 => Ok(state
            .golang
            .parked(event.pid as u32, length as usize, value as usize)
            .unwrap_or_else(|error| {
                format!(
                    "    <Go goroutines unavailable: {}>\n",
                    error.replace(['\n', '\r'], "?")
                )
            })),
        52 => Ok(state
            .golang
            .stack(
                event.pid as u32,
                event.tid as u32,
                length as usize,
                state.js_snapshot.as_ref(),
            )
            .unwrap_or_else(|error| {
                format!(
                    "    <Go stack unavailable: {}>\n",
                    error.replace(['\n', '\r'], "?")
                )
            })),
        51 => Ok(state
            .javascript
            .stack(
                event.pid as u32,
                event.tid as u32,
                length as usize,
                state.js_snapshot.as_ref().filter(|_| !state.target_paused),
            )
            .unwrap_or_else(|error| {
                format!(
                    "    <JavaScript stack unavailable: {}>\n",
                    error.replace(['\n', '\r'], "?")
                )
            })),
        50 => Ok(state
            .python
            .stack(event.pid as u32, event.tid as u32, length as usize)
            .unwrap_or_else(|error| {
                format!(
                    "    <Python stack unavailable: {}>\n",
                    error.replace(['\n', '\r'], "?")
                )
            })),
        30 | 31 => {
            let index = (value & 0xffff_ffff) as usize;
            let id = (value >> 32) as u32;
            if index >= 256 || id >= 128 {
                state.fail("local array index must be 0..255".into());
                return 0;
            }
            let array = state.scratch.entry(id).or_insert_with(|| vec![0; 256]);
            if op == 31 {
                array[index] = length;
            }
            return array[index];
        }
        20 => {
            if state.fuel == 0 {
                state.fail("handler exceeded 4096 loop iterations".into());
                return 0;
            }
            state.fuel -= 1;
            return 1;
        }
        11..=16 => {
            let first = unsafe { CStr::from_ptr(value as *const c_char) }.to_string_lossy();
            if op == 11 {
                return first.len() as u64;
            }
            if op == 16 {
                let start = (length >> 32) as usize;
                let size = (length & 0xffff_ffff) as usize;
                let bytes = first.as_bytes();
                Ok(String::from_utf8_lossy(
                    &bytes[start.min(bytes.len())..start.saturating_add(size).min(bytes.len())],
                )
                .into_owned())
            } else {
                let second = unsafe { CStr::from_ptr(length as *const c_char) }.to_string_lossy();
                match op {
                    12 => return first.contains(second.as_ref()) as u64,
                    13 => return first.starts_with(second.as_ref()) as u64,
                    14 => return first.ends_with(second.as_ref()) as u64,
                    _ => {
                        if first.len() + second.len() > 4096 {
                            Err("strcat result exceeds 4096 bytes".into())
                        } else {
                            Ok(format!("{first}{second}"))
                        }
                    }
                }
            }
        }
        10 => {
            let branches =
                unsafe { std::slice::from_raw_parts(event.branches, event.branch_len as usize) };
            let mut out = String::new();
            for branch in branches {
                out.push_str(&format!(
                    "    {} -> {}\n",
                    state.symbols.symbol(event.pid as u32, branch.from),
                    state.symbols.symbol(event.pid as u32, branch.to)
                ));
            }
            if out.is_empty() {
                out.push_str("    <no branch stack>\n");
            }
            Ok(out)
        }
        _ => Err("invalid runtime helper".into()),
    };
    let text = match result {
        Ok(text) => text,
        Err(error) => {
            state.fail(error);
            String::new()
        }
    };
    let text = CString::new(text.replace('\0', "\\0")).unwrap();
    let pointer = text.as_ptr() as u64;
    state.stack_strings.push(text);
    pointer
}

unsafe fn recorded_helper(
    state: *mut State<'_>,
    event: *const Event<'_>,
    op: u64,
    value: u64,
    length: u64,
) -> u64 {
    if matches!(op, 200 | 201) {
        return unsafe { crate::builtins::invoke(state, event, op, value, length) };
    }
    if matches!(op, 110 | 111 | 130 | 131) || (90..=93).contains(&op) {
        return unsafe { helper_inner(state, event, op, value, length) };
    }
    let s = unsafe { &mut *state };
    let string_result = matches!(
        op,
        0 | 1
            | 2
            | 10
            | 15
            | 16
            | 43
            | 45
            | 46
            | 50
            | 51
            | 52
            | 53
            | 60
            | 70
            | 81
            | 100
            | 114
            | 115
            | 120
            | 121
            | 125
            | 150..=154 | 160
    );
    let empty = if string_result {
        c"".as_ptr() as u64
    } else {
        0
    };
    let descriptor = if (40..=46).contains(&op)
        || ((122..=125).contains(&op) || matches!(op, 114 | 115 | 160))
    {
        Some(
            unsafe { CStr::from_ptr(length as *const c_char) }
                .to_string_lossy()
                .into_owned(),
        )
    } else if matches!(op, 80 | 81) {
        Some(
            unsafe { CStr::from_ptr(value as *const c_char) }
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        None
    };
    if s.replay_lookup && matches!(op, 11..=16 | 20 | 30 | 31 | 80 | 81) {
        return unsafe { helper_inner(state, event, op, value, length) };
    }
    if s.replay_lookup
        && (1..=6).contains(&op)
        && !s.replay.as_ref().is_some_and(|queue| {
            queue
                .iter()
                .any(|item| item.op == op && item.value == value && item.length == length)
        })
    {
        let size = if op <= 2 {
            length as usize
        } else {
            1usize << (op - 3)
        };
        let bytes = match crate::recording::read_memory(&s.replay_memory, value, size, op == 1) {
            Ok(bytes) => bytes,
            Err(error) => {
                s.fail(error);
                return empty;
            }
        };
        if op >= 3 {
            let mut raw = [0; 8];
            raw[..bytes.len()].copy_from_slice(&bytes);
            return match size {
                1 => raw[0] as u64,
                2 => u16::from_ne_bytes(raw[..2].try_into().unwrap()) as u64,
                4 => u32::from_ne_bytes(raw[..4].try_into().unwrap()) as u64,
                _ => u64::from_ne_bytes(raw),
            };
        }
        let text = if op == 1 {
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        } else {
            bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let text = CString::new(text.replace('\0', "\\0")).unwrap();
        let ptr = text.as_ptr() as u64;
        s.stack_strings.push(text);
        return ptr;
    }
    if s.replay_lookup && matches!(op, 10 | 50 | 51 | 52 | 100 | 120) {
        let requested = if matches!(op, 100 | 120) {
            value
        } else {
            length
        };
        let candidates: Vec<_> = s
            .replay
            .as_ref()
            .map(|queue| {
                queue
                    .iter()
                    .filter(|item| {
                        item.op == op
                            && if op == 10 {
                                true
                            } else {
                                let depth = if matches!(op, 100 | 120) {
                                    item.value
                                } else {
                                    item.length
                                };
                                depth >= requested
                            }
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let prefix = |item: &crate::recording::Helper| {
            item.text.as_ref().map(|text| {
                if op == 10 {
                    text.clone()
                } else {
                    text.split_inclusive('\n')
                        .take(requested as usize + usize::from(op == 52))
                        .collect::<String>()
                }
            })
        };
        if candidates
            .windows(2)
            .any(|pair| prefix(&pair[0]) != prefix(&pair[1]) || pair[0].error != pair[1].error)
        {
            s.fail("captured stack results conflict for this observation".into());
            return empty;
        }
        let text = if let Some(item) = candidates.into_iter().next() {
            if let Some(error) = item.error {
                s.fail(error);
                return empty;
            }
            let Some(text) = item.text else {
                s.fail("recording helper result has the wrong type".into());
                return empty;
            };
            if op == 10 {
                Some(text)
            } else {
                Some(
                    text.split_inclusive('\n')
                        .take(requested as usize + usize::from(op == 52))
                        .collect::<String>(),
                )
            }
        } else if op == 120 {
            Some(if s.kernel_frames.is_empty() {
                "    <no kernel stack>\n".into()
            } else {
                s.kernel_frames
                    .iter()
                    .take(requested as usize)
                    .map(|ip| format!("    0x{ip:x}\n"))
                    .collect::<String>()
            })
        } else if op == 100 {
            let event = unsafe { &*event };
            let frames = event.stack_frames();
            Some(if frames.is_empty() {
                "    <no user stack>\n".into()
            } else {
                frames
                    .iter()
                    .take(requested as usize)
                    .map(|ip| format!("    0x{ip:x}\n"))
                    .collect::<String>()
            })
        } else if op == 10 {
            let event = unsafe { &*event };
            let branches = event.branch_records();
            Some(if branches.is_empty() {
                "    <no branch stack>\n".into()
            } else {
                branches
                    .iter()
                    .map(|b| format!("    0x{:x} -> 0x{:x}\n", b.from, b.to))
                    .collect::<String>()
            })
        } else {
            None
        };
        if let Some(text) = text {
            let text = CString::new(text.replace('\0', "\\0")).unwrap();
            let ptr = text.as_ptr() as u64;
            s.stack_strings.push(text);
            return ptr;
        }
    }
    if let Some(queue) = &mut s.replay {
        let item = if s.replay_lookup {
            let matches: Vec<_> = queue
                .iter()
                .filter(|item| {
                    item.op == op
                        && if (40..=46).contains(&op)
                            || ((122..=125).contains(&op) || matches!(op, 114 | 115 | 160))
                        {
                            item.value == value && item.descriptor == descriptor
                        } else if matches!(op, 80 | 81) {
                            item.descriptor == descriptor
                        } else {
                            (item.value, item.length) == (value, length)
                        }
                })
                .cloned()
                .collect();
            if matches.windows(2).any(|pair| {
                pair[0].number != pair[1].number
                    || pair[0].text != pair[1].text
                    || pair[0].error != pair[1].error
            }) {
                s.fail("captured helper results conflict for this observation".into());
                return empty;
            }
            matches.into_iter().next()
        } else {
            queue.pop_front()
        };
        let Some(item) = item else {
            s.fail(
                if s.replay_lookup {
                    "alternate replay requires a captured result for this helper"
                } else {
                    "recording helper stream exhausted"
                }
                .into(),
            );
            return empty;
        };
        if op == 160 && item.descriptor != descriptor {
            s.fail("recording time format does not match script".into());
            return empty;
        }
        if item.op != op
            || (!(11..=16).contains(&op)
                && !((40..=46).contains(&op)
                    || ((122..=125).contains(&op) || matches!(op, 114 | 115 | 160)))
                && !matches!(op, 80 | 81)
                && (item.value, item.length) != (value, length))
            || ((40..=46).contains(&op)
                || ((122..=125).contains(&op) || matches!(op, 114 | 115 | 160)))
                && item.value != value
            || op == 16 && item.length != length
        {
            s.fail("recording helper call does not match script".into());
            return empty;
        }
        if item.text.is_some() != string_result {
            s.fail("recording helper result has the wrong type".into());
            return empty;
        }
        if let Some(error) = item.error {
            s.fail(error);
        }
        if let Some(text) = item.text {
            let text = CString::new(text.replace('\0', "\\0")).unwrap();
            let ptr = text.as_ptr() as u64;
            s.stack_strings.push(text);
            return ptr;
        }
        if op == 20 || op == 30 || op == 31 {
            let actual = unsafe { helper_inner(state, event, op, value, length) };
            let s = unsafe { &mut *state };
            if actual != item.number && s.error.is_none() {
                s.fail("recording deterministic helper result mismatch".into());
            }
            return actual;
        }
        return item.number;
    }
    let result = if op == 100 {
        unsafe { ustack_inner(state, event, value) }
    } else {
        unsafe { helper_inner(state, event, op, value, length) }
    };
    let s = unsafe { &mut *state };
    if s.recorder.is_some() {
        let text = if string_result {
            Some(
                unsafe { CStr::from_ptr(result as *const c_char) }
                    .to_string_lossy()
                    .into_owned(),
            )
        } else {
            None
        };
        s.journal.push(crate::recording::Helper {
            op,
            value,
            length,
            number: if text.is_some() { 0 } else { result },
            text,
            descriptor,
            error: s.error.clone(),
        });
    }
    result
}
pub(crate) unsafe extern "C" fn helper(
    state: *mut State<'_>,
    event: *const Event<'_>,
    op: u64,
    value: u64,
    length: u64,
) -> u64 {
    unsafe { recorded_helper(state, event, op, value, length) }
}
pub(crate) unsafe extern "C" fn ustack(
    state: *mut State<'_>,
    event: *const Event<'_>,
    depth: u64,
) -> u64 {
    unsafe { recorded_helper(state, event, 100, depth, 0) }
}

pub(crate) unsafe extern "C" fn exit_code(state: *mut State<'_>, code: u64) {
    let state = unsafe { &mut *state };
    if code > 255 {
        state.fail("exit status must be 0..255".into());
    } else {
        state.exit_code = code as i32;
        state.exit_set = true;
        state.stopped = true;
    }
}
pub(crate) unsafe extern "C" fn diagnostic(state: *mut State<'_>, text: u64) {
    let state = unsafe { &mut *state };
    let text = unsafe { CStr::from_ptr(text as *const c_char) }.to_bytes();
    if let Err(error) = std::io::stderr().write_all(text) {
        state.fail(format!("diagnostic output: {error}"));
    }
}

pub(crate) unsafe extern "C" fn map_query(
    state: *mut State<'_>,
    id: u64,
    raw: *const RawKey,
    len: u64,
    op: u64,
) -> u64 {
    let state = unsafe { &mut *state };
    if op == 1 {
        return state.maps[id as usize].len() as u64;
    }
    let key = match unsafe { keys(raw, len) } {
        Ok(key) => key,
        Err(error) => {
            state.fail(error);
            return 0;
        }
    };
    let map = &mut state.maps[id as usize];
    if op == 2 {
        if let Some(cell) = map.remove(&key) {
            state.series_points = state.series_points.saturating_sub(cell.series.len());
            1
        } else {
            0
        }
    } else {
        map.contains_key(&key) as u64
    }
}
pub(crate) unsafe extern "C" fn map_print(state: *mut State<'_>, id: u64, top: u64, div: u64) {
    let state = unsafe { &mut *state };
    if div == 0 || div > i64::MAX as u64 || top > i64::MAX as u64 {
        state.fail("print requires nonnegative top and positive div".into());
        return;
    }
    let saved = std::mem::take(&mut state.maps[id as usize]);
    let spec = state.specs[id as usize].clone();
    let mut entries: Vec<_> = saved.iter().collect();
    entries.sort_by(|(ka, a), (kb, b)| {
        let order = if spec.value_type == Type::Float {
            b.floating(spec.aggregate)
                .total_cmp(&a.floating(spec.aggregate))
        } else {
            b.number(spec.aggregate).cmp(&a.number(spec.aggregate))
        };
        order.then_with(|| ka.cmp(kb))
    });
    for (key, cell) in entries
        .into_iter()
        .take(if top == 0 { usize::MAX } else { top as usize })
    {
        let mut cell = cell.clone();
        if spec.value_type == Type::Float {
            cell.floating /= div as f64;
        } else {
            cell.value /= div as i64;
            cell.total /= div as i128;
            for (total, _, value) in cell.series.values_mut() {
                *total /= div as i128;
                *value /= div as i64;
            }
            for count in cell.buckets.values_mut() {
                *count /= div;
            }
        }
        state.maps[id as usize].insert(key.clone(), cell);
        state.print_map(id as usize);
        state.maps[id as usize].clear();
    }
    // Restore original map contents even when rendering reports an output error.
    state.maps[id as usize] = saved;
}

pub(crate) unsafe extern "C" fn series_update(
    state: *mut State<'_>,
    event: *const Event<'_>,
    id: u64,
    raw: *const RawKey,
    len: u64,
    value: i64,
) {
    let state = unsafe { &mut *state };
    let event = unsafe { &*event };
    let key = match unsafe { keys(raw, len) } {
        Ok(key) => key,
        Err(e) => {
            state.fail(e);
            return;
        }
    };
    let Some((interval, limit, agg)) = state.specs[id as usize].series else {
        state.fail("invalid tseries metadata".into());
        return;
    };
    let map = &mut state.maps[id as usize];
    if !map.contains_key(&key) && map.len() >= state.max_entries {
        state.fail("tseries map entry limit exceeded".into());
        return;
    }
    let cell = map.entry(key).or_default();
    let bin = event.nsecs / interval * interval;
    let old_len = cell.series.len();
    if !cell.series.contains_key(&bin) && state.series_points >= 1_048_576 {
        state.fail("global tseries interval limit (1048576) exceeded".into());
        return;
    }
    let entry = cell.series.entry(bin).or_insert((0, 0, value));
    entry.0 = entry.0.wrapping_add(value as i128);
    entry.2 = match agg {
        Aggregate::Sum => entry.2.wrapping_add(if entry.1 == 0 { 0 } else { value }),
        Aggregate::Min => entry.2.min(value),
        Aggregate::Max => entry.2.max(value),
        _ => value,
    };
    entry.1 = entry.1.saturating_add(1);
    let newest = *cell.series.last_key_value().unwrap().0;
    let cutoff = newest.saturating_sub(interval.saturating_mul(limit.saturating_sub(1) as u64));
    cell.series.retain(|time, _| *time >= cutoff);
    while cell.series.len() > limit {
        cell.series.pop_first();
    }
    state.series_points = state.series_points.saturating_sub(old_len) + cell.series.len();
    cell.value = value;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn floating_general_precision_uses_significant_digits_and_rounded_exponents() {
        for (format, value, expected) in [
            ("%g", 0.0, "0"),
            ("%g", -0.0, "-0"),
            ("%.3g", 0.000012345, "1.23e-5"),
            ("%.3g", 0.00012345, "0.000123"),
            ("%.3g", 123456.0, "1.23e5"),
            ("%.3g", 9.999, "10"),
            ("%.3g", 0.00009999, "0.0001"),
            ("%.0g", 9.999, "1e1"),
            ("%g", 1.0 / 3.0, "0.333333"),
            ("%.2f", 1.25, "1.25"),
        ] {
            assert_eq!(
                Format::parse(format)
                    .unwrap()
                    .render(&[f64::to_bits(value)]),
                expected,
                "{format} {value}"
            );
        }
        assert!(Format::parse("%.201g").is_err());
    }
    #[test]
    fn stack_fields_and_key_tags_match_the_llvm_abi() {
        assert_eq!(std::mem::offset_of!(Event<'_>, stack), 64);
        assert_eq!(std::mem::offset_of!(Event<'_>, stack_len), 72);
        assert_eq!(std::mem::size_of::<RawKey>(), 16);
        assert_eq!(std::mem::offset_of!(RawKey, kind), 8);
        assert_eq!(
            [Type::Number as u64, Type::String as u64, Type::Stack as u64],
            [0, 1, 2]
        );
    }
}
