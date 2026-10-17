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
    comm: *const c_char,
    probe: *const c_char,
    stack: *const u64,
    stack_len: u64,
    pub addr: u64,
    pub offcpu_ns: u64,
    pub preempt: u64,
    pub sysno: u64,
    pub retval: i64,
    pub latency: u64,
    pub args: [u64; 6],
    syscall: *const c_char,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Type {
    Number = 0,
    String = 1,
    Stack = 2,
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
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapSpec {
    pub name: String,
    pub keys: Vec<Type>,
    pub aggregate: Aggregate,
    pub linear: Option<(i64, i64, i64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatPart {
    Text(String),
    Value {
        conversion: char,
        width: usize,
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
            if chars.peek() == Some(&'l') {
                chars.next();
                if chars.peek() == Some(&'l') {
                    chars.next();
                }
            }
            let conversion = chars.next().ok_or("incomplete printf conversion")?;
            types.push(match conversion {
                's' => Type::String,
                'd' | 'i' | 'u' | 'x' | 'X' | 'o' | 'c' | 'p' => Type::Number,
                _ => return Err(format!("unsupported printf conversion %{conversion}")),
            });
            parts.push(FormatPart::Value {
                conversion,
                width,
                left,
                zero,
            });
        }
        if !text.is_empty() {
            parts.push(FormatPart::Text(text));
        }
        Ok(Self { parts, types })
    }
    fn render(&self, args: &[u64]) -> String {
        let mut out = String::new();
        let mut at = 0;
        for part in &self.parts {
            match part {
                FormatPart::Text(t) => out.push_str(t),
                FormatPart::Value {
                    conversion,
                    width,
                    left,
                    zero,
                } => {
                    let v = args[at];
                    at += 1;
                    let s = match conversion {
                        's' => string(v),
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
enum Key {
    Number(i64),
    String(String),
    Stack(String),
}
#[derive(Clone, Debug, Default)]
struct Cell {
    value: i64,
    total: i128,
    count: u64,
    buckets: BTreeMap<i32, u64>,
}
impl Cell {
    fn number(&self, agg: Aggregate) -> i64 {
        if agg == Aggregate::Avg {
            (self.total / self.count.max(1) as i128) as i64
        } else {
            self.value
        }
    }
}

pub struct State<'a> {
    pub(crate) origin: std::sync::Arc<()>,
    maps: Vec<BTreeMap<Vec<Key>, Cell>>,
    pub(crate) specs: Vec<MapSpec>,
    pub(crate) formats: Vec<Format>,
    writer: Box<dyn Write + 'a>,
    pub stopped: bool,
    pub error: Option<String>,
    pub max_entries: usize,
    pub(crate) stack_strings: Vec<CString>,
    symbols: crate::symbols::Symbolizer,
    pub report: crate::report::Options,
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
            error: None,
            max_entries: 65536,
            stack_strings: Vec::new(),
            symbols: crate::symbols::Symbolizer::default(),
            report: crate::report::Options::default(),
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
    fn fail(&mut self, e: String) {
        self.error = Some(e);
        self.stopped = true;
    }
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().map_err(|e| format!("output: {e}"))?;
        match &self.error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
    pub fn unwind_sample(&mut self, sample: &crate::perf::Sample) -> Vec<u64> {
        self.symbols.unwind(sample)
    }
    pub fn clear_all(&mut self) {
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
                    .map(|(bucket, count)| (bucket_label(*bucket, spec), *count))
                    .collect();
                rows.push(crate::report::Row {
                    map: spec.name.clone(),
                    keys,
                    value: cell.number(spec.aggregate),
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
            if matches!(spec.aggregate, Aggregate::Hist | Aggregate::Lhist) {
                out.push('\n');
                for (bucket, count) in &cell.buckets {
                    let label = bucket_label(*bucket, spec);
                    out.push_str(&format!("  {label}: {count}\n"));
                }
            } else {
                out.push_str(&format!("{}\n", cell.number(spec.aggregate)));
            }
        }
        self.write(&out);
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
unsafe fn keys(raw: *const RawKey, len: u64) -> Vec<Key> {
    // The compiler emits a properly aligned array with exactly len initialized entries.
    unsafe { std::slice::from_raw_parts(raw, len as usize) }
        .iter()
        .map(|k| match k.kind {
            0 => Key::Number(k.value as i64),
            1 => Key::String(string(k.value)),
            _ => Key::Stack(string(k.value)),
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
    let key = unsafe { keys(raw, len) };
    let linear = state.specs[id as usize].linear;
    let map = &mut state.maps[id as usize];
    if !map.contains_key(&key) && map.len() >= state.max_entries {
        state.fail(format!(
            "map @{} reached the {} entry limit",
            state.specs[id as usize].name, state.max_entries
        ));
        return;
    }
    let cell = map.entry(key).or_default();
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
        5 => cell.total += value as i128,
        6 => {
            let bin = if value < 0 {
                -1
            } else if value == 0 {
                0
            } else {
                64 - (value as u64).leading_zeros() as i32
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
        _ => unreachable!(),
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
    let key = unsafe { keys(raw, len) };
    state.maps[id as usize]
        .get(&key)
        .map(|c| c.number(state.specs[id as usize].aggregate))
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
    } else {
        state.maps[id as usize].clear();
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

pub(crate) unsafe extern "C" fn ustack(
    state: *mut State<'_>,
    event: *const Event<'_>,
    depth: u64,
) -> u64 {
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
        n => format!("[{}, {})", 1u64 << (n - 1), 1u64 << n),
    }
}

pub(crate) unsafe extern "C" fn helper(
    state: *mut State<'_>,
    event: *const Event<'_>,
    op: u64,
    value: u64,
    length: u64,
) -> u64 {
    let state = unsafe { &mut *state };
    let event = unsafe { &*event };
    let result: Result<String> = match op {
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

#[cfg(test)]
mod tests {
    use super::*;
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
