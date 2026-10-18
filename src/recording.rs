//! Versioned handler-event recordings with captured helper results for offline replay.
use crate::{Result, runtime::Event};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CStr,
    io::{BufRead, Write},
};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Helper {
    pub op: u64,
    pub value: u64,
    pub length: u64,
    pub number: u64,
    pub text: Option<String>,
    pub error: Option<String>,
    #[serde(default)]
    pub descriptor: Option<String>,
}
#[derive(Serialize, Deserialize)]
pub struct Header {
    pub version: u32,
    pub source: String,
}
/// Architecture-independent register values and bytes captured at event time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawContext {
    pub architecture: String,
    pub registers: [u64; 4],
    #[serde(default)]
    pub runtime_g: u64,
    pub stack_bytes: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Saved {
    pub clause: usize,
    pub stopped: bool,
    pub pid: u64,
    pub tid: u64,
    pub cpu: u64,
    pub nsecs: u64,
    pub ip: u64,
    pub period: u64,
    pub comm: String,
    pub probe: String,
    pub syscall: String,
    pub addr: u64,
    pub offcpu_ns: u64,
    pub preempt: u64,
    pub sysno: u64,
    pub retval: i64,
    pub latency: u64,
    pub args: [u64; 6],
    pub helpers: Vec<Helper>,
    #[serde(default)]
    pub stack: Vec<u64>,
    #[serde(default)]
    pub branches: Vec<[u64; 2]>,
    #[serde(default)]
    pub raw: Option<RawContext>,
    #[serde(default)]
    pub trace_fields: crate::kernel::Fields,
}
impl Saved {
    /// Synthetic offline lifecycle observation for alternate-script BEGIN/END.
    pub fn lifecycle(probe: &str, pid: u64, tid: u64, nsecs: u64) -> Self {
        Self {
            clause: 0,
            stopped: false,
            pid,
            tid,
            cpu: 0,
            nsecs,
            ip: 0,
            period: 0,
            comm: "replay".into(),
            probe: probe.into(),
            syscall: String::new(),
            addr: 0,
            offcpu_ns: 0,
            preempt: 0,
            sysno: 0,
            retval: 0,
            latency: 0,
            args: [0; 6],
            helpers: Vec::new(),
            stack: Vec::new(),
            branches: Vec::new(),
            raw: None,
            trace_fields: Default::default(),
        }
    }
    /// Resolve syscall wildcard selectors to the name observed at the stop.
    pub fn actual_probe(&self) -> String {
        for prefix in ["syscall:enter:", "syscall:exit:"] {
            if self.probe.starts_with(prefix) && !self.syscall.is_empty() {
                return format!("{prefix}{}", self.syscall);
            }
        }
        self.probe.clone()
    }
    pub(crate) fn capture_raw(&mut self, snapshot: Option<&(crate::perf::UserRegs, Vec<u8>)>) {
        self.raw = snapshot.map(|(r, bytes)| RawContext {
            architecture: std::env::consts::ARCH.into(),
            registers: [r.ip, r.sp, r.fp, r.lr],
            runtime_g: r.runtime_g,
            stack_bytes: bytes.clone(),
        });
    }
    pub(crate) fn capture(clause: usize, stopped: bool, event: &Event<'_>) -> Self {
        let string = |p| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        Self {
            clause,
            stopped,
            pid: event.pid,
            tid: event.tid,
            cpu: event.cpu,
            nsecs: event.nsecs,
            ip: event.ip,
            period: event.period,
            comm: string(event.comm),
            probe: string(event.probe),
            syscall: string(event.syscall),
            addr: event.addr,
            offcpu_ns: event.offcpu_ns,
            preempt: event.preempt,
            sysno: event.sysno,
            retval: event.retval,
            latency: event.latency,
            args: event.args,
            helpers: Vec::new(),
            stack: event.stack_frames().to_vec(),
            branches: event
                .branch_records()
                .iter()
                .map(|b| [b.from, b.to])
                .collect(),
            raw: None,
            trace_fields: Default::default(),
        }
    }
}
pub struct Recorder {
    writer: std::io::BufWriter<std::fs::File>,
    bytes: usize,
}
impl Recorder {
    pub fn create(path: &std::path::Path, source: &str) -> Result<Self> {
        let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
        let mut out = Self {
            writer: std::io::BufWriter::new(file),
            bytes: 0,
        };
        out.line(&Header {
            version: 2,
            source: source.into(),
        })?;
        Ok(out)
    }
    fn line(&mut self, value: &impl Serialize) -> Result<()> {
        let text = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        let line_bytes = text.len().saturating_add(1);
        if line_bytes > 1024 * 1024 || self.bytes.saturating_add(line_bytes) > 256 * 1024 * 1024 {
            return Err("recording exceeds its 1 MiB event or 256 MiB file limit".into());
        }
        self.writer
            .write_all(&text)
            .and_then(|_| self.writer.write_all(b"\n"))
            .map_err(|e| e.to_string())?;
        self.bytes += line_bytes;
        Ok(())
    }
    pub(crate) fn event(&mut self, event: &Saved) -> Result<()> {
        self.line(event)
    }
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().map_err(|e| e.to_string())
    }
}
pub fn read(path: &std::path::Path) -> Result<(Header, Vec<Saved>)> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 256 * 1024 * 1024 {
        return Err("recording exceeds 256 MiB".into());
    }
    let mut reader = std::io::BufReader::new(file);
    let mut line = String::new();
    fn next(reader: &mut impl BufRead, line: &mut String) -> Result<usize> {
        use std::io::Read;
        line.clear();
        let n = reader
            .take(1024 * 1024 + 1)
            .read_line(line)
            .map_err(|e| e.to_string())?;
        if n > 1024 * 1024 {
            return Err("recording line exceeds 1 MiB".into());
        }
        Ok(n)
    }
    next(&mut reader, &mut line)?;
    let header: Header =
        serde_json::from_str(&line).map_err(|e| format!("recording header: {e}"))?;
    if ![1, 2].contains(&header.version) || header.source.len() > 256 * 1024 {
        return Err("unsupported recording version or script size".into());
    }
    let mut events = Vec::new();
    let mut total = line.len();
    loop {
        let n = next(&mut reader, &mut line)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n);
        if total > 256 * 1024 * 1024 {
            return Err("recording exceeds 256 MiB".into());
        }
        let event: Saved =
            serde_json::from_str(&line).map_err(|e| format!("recording event: {e}"))?;
        if event.stack.len() > 4096
            || event.branches.len() > 4096
            || event.raw.as_ref().is_some_and(|r| {
                r.stack_bytes.len() > 32768
                    || !matches!(r.architecture.as_str(), "x86_64" | "aarch64")
            })
            || event.helpers.len() > 16384
            || [&event.comm, &event.probe, &event.syscall]
                .iter()
                .any(|s| s.contains('\0'))
        {
            return Err("invalid recording event".into());
        }
        events.push(event);
    }
    Ok((header, events))
}

/// Render recorded stack observations in timestamp order, independently per thread.
/// Captured helper strings preserve symbols after the target and its ELF files disappear.
pub fn timeline_speedscope(events: &[Saved]) -> Result<String> {
    use std::collections::{BTreeMap, BTreeSet};
    type Observations = Vec<(u64, Vec<String>)>;
    let mut threads: BTreeMap<(u64, u64), Observations> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for event in events {
        let stack = event
            .helpers
            .iter()
            .find_map(|h| {
                if matches!(h.op, 50 | 51 | 52 | 100) {
                    h.text.as_ref().map(|text| {
                        text.lines()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .rev()
                            .map(String::from)
                            .collect::<Vec<_>>()
                    })
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                event
                    .stack
                    .iter()
                    .rev()
                    .map(|ip| format!("0x{ip:x}"))
                    .collect()
            });
        if !stack.is_empty() && seen.insert((event.pid, event.tid, event.nsecs, stack.clone())) {
            threads
                .entry((event.pid, event.tid))
                .or_default()
                .push((event.nsecs, stack));
        }
    }
    let mut ids = BTreeMap::new();
    let mut frames = Vec::new();
    let mut profiles = Vec::new();
    for ((pid, tid), mut observations) in threads {
        observations.sort_by_key(|(time, _)| *time);
        let start = observations[0].0;
        let end = observations.last().unwrap().0.saturating_add(1);
        let mut samples = Vec::new();
        let mut weights = Vec::new();
        for (i, (time, stack)) in observations.iter().enumerate() {
            let sample: Vec<usize> = stack
                .iter()
                .map(|name| {
                    *ids.entry(name.clone()).or_insert_with(|| {
                        let id = frames.len();
                        frames.push(serde_json::json!({"name":name}));
                        id
                    })
                })
                .collect();
            samples.push(sample);
            weights.push(
                observations
                    .get(i + 1)
                    .map_or(end, |(time, _)| *time)
                    .saturating_sub(*time),
            );
        }
        profiles.push(serde_json::json!({"type":"sampled", "name":format!("PID {pid} / TID {tid}"), "unit":"nanoseconds", "startValue":start,"endValue":end,"samples":samples,"weights":weights}));
    }
    if profiles.is_empty() {
        return Err("recording has no captured stack observations; record a script that uses ustack, pystack, jsstack, or gostack".into());
    }
    serde_json::to_string(&serde_json::json!({"$schema":"https://www.speedscope.app/file-format-schema.json","name":"poortrace recorded timeline","shared":{"frames":frames},"profiles":profiles})).map(|s|s+"\n").map_err(|e|e.to_string())
}

/// Combine handler observations of the same captured probe event for a different
/// script. Independent streams with different timestamps remain separate samples.
pub fn coalesce(events: Vec<Saved>) -> Vec<Saved> {
    use std::collections::BTreeMap;
    let mut indices: BTreeMap<(u64, u64, u64, String), usize> = BTreeMap::new();
    let mut output: Vec<Saved> = Vec::new();
    for mut event in events {
        let key = (event.pid, event.tid, event.nsecs, event.actual_probe());
        if let Some(index) = indices.get(&key).copied() {
            let existing: &mut Saved = &mut output[index];
            // Pure lookups are keyed by inputs and descriptors. Keep distinct
            // values too: a handler can issue repeated reads while a target runs.
            for helper in event.helpers {
                if !existing.helpers.iter().any(|old| {
                    old.op == helper.op
                        && old.value == helper.value
                        && old.length == helper.length
                        && old.descriptor == helper.descriptor
                        && old.number == helper.number
                        && old.text == helper.text
                        && old.error == helper.error
                }) {
                    existing.helpers.push(helper);
                }
            }
            if existing.stack.is_empty() {
                existing.stack = event.stack;
            }
            if existing.branches.is_empty() {
                existing.branches = event.branches;
            }
            if existing.raw.is_none() {
                existing.raw = event.raw;
            }
            existing.trace_fields.append(&mut event.trace_fields);
        } else {
            indices.insert(key, output.len());
            output.push(event);
        }
    }
    output
}
