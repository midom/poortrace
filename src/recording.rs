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
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub endianness: Option<String>,
    #[serde(default)]
    pub capture_mode: Option<String>,
    #[serde(default)]
    pub provenance: Option<crate::report::Provenance>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub address: u64,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
pub enum Metadata {
    Output {
        pid: u64,
        nsecs: u64,
        stream: String,
        bytes: Vec<u8>,
    },
    Exit {
        pid: u64,
        nsecs: u64,
        status: i32,
    },
    RawPerf {
        pid: u64,
        tid: u64,
        cpu: u32,
        nsecs: u64,
        probe: String,
        bytes: Vec<u8>,
        #[serde(default)]
        capture: Option<serde_json::Value>,
    },
    Lost {
        cpu: u32,
        nsecs: u64,
        count: u64,
    },
    Discontinuity {
        cpu: u32,
        nsecs: u64,
        reason: String,
    },
    SchedulerCoverage {
        cpus: Vec<u32>,
        start: u64,
        end: u64,
        complete: bool,
        #[serde(default)]
        clause: Option<usize>,
    },
}
pub struct Recording {
    pub header: Header,
    pub events: Vec<Saved>,
    pub metadata: Vec<Metadata>,
}
/// Architecture-independent register values and bytes captured at event time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawContext {
    pub architecture: String,
    pub registers: [u64; 4],
    #[serde(default)]
    pub runtime_g: u64,
    #[serde(default)]
    pub extra: [u64; 32],
    #[serde(default)]
    pub valid: u64,
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
    pub kernel_stack: Vec<u64>,
    #[serde(default)]
    pub branches: Vec<[u64; 2]>,
    #[serde(default)]
    pub raw: Option<RawContext>,
    #[serde(default)]
    pub trace_fields: crate::kernel::Fields,
    #[serde(default)]
    pub memory: Vec<MemoryRegion>,
    #[serde(default)]
    pub raw_perf: Option<Vec<u8>>,
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
            kernel_stack: Vec::new(),
            branches: Vec::new(),
            raw: None,
            trace_fields: Default::default(),
            memory: Vec::new(),
            raw_perf: None,
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
            extra: r.extra,
            valid: r.valid,
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
            kernel_stack: Vec::new(),
            branches: event
                .branch_records()
                .iter()
                .map(|b| [b.from, b.to])
                .collect(),
            raw: None,
            trace_fields: Default::default(),
            memory: Vec::new(),
            raw_perf: None,
        }
    }
}
pub struct Recorder {
    writer: std::io::BufWriter<std::fs::File>,
    bytes: usize,
}
impl Recorder {
    pub fn create(path: &std::path::Path, source: &str) -> Result<Self> {
        Self::create_with_mode(path, source, None)
    }
    pub fn create_with_mode(
        path: &std::path::Path,
        source: &str,
        capture_mode: Option<&str>,
    ) -> Result<Self> {
        let provenance = capture_mode.map(|mode| crate::report::Provenance {
            capture_mode: mode.into(),
            ..Default::default()
        });
        Self::create_with_provenance(path, source, provenance.as_ref())
    }
    pub fn create_with_provenance(
        path: &std::path::Path,
        source: &str,
        provenance: Option<&crate::report::Provenance>,
    ) -> Result<Self> {
        let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
        let mut out = Self {
            writer: std::io::BufWriter::new(file),
            bytes: 0,
        };
        out.line(&Header {
            version: 3,
            capture_mode: provenance.map(|p| p.capture_mode.clone()),
            provenance: provenance.cloned(),
            source: source.into(),
            architecture: Some(std::env::consts::ARCH.into()),
            endianness: Some(
                if cfg!(target_endian = "little") {
                    "little"
                } else {
                    "big"
                }
                .into(),
            ),
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
    pub fn metadata(&mut self, metadata: &Metadata) -> Result<()> {
        validate_metadata(metadata)?;
        self.line(metadata)
    }
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().map_err(|e| e.to_string())
    }
}
pub fn read(path: &std::path::Path) -> Result<(Header, Vec<Saved>)> {
    let recording = read_full(path)?;
    Ok((recording.header, recording.events))
}
pub fn read_full(path: &std::path::Path) -> Result<Recording> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 256 * 1024 * 1024 {
        return Err("recording exceeds 256 MiB".into());
    }
    read_from(std::io::BufReader::new(file))
}

/// Read an untrusted journal with the same byte/line/schema limits as file replay.
pub fn read_from(mut reader: impl BufRead) -> Result<Recording> {
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
    if ![1, 2, 3].contains(&header.version) || header.source.len() > 256 * 1024 {
        return Err("unsupported recording version or script size".into());
    }
    let mut events = Vec::new();
    let mut metadata = Vec::new();
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
        let value: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| format!("recording record: {e}"))?;
        if value.get("record_type").is_some() {
            let item: Metadata =
                serde_json::from_value(value).map_err(|e| format!("recording metadata: {e}"))?;
            validate_metadata(&item)?;
            metadata.push(item);
            continue;
        }
        let event: Saved =
            serde_json::from_value(value).map_err(|e| format!("recording event: {e}"))?;
        if event.memory.len() > 256
            || event.memory.iter().any(|r| {
                r.bytes.len() > 4096 || r.address.checked_add(r.bytes.len() as u64).is_none()
            })
            || event.memory.iter().map(|r| r.bytes.len()).sum::<usize>() > 256 * 1024
            || event.raw_perf.as_ref().is_some_and(|r| r.len() > 65536)
            || event.kernel_stack.len() > 4096
            || event.stack.len() > 4096
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
    Ok(Recording {
        header,
        events,
        metadata,
    })
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
                if matches!(h.op, 50 | 51 | 52 | 100 | 120 | 150..=153) {
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
                (if event.stack.is_empty() {
                    &event.kernel_stack
                } else {
                    &event.stack
                })
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
        return Err("recording has no captured stack observations; record a script that uses native, kernel, or managed stack helpers".into());
    }
    serde_json::to_string(&serde_json::json!({"$schema":"https://www.speedscope.app/file-format-schema.json","name":"poortrace recorded timeline","shared":{"frames":frames},"profiles":profiles})).map(|s|s+"\n").map_err(|e|e.to_string())
}

/// Combine handler observations of the same captured probe event for a different
/// script. Independent streams with different timestamps remain separate samples.
pub fn coalesce(events: Vec<Saved>) -> Result<Vec<Saved>> {
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
                    if existing.helpers.len() >= 16384 {
                        return Err("coalesced recording helper limit (16384) exceeded".into());
                    }
                    existing.helpers.push(helper);
                }
            }
            if !existing.stack.is_empty()
                && !event.stack.is_empty()
                && existing.stack != event.stack
            {
                return Err("conflicting recorded native stacks for the same observation".into());
            }
            if existing.stack.is_empty() {
                existing.stack = event.stack;
            }
            if !existing.kernel_stack.is_empty()
                && !event.kernel_stack.is_empty()
                && existing.kernel_stack != event.kernel_stack
            {
                return Err("conflicting recorded kernel stacks for the same observation".into());
            }
            if existing.kernel_stack.is_empty() {
                existing.kernel_stack = event.kernel_stack;
            }
            if !existing.branches.is_empty()
                && !event.branches.is_empty()
                && existing.branches != event.branches
            {
                return Err("conflicting recorded branches for the same observation".into());
            }
            if existing.branches.is_empty() {
                existing.branches = event.branches;
            }
            if existing
                .raw
                .as_ref()
                .zip(event.raw.as_ref())
                .is_some_and(|(a, b)| a != b)
            {
                return Err(
                    "conflicting recorded register/stack snapshots for the same observation".into(),
                );
            }
            if existing.raw.is_none() {
                existing.raw = event.raw;
            }
            if event.trace_fields.iter().any(|(name, value)| {
                existing
                    .trace_fields
                    .get(name)
                    .is_some_and(|old| old != value)
            }) {
                return Err(
                    "conflicting recorded tracepoint fields for the same observation".into(),
                );
            }
            existing.trace_fields.append(&mut event.trace_fields);
            if existing.raw_perf.is_none() {
                existing.raw_perf = event.raw_perf;
            }
            for region in event.memory {
                if !existing
                    .memory
                    .iter()
                    .any(|old| old.address == region.address && old.bytes == region.bytes)
                {
                    if existing.memory.len() >= 256
                        || existing.memory.iter().map(|r| r.bytes.len()).sum::<usize>()
                            + region.bytes.len()
                            > 256 * 1024
                    {
                        return Err(
                            "coalesced recording memory exceeds 256 regions or 256 KiB".into()
                        );
                    }
                    existing.memory.push(region);
                }
            }
        } else {
            indices.insert(key, output.len());
            output.push(event);
        }
    }
    Ok(output)
}

fn validate_metadata(item: &Metadata) -> Result<()> {
    let invalid = match item {
        Metadata::Output { stream, bytes, .. } => {
            !matches!(stream.as_str(), "stdout" | "stderr") || bytes.len() > 65536
        }
        Metadata::Exit { status, .. } => !(0..=255).contains(status),
        Metadata::RawPerf { probe, bytes, .. } => {
            probe.len() > 4096 || probe.contains('\0') || bytes.len() > 65536
        }
        Metadata::Lost { .. } => false,
        Metadata::Discontinuity { reason, .. } => reason.len() > 4096 || reason.contains('\0'),
        Metadata::SchedulerCoverage {
            cpus, start, end, ..
        } => {
            cpus.is_empty()
                || cpus.len() > 4096
                || cpus.iter().any(|cpu| *cpu > 1048575)
                || start >= end
                || cpus.iter().collect::<std::collections::BTreeSet<_>>().len() != cpus.len()
        }
    };
    if invalid {
        Err("invalid recording metadata".into())
    } else {
        Ok(())
    }
}
/// Read only bytes captured for this event. Contiguous regions can satisfy a
/// later read, while holes and reads beyond the capture fail explicitly.
pub fn read_memory(
    regions: &[MemoryRegion],
    address: u64,
    length: usize,
    partial: bool,
) -> Result<Vec<u8>> {
    if length == 0 || length > 4096 {
        return Err("captured memory read length must be 1..4096".into());
    }
    address
        .checked_add(length as u64)
        .ok_or("captured memory read overflow")?;
    let mut bytes = Vec::with_capacity(length);
    for offset in 0..length {
        let at = address + offset as u64;
        let mut byte = None;
        for candidate in regions.iter().filter_map(|r| {
            at.checked_sub(r.address)
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| r.bytes.get(offset))
                .copied()
        }) {
            if byte.is_some_and(|previous| previous != candidate) {
                return Err(format!("conflicting captured bytes at address 0x{at:x}"));
            }
            byte = Some(candidate);
        }
        match byte {
            Some(byte) => bytes.push(byte),
            None if partial && !bytes.is_empty() => break,
            None => return Err(format!("address 0x{at:x} was not captured in this event")),
        }
    }
    Ok(bytes)
}

/// Export only execution intervals proven by complete system-wide sched_switch
/// coverage. Boundaries before the first and after the last switch are omitted.
pub fn scheduler_speedscope(recording: &Recording) -> Result<String> {
    use std::collections::{BTreeMap, BTreeSet};
    let coverage: Vec<_> = recording
        .metadata
        .iter()
        .filter_map(|item| match item {
            Metadata::SchedulerCoverage {
                cpus,
                start,
                end,
                complete: true,
                clause,
            } => Some((cpus, *start, *end, *clause)),
            _ => None,
        })
        .collect();
    if coverage.is_empty() {
        return Err(
            "exact scheduler export requires complete recorded system-wide sched_switch coverage"
                .into(),
        );
    }
    let lost: BTreeSet<_> = recording
        .metadata
        .iter()
        .filter_map(|m| match m {
            Metadata::Lost { cpu, count, .. } if *count > 0 => Some(*cpu),
            _ => None,
        })
        .collect();
    let discontinuous: std::collections::BTreeSet<_> = recording
        .metadata
        .iter()
        .filter_map(|m| match m {
            Metadata::Discontinuity { cpu, .. } => Some(*cpu),
            _ => None,
        })
        .collect();
    let throttled: Vec<_> = recording
        .metadata
        .iter()
        .filter_map(|item| {
            let Metadata::RawPerf {
                cpu,
                bytes,
                capture,
                ..
            } = item
            else {
                return None;
            };
            let word: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
            let endian = capture
                .as_ref()
                .and_then(|v| v.get("endianness"))
                .and_then(|v| v.as_str())
                .or(recording.header.endianness.as_deref())
                .unwrap_or("little");
            let kind = if endian == "big" {
                u32::from_be_bytes(word)
            } else {
                u32::from_le_bytes(word)
            };
            matches!(kind, 5 | 6).then(|| {
                (
                    *cpu,
                    capture
                        .as_ref()
                        .and_then(|v| v.get("clause"))
                        .and_then(|v| v.as_u64())
                        .and_then(|v| usize::try_from(v).ok()),
                )
            })
        })
        .collect();
    let mut switches: BTreeMap<(u32, usize), BTreeMap<u64, &Saved>> = BTreeMap::new();
    for event in &recording.events {
        if event.actual_probe() == "tracepoint:sched:sched_switch" {
            let cpu = u32::try_from(event.cpu).map_err(|_| "invalid scheduler CPU ID")?;
            if let Some(old) = switches
                .entry((cpu, event.clause))
                .or_default()
                .insert(event.nsecs, event)
            {
                if old.trace_fields != event.trace_fields {
                    return Err(
                        "conflicting scheduler observations at the same CPU/timestamp".into(),
                    );
                }
            }
        }
    }
    let mut frame_ids = BTreeMap::new();
    let mut frames = Vec::new();
    let mut profiles = Vec::new();
    let integer = |event: &Saved, name: &str| -> Result<u64> {
        match event.trace_fields.get(name) {
            Some(crate::kernel::Value::Integer(value)) if *value <= i32::MAX as u64 => Ok(*value),
            _ => Err(format!("scheduler observation lacks valid {name}")),
        }
    };
    for (cpus, start, end, clause) in coverage {
        for cpu in cpus {
            if discontinuous.contains(cpu) {
                return Err(format!(
                    "scheduler CPU {cpu} has a recorded discontinuity; exact intervals cannot be proven"
                ));
            }
            if lost.contains(cpu) {
                return Err(format!(
                    "scheduler CPU {cpu} has recorded event loss; exact intervals cannot be proven"
                ));
            }
            let selected = clause
                .ok_or("scheduler coverage must identify its authoritative recorded clause")?;
            if throttled.iter().any(|(candidate, stream)| {
                candidate == cpu && stream.is_none_or(|stream| stream == selected)
            }) {
                return Err(format!(
                    "scheduler CPU {cpu} was throttled; exact intervals cannot be proven"
                ));
            }
            let observations: Vec<_> = switches
                .get(&(*cpu, selected))
                .into_iter()
                .flat_map(|events| events.range(start..=end).map(|(_, e)| *e))
                .filter(|event| clause.is_none_or(|clause| event.clause == clause))
                .collect();
            if observations.len() < 2 {
                return Err(format!(
                    "scheduler coverage CPU {cpu} has fewer than two captured switches"
                ));
            }
            let mut events = Vec::new();
            for pair in observations.windows(2) {
                let (a, b) = (pair[0], pair[1]);
                let task = integer(a, "next_pid")?;
                if task != integer(b, "prev_pid")? {
                    return Err(format!(
                        "scheduler CPU {cpu} has an unmatched switch pair; coverage is incomplete"
                    ));
                }
                let comm = match a.trace_fields.get("next_comm") {
                    Some(crate::kernel::Value::String(s)) => s.as_str(),
                    _ => "task",
                };
                let name = format!("{comm} [{task}]");
                let frame = *frame_ids.entry(name.clone()).or_insert_with(|| {
                    let id = frames.len();
                    frames.push(serde_json::json!({"name":name}));
                    id
                });
                events.push(serde_json::json!({"type":"O","at":a.nsecs,"frame":frame}));
                events.push(serde_json::json!({"type":"C","at":b.nsecs,"frame":frame}));
            }
            profiles.push(serde_json::json!({"type":"evented","name":format!("CPU {cpu}: proven switch-to-switch execution"),"unit":"nanoseconds","startValue":observations.first().unwrap().nsecs,"endValue":observations.last().unwrap().nsecs,"events":events}));
        }
    }
    serde_json::to_string(&serde_json::json!({"$schema":"https://www.speedscope.app/file-format-schema.json","name":"poortrace exact scheduler intervals (uncaptured boundaries omitted)","shared":{"frames":frames},"profiles":profiles})).map(|s|s+"\n").map_err(|e|e.to_string())
}

/// Reconstruct archived perf observations without opening tracefs, ELF files, or
/// a current target. Existing handler captures retain their helpers and memory.
pub fn observations_from_raw(recording: &Recording) -> Result<Vec<Saved>> {
    use std::collections::BTreeMap;
    let endianness = if cfg!(target_endian = "little") {
        "little"
    } else {
        "big"
    };
    if recording
        .header
        .architecture
        .as_ref()
        .is_some_and(|a| a != std::env::consts::ARCH)
        || recording
            .header
            .endianness
            .as_ref()
            .is_some_and(|e| e != endianness)
    {
        return Err(
            "raw perf replay requires the native recorded architecture and endianness".into(),
        );
    }
    if recording.events.len() > 2_000_000 {
        return Err("raw replay observation limit (2000000) exceeded".into());
    }
    #[derive(Deserialize)]
    struct Descriptor {
        architecture: String,
        endianness: String,
        layout: crate::perf::Capture,
        #[serde(default)]
        trace_format: Option<crate::kernel::Format>,
        clause: usize,
    }
    type Key = (u64, u64, u64, String);
    let mut observations = recording.events.clone();
    let mut indices: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
    for (i, event) in observations.iter().enumerate() {
        indices
            .entry((event.pid, event.tid, event.nsecs, event.actual_probe()))
            .or_default()
            .push(i);
    }
    let mut comms: BTreeMap<(u32, u32), String> = BTreeMap::new();
    type Stream = (u32, u32, String, usize);
    let mut pending: BTreeMap<Stream, (u64, bool)> = BTreeMap::new();
    let mut raw_count = 0;
    for metadata in &recording.metadata {
        if matches!(metadata,Metadata::Lost{count,..} if *count>0)
            || matches!(metadata, Metadata::Discontinuity { .. })
        {
            pending.clear();
            continue;
        }
        let Metadata::RawPerf {
            probe,
            bytes,
            capture,
            ..
        } = metadata
        else {
            continue;
        };
        raw_count += 1;
        let descriptor: Descriptor = serde_json::from_value(
            capture
                .clone()
                .ok_or("raw perf record lacks its decoding descriptor")?,
        )
        .map_err(|e| format!("raw perf capture descriptor: {e}"))?;
        if descriptor.architecture != std::env::consts::ARCH
            || descriptor.endianness
                != if cfg!(target_endian = "little") {
                    "little"
                } else {
                    "big"
                }
        {
            return Err(
                "raw perf replay requires the native recorded architecture and endianness".into(),
            );
        }

        let sample = match crate::perf::decode_record(bytes, descriptor.layout)? {
            crate::perf::Record::Sample(mut sample) => {
                if let Some(format) = descriptor.trace_format {
                    let trace = sample
                        .trace
                        .as_mut()
                        .ok_or("raw tracepoint observation lacks its payload")?;
                    trace.fields = format.decode(&trace.raw)?;
                } else if descriptor.layout.raw {
                    return Err("raw tracepoint observation lacks its archived format".into());
                }
                sample
            }
            crate::perf::Record::Comm { pid, tid, name } => {
                comms.insert((pid, tid), name);
                continue;
            }
            crate::perf::Record::Lost(_) | crate::perf::Record::Throttle { .. } => {
                pending.clear();
                continue;
            }
            crate::perf::Record::Switch {
                out,
                preempt,
                pid,
                tid,
                cpu,
                time,
            } => {
                let key = (pid, tid, probe.clone(), descriptor.clause);
                if out {
                    pending.insert(key, (time, preempt));
                    continue;
                }
                let Some((start, preempt)) = pending.remove(&key) else {
                    continue;
                };
                if time < start {
                    return Err("raw switch observation timestamps run backwards".into());
                }
                crate::perf::Sample {
                    pid,
                    tid,
                    cpu,
                    time,
                    period: time - start,
                    offcpu_ns: time - start,
                    preempt,
                    ..Default::default()
                }
            }
            crate::perf::Record::Other => continue,
        };
        let mut saved = Saved::lifecycle(probe, sample.pid as u64, sample.tid as u64, sample.time);
        saved.clause = descriptor.clause;
        saved.cpu = sample.cpu as u64;
        saved.ip = sample.ip;
        saved.period = sample.period;
        saved.addr = sample.addr;
        saved.offcpu_ns = sample.offcpu_ns;
        saved.preempt = u64::from(sample.preempt);
        saved.args = sample.args;
        saved.retval = sample.retval;
        saved.stack = sample.callchain;
        saved.kernel_stack = sample.kernel_callchain;
        let misc = u16::from_ne_bytes(bytes[4..6].try_into().unwrap()) & 7;
        if saved.stack.is_empty() {
            if let Some(ip) = sample.regs.map(|r| r.ip).filter(|ip| *ip != 0) {
                saved.stack.push(ip);
            } else if sample.ip != 0 && (!descriptor.layout.kernel || misc == 2) {
                saved.stack.push(sample.ip);
            }
        }
        if saved.kernel_stack.is_empty()
            && descriptor.layout.kernel_callchain
            && misc == 1
            && sample.ip != 0
        {
            saved.kernel_stack.push(sample.ip);
        }
        saved.branches = sample
            .branches
            .into_iter()
            .map(|b| [b.from, b.to])
            .collect();
        saved.trace_fields = sample.trace.map(|t| t.fields).unwrap_or_default();
        saved.raw = sample.regs.map(|r| RawContext {
            architecture: descriptor.architecture,
            registers: [r.ip, r.sp, r.fp, r.lr],
            runtime_g: r.runtime_g,
            extra: r.extra,
            valid: r.valid,
            stack_bytes: sample.stack,
        });
        if let Some(comm) = comms.get(&(sample.pid, sample.tid)) {
            saved.comm = comm.clone();
        }
        saved.raw_perf = Some(bytes.clone());
        let key = (saved.pid, saved.tid, saved.nsecs, saved.actual_probe());
        if let Some(matches) = indices.get(&key) {
            for &index in matches {
                let existing = &mut observations[index];
                existing.cpu = saved.cpu;
                existing.ip = saved.ip;
                existing.period = saved.period;
                existing.addr = saved.addr;
                existing.offcpu_ns = saved.offcpu_ns;
                existing.preempt = saved.preempt;
                existing.args = saved.args;
                existing.retval = saved.retval;
                if existing.stack.is_empty() {
                    existing.stack = saved.stack.clone();
                }
                if existing.kernel_stack.is_empty() {
                    existing.kernel_stack = saved.kernel_stack.clone();
                }
                if existing.branches.is_empty() {
                    existing.branches = saved.branches.clone();
                }
                if existing.raw.is_none() {
                    existing.raw = saved.raw.clone();
                }
                if existing.trace_fields.is_empty() {
                    existing.trace_fields = saved.trace_fields.clone();
                }
                if existing.raw_perf.is_none() {
                    existing.raw_perf = saved.raw_perf.clone();
                }
            }
        } else {
            if observations.len() >= 2_000_000 {
                return Err("raw replay observation limit (2000000) exceeded".into());
            }
            indices.entry(key).or_default().push(observations.len());
            observations.push(saved);
        }
    }
    if raw_count == 0 {
        return Err("recording has no archived raw perf records".into());
    }
    Ok(observations)
}
