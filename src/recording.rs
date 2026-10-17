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
}
#[derive(Serialize, Deserialize)]
pub struct Header {
    pub version: u32,
    pub source: String,
}
#[derive(Serialize, Deserialize)]
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
}
impl Saved {
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
            version: 1,
            source: source.into(),
        })?;
        Ok(out)
    }
    fn line(&mut self, value: &impl Serialize) -> Result<()> {
        let text = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        if text.len() > 1024 * 1024 || self.bytes.saturating_add(text.len()) > 256 * 1024 * 1024 {
            return Err("recording exceeds its 1 MiB event or 256 MiB file limit".into());
        }
        self.writer
            .write_all(&text)
            .and_then(|_| self.writer.write_all(b"\n"))
            .map_err(|e| e.to_string())?;
        self.bytes += text.len() + 1;
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
    if header.version != 1 || header.source.len() > 256 * 1024 {
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
        if event.helpers.len() > 16384
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
