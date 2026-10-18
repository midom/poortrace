//! Explicit cooperative runtime snapshots. Adapters use supported VM diagnostics;
//! no runtime tooling is launched and no code is injected by the tracer.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub pid: u32,
    pub start_ticks: u64,
    pub captured_unix_ms: u64,
    pub runtime: String,
    #[serde(default)]
    pub runtime_version: String,
    pub threads: Vec<Thread>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thread {
    pub tid: Option<u32>,
    pub name: String,
    pub state: String,
    pub frames: Vec<String>,
}
pub struct Reader {
    path: Option<PathBuf>,
    max_age: Duration,
}
impl Default for Reader {
    fn default() -> Self {
        Self {
            path: None,
            max_age: Duration::from_secs(10),
        }
    }
}
pub fn start_ticks(pid: u32) -> Result<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())?;
    text.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .ok_or("invalid process stat identity")?
        .parse()
        .map_err(|_| "invalid process start ticks".into())
}
impl Snapshot {
    pub fn validate(&self, pid: u32, max_age: Duration) -> Result<()> {
        if self.version != 1 {
            return Err("unsupported managed snapshot version".into());
        }
        if self.pid != pid || self.start_ticks != start_ticks(pid)? {
            return Err("managed snapshot process identity does not match the target".into());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis();
        let captured = self.captured_unix_ms as u128;
        if captured > now + 1000 || now.saturating_sub(captured) > max_age.as_millis() {
            return Err("managed snapshot is stale or has a future timestamp".into());
        }
        if !["python", "javascript", "java", "dotnet", "wasm"].contains(&self.runtime.as_str())
            || self.runtime_version.len() > 256
            || self.threads.len() > 2048
        {
            return Err("invalid managed snapshot runtime/thread bounds".into());
        }
        for thread in &self.threads {
            if thread.tid == Some(0)
                || thread.name.len() > 4096
                || thread.state.len() > 1024
                || thread.frames.len() > 127
                || thread.frames.iter().any(|frame| frame.len() > 8192)
            {
                return Err("managed snapshot frame/string bounds exceeded".into());
            }
        }
        Ok(())
    }
}
impl Reader {
    pub fn configure(&mut self, path: PathBuf) -> Result<()> {
        if path.as_os_str().is_empty() {
            return Err("managed snapshot path is empty".into());
        }
        self.path = Some(path);
        Ok(())
    }
    pub fn set_max_age(&mut self, max_age: Duration) -> Result<()> {
        if max_age < Duration::from_millis(1) || max_age > Duration::from_secs(3600) {
            return Err("managed snapshot age must be 1ms..3600s".into());
        }
        self.max_age = max_age;
        Ok(())
    }
    pub fn stack(&mut self, pid: u32, tid: u32, runtime: &str, depth: usize) -> Result<String> {
        let path = self
            .path
            .as_ref()
            .ok_or("configure --managed-snapshot and run an explicit VM adapter")?;
        let file = std::fs::File::open(path).map_err(|e| format!("managed snapshot: {e}"))?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("managed snapshot must be a regular file".into());
        }
        let mut data = Vec::new();
        file.take(1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        if data.len() > 1024 * 1024 {
            return Err("managed snapshot exceeds1MiB".into());
        }
        let snapshot: Snapshot =
            serde_json::from_slice(&data).map_err(|e| format!("invalid managed snapshot: {e}"))?;
        snapshot.validate(pid, self.max_age)?;
        let all = runtime == "all" && tid == 0;
        if runtime == "all" && tid != 0 {
            return Err("process-wide managed snapshots require TID zero".into());
        }
        if !all
            && snapshot.runtime != runtime
            && !(runtime == "async"
                && ["python", "javascript"].contains(&snapshot.runtime.as_str()))
        {
            return Err(format!(
                "snapshot runtime {} does not match requested {runtime}",
                snapshot.runtime
            ));
        }
        let exact = snapshot
            .threads
            .iter()
            .any(|thread| thread.tid == Some(tid));
        let mut output = String::new();
        for thread in &snapshot.threads {
            if !all && (exact && thread.tid != Some(tid) || !exact && thread.tid.is_some()) {
                continue;
            }
            let identity = thread.tid.map_or_else(
                || "process-level; no native TID association".into(),
                |tid| format!("native TID {tid}"),
            );
            output.push_str(&format!(
                "    {} {} [{}; {}; cooperative snapshot]\n",
                snapshot.runtime,
                clean(&thread.name),
                identity,
                clean(&thread.state)
            ));
            for frame in thread.frames.iter().take(depth.min(127)) {
                output.push_str("    ");
                output.push_str(&clean(frame));
                output.push('\n');
            }
            if output.len() > 512 * 1024 {
                let mut end = 512 * 1024;
                while !output.is_char_boundary(end) {
                    end -= 1;
                }
                output.truncate(end);
                output.push_str("\n    <managed output truncated>\n");
                break;
            }
        }
        if output.is_empty() {
            return Err(format!(
                "snapshot contains no frames associated with TID {tid}"
            ));
        }
        Ok(output)
    }
}
fn clean(value: &str) -> String {
    value.replace(['\n', '\r', '\0'], "?")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_process_snapshot_preserves_all_native_thread_identities() {
        let pid = std::process::id();
        let snapshot = Snapshot {
            version: 1,
            pid,
            start_ticks: start_ticks(pid).unwrap(),
            captured_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            runtime: "java".into(),
            runtime_version: "test".into(),
            threads: vec![
                Thread {
                    tid: Some(123),
                    name: "one".into(),
                    state: "sleep".into(),
                    frames: vec!["First.method".into()],
                },
                Thread {
                    tid: Some(456),
                    name: "two".into(),
                    state: "sleep".into(),
                    frames: vec!["Second.method".into()],
                },
            ],
        };
        let path = std::env::temp_dir().join(format!("poortrace-managed-reader-{pid}.json"));
        std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let mut reader = Reader::default();
        reader.configure(path.clone()).unwrap();
        assert!(reader.stack(pid, pid, "java", 8).is_err());
        let first = reader.stack(pid, 123, "java", 8).unwrap();
        assert!(first.contains("First.method"));
        assert!(!first.contains("Second.method"));
        let all = reader.stack(pid, 0, "all", 8).unwrap();
        assert!(all.contains("native TID 123"));
        assert!(all.contains("native TID 456"));
        assert!(all.contains("First.method") && all.contains("Second.method"));
        assert!(reader.stack(pid, 123, "all", 8).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn identities_freshness_and_resource_limits_are_checked() {
        let pid = std::process::id();
        let mut snapshot = Snapshot {
            version: 1,
            pid,
            start_ticks: start_ticks(pid).unwrap(),
            captured_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            runtime: "python".into(),
            runtime_version: String::new(),
            threads: Vec::new(),
        };
        assert!(snapshot.validate(pid, Duration::from_secs(10)).is_ok());
        snapshot.start_ticks += 1;
        assert!(snapshot.validate(pid, Duration::from_secs(10)).is_err());
        snapshot.start_ticks -= 1;
        snapshot.captured_unix_ms = 0;
        assert!(snapshot.validate(pid, Duration::from_secs(10)).is_err());
    }
}
