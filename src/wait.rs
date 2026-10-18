//! Polling snapshots of sleeping target threads; these are not scheduler events.
use crate::{Result, language::Probe, perf::UserRegs};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};
#[derive(Clone)]
pub struct Snapshot {
    pub clause: usize,
    pub probe: String,
    pub pid: u32,
    pub tid: u32,
    pub period: u64,
    pub latency: u64,
    pub stack: Arc<Vec<u8>>,
    pub ip: u64,
    pub regs: UserRegs,
    pub number: i64,
    pub args: [u64; 6],
    pub reason: String,
}
pub struct Poller {
    timers: Vec<(usize, String, Duration, Instant, bool)>,
    sleeping: BTreeMap<(usize, String, u32), (Instant, Snapshot)>,
    stack_bytes: usize,
}
impl Poller {
    pub fn new(program: &crate::codegen::Program, stack_bytes: usize, capture_raw: bool) -> Self {
        Self {
            sleeping: BTreeMap::new(),
            stack_bytes: if program.needs_ustack() || capture_raw {
                stack_bytes
            } else {
                0
            },
            timers: program
                .clauses
                .iter()
                .enumerate()
                .flat_map(|(id, c)| {
                    c.probes.iter().filter_map(move |(name, p)| match p {
                        Probe::Wait(period) | Probe::Wakeup(period) => Some((
                            id,
                            name.clone(),
                            *period,
                            Instant::now(),
                            matches!(p, Probe::Wakeup(_)),
                        )),
                        _ => None,
                    })
                })
                .collect(),
        }
    }
    pub fn delay(&self) -> Duration {
        self.timers
            .iter()
            .map(|(_, _, _, next, _)| next.saturating_duration_since(Instant::now()))
            .min()
            .unwrap_or(Duration::from_secs(1))
    }
    pub fn poll(&mut self, targets: impl IntoIterator<Item = i32>) -> Result<Vec<Snapshot>> {
        let now = Instant::now();
        let due: Vec<_> = self
            .timers
            .iter_mut()
            .filter_map(|(id, name, period, next, wakeup)| {
                if now < *next {
                    return None;
                }
                *next = now + *period;
                Some((*id, name.clone(), *period, *wakeup))
            })
            .collect();
        if due.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        let mut tids = BTreeSet::new();
        for pid in targets {
            let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
                continue;
            };
            for entry in tasks.flatten() {
                let Some(tid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<u32>().ok())
                else {
                    continue;
                };
                if !tids.insert(tid) {
                    continue;
                }
                if tids.len() > 4096 {
                    return Err("wait snapshot thread limit (4096) exceeded".into());
                }
                let Ok(status) = std::fs::read_to_string(format!("/proc/{tid}/status")) else {
                    continue;
                };
                let Some(state) = status.lines().find_map(|line| {
                    line.strip_prefix("State:")
                        .and_then(|s| s.split_whitespace().next())
                }) else {
                    continue;
                };
                if state == "R" {
                    for (id, name, _, wakeup) in &due {
                        if *wakeup {
                            if let Some((start, mut snapshot)) =
                                self.sleeping.remove(&(*id, name.clone(), tid))
                            {
                                snapshot.latency =
                                    now.duration_since(start).as_nanos().min(u64::MAX as u128)
                                        as u64;
                                output.push(snapshot);
                            }
                        }
                    }
                }
                if state != "S" && state != "D" {
                    continue;
                }
                let Ok(syscall) = std::fs::read_to_string(format!("/proc/{tid}/syscall")) else {
                    continue;
                };
                let words: Vec<_> = syscall.split_whitespace().collect();
                if words.len() != 9 && words.len() != 3 {
                    continue;
                }
                let number = words[0].parse::<i64>().unwrap_or(-1);
                let parse = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok();
                let Some(sp) = parse(words[words.len() - 2]) else {
                    continue;
                };
                let Some(ip) = parse(words[words.len() - 1]) else {
                    continue;
                };
                if sp == 0 || ip == 0 {
                    continue;
                }
                let args = if words.len() == 9 {
                    std::array::from_fn(|i| parse(words[i + 1]).unwrap_or(0))
                } else {
                    [0; 6]
                };
                let wchan =
                    std::fs::read_to_string(format!("/proc/{tid}/wchan")).unwrap_or_default();
                let wchan = if wchan.trim().is_empty() || wchan.trim() == "0" {
                    "<unavailable>"
                } else {
                    wchan.trim()
                };
                let reason = format!(
                    "state={state} wchan={wchan} syscall={}",
                    crate::syscall::name(number)
                );
                let stack = Arc::new(if self.stack_bytes == 0 {
                    Vec::new()
                } else {
                    crate::memory::read_stack(tid, sp, self.stack_bytes).unwrap_or_default()
                });
                for (clause, probe, period, wakeup) in &due {
                    let snapshot = Snapshot {
                        clause: *clause,
                        probe: probe.clone(),
                        pid: pid as u32,
                        tid,
                        period: period.as_nanos().min(u64::MAX as u128) as u64,
                        latency: 0,
                        stack: stack.clone(),
                        ip,
                        regs: UserRegs {
                            ip,
                            sp,
                            fp: 0,
                            lr: 0,
                            runtime_g: 0,
                        },
                        number,
                        args,
                        reason: reason.clone(),
                    };
                    if *wakeup {
                        let key = (*clause, probe.clone(), tid);
                        if self.sleeping.len() >= 4096 && !self.sleeping.contains_key(&key) {
                            return Err("observed sleeping-thread limit exceeded".into());
                        }
                        self.sleeping.entry(key).or_insert((now, snapshot));
                    } else {
                        output.push(snapshot);
                    }
                    if output.len() > 65536 {
                        return Err("wait snapshot batch limit exceeded".into());
                    }
                }
            }
        }
        self.sleeping.retain(|(_, _, tid), _| tids.contains(tid));
        Ok(output)
    }
}
