//! Grouped counter collection and statistics output.

use super::{
    cli::Args,
    process::{
        Child, INTERRUPTED, alive, command_for, install_signals, kill_owned_descendants, threads,
        track_owned_descendants,
    },
};
use poortrace::Result;
use std::{
    collections::BTreeSet,
    io,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub(super) fn run_stat(args: &Args) -> Result<i32> {
    if !matches!(args.output_format.as_str(), "text" | "json")
        || args.compare.is_some()
        || args.window.is_some()
        || args.live.is_some()
        || !args.quantiles.is_empty()
        || args.percent
        || args.rate
    {
        return Err("--stat supports final text or JSON counter reports".into());
    }
    install_signals()?;
    let command = command_for(args);
    let mut child = if command.is_empty() {
        None
    } else {
        Some(Child::spawn(
            &command,
            args.follow_forks,
            args.record_output,
        )?)
    };
    let pid = child
        .as_ref()
        .map(|c| c.pid)
        .or(args.pid)
        .or(args.system_wide.then_some(-1))
        .ok_or("--stat requires -p PID, a command, or --system-wide")?;
    let open_group = |id: i32, on_exec: bool| {
        if args.system_wide {
            poortrace::counters::Group::open_on_cpu(id, &args.stat_events, args.include_kernel)
        } else {
            poortrace::counters::Group::open_with_kernel(
                id,
                &args.stat_events,
                on_exec,
                args.include_kernel,
            )
        }
    };
    let mut monitor = if !args.system_wide && (args.follow_forks || args.track_threads) {
        let mut monitor = poortrace::syscall::Tracer::seize_tree(
            pid,
            threads(pid)?,
            child.is_some(),
            args.attach_descendants,
        )?;
        monitor.follow_forks(args.follow_forks);
        monitor.trace_syscalls(false);
        Some(monitor)
    } else {
        None
    };
    let mut groups = std::collections::BTreeMap::new();
    let initial_targets = monitor
        .as_ref()
        .map(|monitor| monitor.targets())
        .unwrap_or_else(|| BTreeSet::from([pid]));
    let initial_tids: BTreeSet<_> = if args.system_wide {
        poortrace::kernel::online_cpus()?.into_iter().collect()
    } else {
        initial_targets
            .into_iter()
            .flat_map(|pid| threads(pid).unwrap_or_default())
            .collect()
    };
    for tid in initial_tids {
        groups.insert(tid, open_group(tid, child.is_some())?);
    }
    for group in groups.values() {
        if child.is_none() {
            group.enable()?;
        }
    }
    if let Some(child) = &mut child {
        child.start()?;
    }
    let start = Instant::now();
    let mut refresh = Instant::now();
    let mut readings = Vec::new();
    loop {
        let done = if let Some(monitor) = &mut monitor {
            monitor.poll()?;
            track_owned_descendants(&mut child, args.follow_forks, monitor.targets())?;
            for tid in monitor.take_discovered() {
                if let std::collections::btree_map::Entry::Vacant(entry) = groups.entry(tid) {
                    let group = open_group(tid, false)?;
                    group.enable()?;
                    entry.insert(group);
                }
                monitor.resume(tid)?;
            }
            if let Some(child) = &mut child {
                if let Some(code) = (!monitor.targets().contains(&child.pid))
                    .then(|| monitor.exits.remove(&child.pid))
                    .flatten()
                {
                    child.status = Some(code);
                    if !args.follow_forks {
                        unsafe {
                            libc::kill(-child.pid, libc::SIGKILL);
                        }
                    }
                }
            }
            monitor.is_empty()
                || !args.follow_forks && child.as_ref().is_some_and(|child| child.status.is_some())
        } else if let Some(child) = &mut child {
            child.check()?.is_some()
        } else {
            !args.system_wide && !alive(pid)
        };
        if done
            || INTERRUPTED.load(Ordering::Relaxed)
            || args.duration.is_some_and(|d| start.elapsed() >= d)
        {
            break;
        }
        if refresh.elapsed() >= Duration::from_millis(100) {
            let targets = monitor
                .as_ref()
                .map(|monitor| monitor.targets())
                .unwrap_or_else(|| BTreeSet::from([pid]));
            let tids: BTreeSet<_> = if args.system_wide {
                poortrace::kernel::online_cpus()?.into_iter().collect()
            } else {
                targets
                    .into_iter()
                    .flat_map(|target| threads(target).unwrap_or_default())
                    .collect()
            };
            let dead: Vec<_> = groups
                .keys()
                .filter(|tid| !tids.contains(tid))
                .copied()
                .collect();
            for tid in dead {
                let group = groups.remove(&tid).unwrap();
                group.disable()?;
                readings.extend(group.read()?);
            }
            for tid in tids {
                if let std::collections::btree_map::Entry::Vacant(entry) = groups.entry(tid) {
                    match open_group(tid, false) {
                        Ok(group) => {
                            group.enable()?;
                            entry.insert(group);
                        }
                        Err(_)
                            if !args.system_wide
                                && !std::path::Path::new(&format!("/proc/{tid}")).exists() => {}
                        Err(_)
                            if args.system_wide
                                && !poortrace::kernel::online_cpus()?.contains(&tid) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            refresh = Instant::now();
        }
        unsafe {
            libc::poll(
                std::ptr::null_mut(),
                0,
                if monitor.is_some() { 1 } else { 20 },
            );
        }
    }
    if let Some(monitor) = &mut monitor {
        kill_owned_descendants(child.as_ref(), args.follow_forks, monitor.targets());
        monitor.detach();
        if let Some(child) = &mut child {
            if let Some(code) = (!monitor.targets().contains(&child.pid))
                .then(|| monitor.exits.remove(&child.pid))
                .flatten()
            {
                child.status = Some(code);
            }
        }
    }
    for group in groups.values() {
        group.disable()?;
        readings.extend(group.read()?);
    }
    let mut totals = std::collections::BTreeMap::<String, (u128, u128, u128, Option<f64>)>::new();
    for reading in readings {
        let total = totals.entry(reading.event).or_insert((0, 0, 0, Some(0.0)));
        total.0 += reading.raw as u128;
        total.1 += reading.enabled_ns as u128;
        total.2 += reading.running_ns as u128;
        total.3 = total.3.zip(reading.scaled).map(|(a, b)| a + b);
    }
    let rows:Vec<_>=totals.iter().map(|(event,(raw,enabled,running,scaled))|serde_json::json!({"event":event,"raw":raw,"enabled_ns":enabled,"running_ns":running,"scaled":scaled})).collect();
    let mut provenance = super::report::provenance(args, args.stat_events.clone(), "stat");
    provenance.capture_mode = "grouped-counters".into();
    provenance.elapsed_seconds = start.elapsed().as_secs_f64();
    provenance.lost_samples = None;
    provenance.discontinuities = None;
    super::report::write_metadata(args, &provenance)?;
    let text = if args.output_format == "json" {
        poortrace::report::json_document(&rows, Some(&provenance), provenance.elapsed_seconds)?
    } else {
        let mut out = String::new();
        for (event, (raw, enabled, running, scaled)) in &totals {
            out.push_str(&format!(
                "{event}: raw={raw} scaled={} running={running}/{enabled} ns\n",
                scaled
                    .map(|v| format!("{v:.3}"))
                    .unwrap_or_else(|| "unavailable".into())
            ));
        }
        if let (Some(cycles), Some(instructions)) = (
            totals
                .get("hardware:cycles")
                .or_else(|| totals.get("hardware:cpu-cycles")),
            totals.get("hardware:instructions"),
        ) {
            if let (Some(cycles), Some(instructions)) = (cycles.3, instructions.3) {
                if cycles > 0.0 {
                    out.push_str(&format!("IPC: {:.4}\n", instructions / cycles));
                }
            }
        }
        out
    };
    if let Some(path) = &args.output {
        std::fs::write(path, text).map_err(|e| e.to_string())?;
    } else {
        use std::io::Write;
        io::stdout()
            .write_all(text.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    Ok(child
        .as_ref()
        .filter(|child| !child.terminated_by_tracer)
        .and_then(|child| child.status)
        .unwrap_or(0))
}
