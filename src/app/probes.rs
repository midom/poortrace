//! Resolve explicit ELF globs and process-scoped selectors before attaching a backend.
use super::cli::Args;
use poortrace::{Result, codegen::Program, discovery, language::Probe, uprobe};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn expand(program: &mut Program, args: &Args) -> Result<()> {
    let mut discovered = BTreeMap::new();
    let mut total = 0usize;
    for clause in &mut program.clauses {
        let mut expanded = Vec::new();
        let mut seen = BTreeSet::new();
        for (name, probe) in &clause.probes {
            let Probe::Uprobe {
                path,
                function,
                ret,
            } = probe
            else {
                push(
                    &mut expanded,
                    &mut total,
                    args.max_probes,
                    (name.clone(), probe.clone()),
                )?;
                continue;
            };
            if path.is_empty() || path.contains(['*', '?']) {
                let pid=args.pid.ok_or("process-scoped function selectors and image wildcards require -p PID; use uprobe:PATH:FUNCTION when launching a command")?;
                if function.starts_with("__usdt__") {
                    return Err(
                        "USDT image wildcards are not supported; select a concrete image".into(),
                    );
                }
                if !discovered.contains_key(function) {
                    let listing = discovery::process_functions(pid, function)?;
                    for warning in &listing.warnings {
                        eprintln!("poortrace: {warning}");
                    }
                    discovered.insert(function.clone(), listing);
                }
                let matches = &discovered[function].functions;
                let mut matched = false;
                for found in matches {
                    if !path.is_empty()
                        && !uprobe::matches(path, &found.path)
                        && !(!path.contains('/')
                            && std::path::Path::new(&found.path)
                                .file_name()
                                .and_then(|p| p.to_str())
                                .is_some_and(|base| uprobe::matches(path, base)))
                    {
                        continue;
                    }
                    matched = true;
                    if seen.insert((found.path.clone(), found.offset, *ret)) {
                        push(
                            &mut expanded,
                            &mut total,
                            args.max_probes,
                            (
                                discovery::function_probe_name(&found.path, &found.name, *ret)?,
                                Probe::Uprobe {
                                    path: found.path.clone(),
                                    function: format!("0x{:x}", found.offset),
                                    ret: *ret,
                                },
                            ),
                        )?;
                    }
                }
                if !matched {
                    return Err(format!(
                        "function pattern {function:?} matched no symbols in {} for PID {pid}",
                        if path.is_empty() {
                            "mapped images"
                        } else {
                            path
                        }
                    ));
                }
            } else if let Some(selector) = function.strip_prefix("__usdt__") {
                if args.uprobe_backend != "ptrace" {
                    return Err("SDT probes require --uprobe-backend ptrace".into());
                }
                let (provider, marker) = selector
                    .split_once(':')
                    .ok_or("SDT requires PROVIDER:NAME")?;
                let mut matched = false;
                for site in
                    poortrace::usdt::sites(args.pid.unwrap_or(std::process::id() as i32), path)?
                {
                    if uprobe::matches(provider, &site.provider)
                        && uprobe::matches(marker, &site.name)
                    {
                        matched = true;
                        push(
                            &mut expanded,
                            &mut total,
                            args.max_probes,
                            (
                                format!("usdt:{path}:{}:{}", site.provider, site.name),
                                Probe::Uprobe {
                                    path: path.clone(),
                                    function: format!(
                                        "__sdt__{}",
                                        serde_json::to_string(&site).map_err(|e| e.to_string())?
                                    ),
                                    ret: false,
                                },
                            ),
                        )?;
                    }
                }
                if !matched {
                    return Err(format!("no SDT probes matched {selector} in {path}"));
                }
            } else if function.contains(['*', '?']) {
                let matches = uprobe::functions(
                    args.pid.unwrap_or(std::process::id() as i32),
                    path,
                    function,
                )?;
                if matches.is_empty() {
                    return Err(format!(
                        "function pattern {function:?} matched no symbols in {path}"
                    ));
                }
                for found in matches {
                    if seen.insert((path.clone(), found.offset, *ret)) {
                        push(
                            &mut expanded,
                            &mut total,
                            args.max_probes,
                            (
                                discovery::function_probe_name(path, &found.name, *ret)?,
                                Probe::Uprobe {
                                    path: path.clone(),
                                    function: format!("0x{:x}", found.offset),
                                    ret: *ret,
                                },
                            ),
                        )?;
                    }
                }
            } else {
                push(
                    &mut expanded,
                    &mut total,
                    args.max_probes,
                    (name.clone(), probe.clone()),
                )?;
            }
        }
        clause.probes = expanded;
    }
    Ok(())
}

fn push(
    expanded: &mut Vec<(String, Probe)>,
    total: &mut usize,
    limit: Option<usize>,
    probe: (String, Probe),
) -> Result<()> {
    if let Some(limit) = limit.filter(|limit| *limit != 0) {
        if *total >= limit {
            return Err(format!(
                "expanded probe limit ({limit}) exceeded (--max-probes); narrow the pattern or raise the limit"
            ));
        }
    }
    *total = total.checked_add(1).ok_or("probe count overflow")?;
    expanded.push(probe);
    Ok(())
}
