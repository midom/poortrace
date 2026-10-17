use poortrace::{codegen::Program, runtime::Event};

fn execute(source: &str, periods: &[u64]) -> String {
    let program = Program::compile(source).unwrap();
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        let mut event = Event::new(c"worker", c"synthetic");
        event.pid = 42;
        event.tid = 43;
        event.cpu = 3;
        event.nsecs = 1_000_000;
        event.ip = 0xfeed;
        for period in periods {
            event.period = *period;
            program.invoke(0, &mut state, &event);
        }
        for clause in 1..program.clauses.len() {
            state.stopped = false;
            program.invoke(clause, &mut state, &event);
        }
        state.print_all();
        state.flush().unwrap();
    }
    String::from_utf8(output).unwrap()
}

#[test]
fn native_jit_expressions_control_flow_and_locals() {
    let out = execute(
        r#"
        BEGIN {
            $x = 3 + 4 * 5;
            $x += 2;
            $x--;
            if ($x == 24 && comm == "worker") {
                printf("%s %d %x %d %d\n", probe, $x, ip, pid, tid);
            } else { printf("wrong\n"); }
            printf("%d %d %d %d\n", !0, ~0, -5 >> 1, 2 << 65);
        }
    "#,
        &[0],
    );
    assert_eq!(out, "synthetic 24 feed 42 43\n1 -1 -3 4\n");
}

#[test]
fn keyed_aggregations_and_end_access() {
    let out = execute(
        r#"
        profile:hz:99 / pid == 42 && period / 2 >= 0 / {
            @[comm, tid] = count();
            @total = sum(period); @min = min(period); @max = max(period);
            @average = avg(period); @distribution = hist(period);
        }
        END { printf("total=%d avg=%d\n", @total, @average); }
    "#,
        &[0, 3, 7],
    );
    assert!(out.contains("total=10 avg=3\n"));
    assert!(out.contains("@[\"worker\", 43]: 3\n"));
    assert!(out.contains("@min: 0\n"));
    assert!(out.contains("@max: 7\n"));
    assert!(out.contains("[0, 1): 1\n"));
    assert!(out.contains("[2, 4): 1\n"));
    assert!(out.contains("[4, 8): 1\n"));
}

#[test]
fn scalar_maps_increment_print_and_clear() {
    let out = execute(
        r#"
        BEGIN { @x++; @x += 3; @x--; @by_cpu[cpu] = @x; print(@by_cpu); clear(@by_cpu); }
        END { printf("%d %d\n", @x, @by_cpu[3]); clear(@x); }
    "#,
        &[0, 0],
    );
    assert_eq!(out, "@by_cpu[3]: 3\n@by_cpu[3]: 6\n6 0\n");
}

#[test]
fn arithmetic_edges_never_trap_or_poison() {
    let out = execute(
        r#"BEGIN {
        printf("%d %d %d %d %d\n", 17/0, 17%0,
            0x8000000000000000 / -1, 0x8000000000000000 % -1,
            0x7fffffffffffffff + 1);
        printf("%d %d %d\n", 0 || (1 && 5), 1 && (0 || 3), "a" != "b");
    }"#,
        &[0],
    );
    assert_eq!(
        out,
        "0 0 -9223372036854775808 0 -9223372036854775808\n1 1 1\n"
    );
}

#[test]
fn format_is_type_checked_and_rendered_without_c_varargs() {
    let out = execute(
        r#"BEGIN { printf("[%05d][%-6s][%04x][%llu][%%]\n", -3, "λ", 255, -1); }"#,
        &[0],
    );
    assert_eq!(out, "[-0003][λ     ][00ff][18446744073709551615][%]\n");
    for source in [
        r#"BEGIN { printf("%s", 123); }"#,
        r#"BEGIN { printf("%d", "bad"); }"#,
        r#"BEGIN { printf("%d %d", 1); }"#,
        r#"BEGIN { printf("%n", 1); }"#,
        r#"BEGIN { printf("%99999999d", 1); }"#,
    ] {
        assert!(Program::compile(source).is_err(), "{source}");
    }
}

#[test]
fn exit_immediately_skips_following_statements_and_end_can_run() {
    let out = execute(
        r#"BEGIN { printf("start\n"); if (1) { exit(); printf("bad\n"); } printf("bad\n"); } END { printf("end\n"); }"#,
        &[0],
    );
    assert_eq!(out, "start\nend\n");
}

#[test]
fn malformed_and_inconsistent_scripts_are_rejected() {
    for source in [
        "",
        "BEGIN {",
        "BEGIN { @x = ; }",
        "BEGIN { 1 = 2; }",
        "BEGIN { @x = sum(); }",
        "BEGIN { @x = count(1); }",
        "BEGIN { @x = count(); @x = sum(1); }",
        "BEGIN { @x[comm]++; @x[pid]++; }",
        "BEGIN { @x[1]++; printf(\"%d\", @x); }",
        "BEGIN { @x = hist(1); @y = @x; }",
        "BEGIN { $x = comm; }",
        "BEGIN { printf(\"%d\", missing); }",
        "BEGIN { printf(\"%d\", $missing); }",
        "kprobe:do_sys_open { @x++; }",
        "profile:hz:0 { @x++; }",
        "BEGIN { /* unterminated",
        "BEGIN { printf(\"bad\\q\"); }",
    ] {
        assert!(
            Program::compile(source).is_err(),
            "unexpectedly accepted {source:?}"
        );
    }
    assert!(
        Program::compile("BEGIN {\n @x = ;\n}")
            .err()
            .unwrap()
            .contains("2:")
    );
}

#[test]
fn map_capacity_is_an_observable_runtime_error() {
    let program = Program::compile("BEGIN { @x[period]++; printf(\"after\"); }").unwrap();
    let mut output = Vec::new();
    let mut state = program.state(&mut output);
    state.max_entries = 1;
    let mut event = Event::new(c"test", c"BEGIN");
    program.invoke(0, &mut state, &event);
    event.period = 1;
    program.invoke(0, &mut state, &event);
    assert!(state.stopped);
    assert!(state.flush().unwrap_err().contains("entry limit"));
    drop(state);
    assert_eq!(output, b"after");
}

#[test]
fn io_errors_do_not_unwind_through_jit_frames() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let p = Program::compile(r#"BEGIN { printf("first"); @x++; }"#).unwrap();
    let mut state = p.state(Broken);
    p.invoke(0, &mut state, &Event::new(c"test", c"BEGIN"));
    assert!(state.stopped);
    assert!(state.flush().unwrap_err().contains("output:"));
}

#[test]
fn multiple_probe_specs_share_one_native_handler() {
    let p = Program::compile("BEGIN, END { @x++; }").unwrap();
    assert_eq!(p.clauses[0].probes.len(), 2);
    assert!(p.ir.contains("define void @probe_0"));
}

#[test]
fn user_stacks_are_typed_keys_and_strings_live_through_the_handler() {
    let program = Program::compile(
        r#"profile:hz:99 {
        @stacks[comm, ustack] = count();
        @short[ustack(1)] = count();
        if (ustack == ustack()) { @equal++; }
        printf("%s|%s", ustack(1), ustack(2));
    }"#,
    )
    .unwrap();
    assert!(program.needs_ustack());
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        let mut frames = vec![0x1234, 0x5678];
        for _ in 0..2 {
            let event = Event::new(c"test", c"synthetic").with_ustack(&frames);
            program.invoke(0, &mut state, &event);
        }
        // Map keys own the stack after the Event and its backing frames disappear.
        frames.clear();
        state.print_all();
        state.flush().unwrap();
    }
    let text = String::from_utf8(output).unwrap();
    assert!(
        text.contains("    0x1234\n|    0x1234\n    0x5678\n"),
        "{text}"
    );
    assert!(
        text.contains("@stacks[\"test\", \n    0x1234\n    0x5678\n]: 2"),
        "{text}"
    );
    assert!(text.contains("@short[\n    0x1234\n]: 2"), "{text}");
    assert!(text.contains("@equal: 2"), "{text}");
    assert!(!Program::compile("BEGIN { @x++; }").unwrap().needs_ustack());
    for source in [
        "BEGIN { @x[ustack(0)]++; }",
        "BEGIN { @x[ustack(128)]++; }",
        "BEGIN { @x[ustack(pid)]++; }",
        "BEGIN { @x[ustack(1, 2)]++; }",
        "BEGIN { @x[ustack]++; @x[comm]++; }",
        "BEGIN { @x = ustack + 1; }",
        "BEGIN { printf(\"%d\", ustack); }",
    ] {
        assert!(Program::compile(source).is_err(), "{source}");
    }
    let text = execute(r#"BEGIN { printf("%s", ustack); }"#, &[0]);
    assert!(text.contains("<no user stack>"));
}

#[test]
fn event_layout_matches_the_jit_stack_abi() {
    assert_eq!(std::mem::size_of::<Event<'_>>(), 200);
    assert_eq!(std::mem::offset_of!(Event<'_>, period), 40);
}

#[test]
fn memory_helpers_symbol_keys_and_extended_event_fields() {
    let text = std::ffi::CString::new("hello target").unwrap();
    let number = 0x12345678u32;
    let source = format!(
        r#"BEGIN {{
        printf("%s|%s|%x|%d|%d|%d|%d|%d\n", str({}, 64), buf({}, 4), read_u32({}), arg0, arg5, retval, latency, offcpu_ns);
        @symbols[usym(0x1234)]++;
    }}"#,
        text.as_ptr() as u64,
        &number as *const _ as u64,
        &number as *const _ as u64
    );
    let program = Program::compile(&source).unwrap();
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        let mut event = Event::new(c"test", c"BEGIN");
        event.pid = std::process::id() as u64;
        event.args = [11, 0, 0, 0, 0, 55];
        event.retval = -2;
        event.latency = 123;
        event.offcpu_ns = 456;
        program.invoke(0, &mut state, &event);
        state.print_all();
        state.flush().unwrap();
    }
    let output = String::from_utf8(output).unwrap();
    assert!(
        output.contains("hello target|78 56 34 12|12345678|11|55|-2|123|456"),
        "{output}"
    );
    assert!(output.contains("@symbols[\"0x1234\"]: 1"), "{output}");
    let program = Program::compile("BEGIN { @x = read_u64(0); }").unwrap();
    let mut state = program.state(std::io::sink());
    let mut event = Event::new(c"test", c"BEGIN");
    event.pid = std::process::id() as u64;
    program.invoke(0, &mut state, &event);
    assert!(state.flush().unwrap_err().contains("read memory"));
    for source in [
        "BEGIN { @x = read_u64(); }",
        "BEGIN { @x[str(1, 4097)]++; }",
        "BEGIN { @x[buf(1)]++; }",
        "BEGIN { @x[usym(1,2)]++; }",
    ] {
        assert!(Program::compile(source).is_err(), "{source}");
    }
}

#[test]
fn linear_histograms_and_report_controls() {
    let program =
        Program::compile("BEGIN { @linear = lhist(period, -10, 10, 5); @count[period]++; }")
            .unwrap();
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        let mut event = Event::new(c"test", c"BEGIN");
        for value in [-11i64, -10, -6, 0, 9, 10] {
            event.period = value as u64;
            program.invoke(0, &mut state, &event);
        }
        state.print_all();
        state.flush().unwrap();
        state.report = poortrace::report::Options {
            format: "json".into(),
            top: Some(1),
            ..Default::default()
        };
        let rows: serde_json::Value =
            serde_json::from_str(&state.render_report().unwrap()).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 2);
    }
    let text = String::from_utf8(output).unwrap();
    for line in [
        "(-inf, -10): 1",
        "[-10, -5): 2",
        "[0, 5): 1",
        "[5, 10): 1",
        "[10, +inf): 1",
    ] {
        assert!(text.contains(line), "{text}");
    }
    for source in [
        "BEGIN { @x = lhist(1,0,0,1); }",
        "BEGIN { @x = lhist(1,0,10,0); }",
        "BEGIN { @x = lhist(1,0,10000,1); }",
        "BEGIN { @x = lhist(1,0,10,pid); }",
        "BEGIN { @x = lhist(1,0,10,1); @x = lhist(1,0,20,1); }",
    ] {
        assert!(Program::compile(source).is_err(), "{source}");
    }
}
