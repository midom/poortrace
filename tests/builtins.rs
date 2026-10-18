use poortrace::{codegen::Program, runtime::Event};
fn run(source: &str) -> Result<String, String> {
    let program = Program::compile(source)?;
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        let mut event = Event::new(c"tester", c"uprobe:/removed:http_work");
        event.pid = std::process::id() as u64;
        event.tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
        event.cpu = unsafe { libc::sched_getcpu() } as u64;
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        event.nsecs = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
        program.invoke(0, &mut state, &event);
        state.flush()?;
    }
    String::from_utf8(output).map_err(|e| e.to_string())
}
#[test]
fn strings_network_and_named_metadata() {
    let output = run(r#"BEGIN {
        print(strstr("hello world","world")); print(strstr("x","z"));
        print(strncmp("abcdef","abcxyz",3)); print(memcmp("ab","ac",2));
        print(strcap("hello")); print(bswap(u16(0x1234)));
        print(ntop(pton("127.0.0.1"))); print(ntop(pton("2001:db8::1")));
        print(macaddr("00 11 22 aa bb cc"));
        print(syscall_name(0)); print(signal_name(15));
        print(func); print(probetype); print(comm); print(has_cpid);
        assert(ncpus()>0); assert(uid()>=0); assert(gid>=0); assert(ppid>0);
        print(getopt("unset","default")); print(getopt("unset",42));
    }"#)
    .unwrap();
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(
        &lines[..10],
        &[
            "6",
            "-1",
            "0",
            "-1",
            "5",
            "13330",
            "127.0.0.1",
            "2001:db8::1",
            "00:11:22:aa:bb:cc",
            &poortrace::syscall::name(0)
        ]
    );
    assert_eq!(
        &lines[10..],
        &[
            "SIGTERM",
            "http_work",
            "uprobe",
            "tester",
            "0",
            "default",
            "42"
        ]
    );
}
#[test]
fn map_queries_zero_top_and_find_do_not_mutate_original_values() {
    let output = run(r#"BEGIN {
        @m[1]=0; @m[2]=20; @m[3]=30;
        print(has_key(@m,1)); print(has_key(@m,9)); print(len(@m));
        $v=99; print(find(@m,9,$v)); print($v); print(find(@m,2,$v)); print($v);
        print(@m,1,10); print(@m[3]);
        print(delete(@m,2)); print(delete(@m,2));
        zero(@m); print(len(@m)); print(@m[3]); clear(@m);
        @tuple["a",1]=7; print(has_key(@tuple,("a",1))); clear(@tuple);
    }"#)
    .unwrap();
    assert_eq!(
        output,
        "1\n0\n3\n0\n99\n1\n20\n@m[3]: 3\n30\n1\n0\n2\n0\n1\n"
    );
}
#[test]
fn statistics_and_histogram_subdivisions() {
    let output=run(r#"BEGIN { @s=stats(3); @s=stats(7); print(@s); clear(@s); @f=stats(1.5); @f=stats(2.5); print(@f); clear(@f); @h=hist(9,2); @h=hist(11,2); print(@h); clear(@h); }"#).unwrap();
    assert!(
        output.contains("@s: count 2, average 5, total 10\n"),
        "{output}"
    );
    assert!(
        output.contains("@f: count 2, average 2, total 4\n"),
        "{output}"
    );
    assert!(
        output.contains("[8, 10): 1") && output.contains("[10, 12): 1"),
        "{output}"
    );
}
#[test]
fn unsupported_kernel_helpers_are_explicit_and_unsafe_helpers_are_guarded() {
    for expression in [
        "override(0)",
        "skboutput(1,2,3,4)",
        "socket_cookie(0)",
        "path(0)",
        "curtask()",
        "jiffies()",
        "usermode()",
        "kptr(0)",
        "percpu_kaddr(\"x\")",
        "kfunc_allowed(\"x\")",
    ] {
        let source = format!("BEGIN {{ {expression}; }}");
        let error = Program::compile(&source).err().expect(&source);
        assert!(error.contains("unavailable"), "{error}");
    }
    for expr in [
        "system(\"true\")",
        "signal(15)",
        "signal_thread(15)",
        "write_user(1,\"x\",1)",
    ] {
        let error = run(&format!("BEGIN {{ {expr}; }}")).unwrap_err();
        assert!(error.contains("--unsafe"), "{error}");
    }
    assert!(
        run("BEGIN { assert(0,\"failed condition\"); print(\"unreachable\"); }")
            .unwrap_err()
            .contains("failed condition")
    );
}
#[test]
fn time_series_are_bounded_ordered_and_use_event_time() {
    let program = Program::compile("BEGIN { @s=tseries(period,10ns,2,\"sum\"); }").unwrap();
    let mut state = program.state(Vec::new());
    let mut event = Event::new(c"test", c"BEGIN");
    for (time, value) in [(10, 1), (15, 2), (20, 3), (30, 4)] {
        event.nsecs = time;
        event.period = value;
        program.invoke(0, &mut state, &event);
        state.flush().unwrap();
    }
    state.report.format = "json".into();
    let rows: serde_json::Value = serde_json::from_str(&state.render_report().unwrap()).unwrap();
    assert_eq!(rows[0]["series"], serde_json::json!([[20, 3], [30, 4]]));
}

#[test]
fn native_type_sizes_constant_assertions_and_stack_formats() {
    let output=run(r#"BEGIN { static_assert(sizeof(int)==4,"int size"); if (false) { fail("not visited"); } print(sizeof(unsigned long)); print(sizeof(char[12])); print(sizeof(1.5)); print(nsecs(monotonic)==nsecs); print(len(ustack(raw))); unwatch(123); }"#).unwrap();
    assert_eq!(output, "8\n12\n8\n1\n0\n");
    assert!(
        Program::compile("BEGIN { static_assert(2+2==5,\"math failed\"); }")
            .err()
            .unwrap()
            .contains("math failed")
    );
    let program = Program::compile("BEGIN { print(reg(\"sp\")); print(ustack(raw,2)); }").unwrap();
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        state.register_snapshot = Some(poortrace::perf::UserRegs {
            sp: 123,
            ..Default::default()
        });
        let event = Event::new(c"test", c"BEGIN").with_ustack(&[0x1234, 0x5678, 0x9999]);
        program.invoke(0, &mut state, &event);
        state.flush().unwrap();
    }
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "123\n    0x1234\n    0x5678\n\n"
    );
    let dwarf = Program::compile("BEGIN { @[dw_ustack(raw,2)]=count(); }").unwrap();
    assert!(dwarf.needs_dwarf());
    assert_eq!(
        dwarf.state(Vec::new()).stack_mode,
        poortrace::runtime::StackMode::Dwarf
    );
}

#[test]
fn captured_helpers_are_pointer_independent_and_reject_bad_result_types() {
    use poortrace::recording::Helper;
    let program = Program::compile("BEGIN { print(username()); }").unwrap();
    for alternate in [false, true] {
        for valid in [false, true] {
            let mut output = Vec::new();
            {
                let mut state = program.state(&mut output);
                let helpers = vec![Helper {
                    op: 200,
                    value: 0,
                    length: 0,
                    number: 99,
                    text: valid.then(|| "captured_name".into()),
                    descriptor: Some(r#"{"name":"username","args":[]}"#.into()),
                    error: None,
                }];
                if alternate {
                    state.replay_captured_helpers(helpers);
                } else {
                    state.replay_helpers(helpers);
                }
                let mut event = Event::new(c"gone", c"BEGIN");
                event.pid = u32::MAX as u64;
                event.tid = event.pid;
                program.invoke(0, &mut state, &event);
                assert_eq!(state.flush().is_ok(), valid, "{:?}", state.error);
            }
            assert_eq!(
                output,
                if valid {
                    b"captured_name\n".as_slice()
                } else {
                    b"".as_slice()
                }
            );
        }
    }
    let pure = Program::compile(
        "BEGIN { print(ntop(pton(\"127.0.0.1\"))); print(strncmp(\"abc\",\"abd\",3)); }",
    )
    .unwrap();
    let mut output = Vec::new();
    {
        let mut state = pure.state(&mut output);
        state.replay_captured_helpers(vec![]);
        pure.invoke(0, &mut state, &Event::new(c"gone", c"BEGIN"));
        state.flush().unwrap();
    }
    assert_eq!(output, b"127.0.0.1\n-1\n");
}

#[test]
fn helper_bounds_zero_length_reads_and_compile_time_diagnostics() {
    assert_eq!(
        run("BEGIN { print(strncmp(0,0,0)); print(memcmp(0,0,0)); print(strftime(\"\",nsecs)); }")
            .unwrap(),
        "0\n0\n\n"
    );
    assert!(
        run("BEGIN { print(memcmp(\"a\",\"a\",4097)); }")
            .unwrap_err()
            .contains("4096")
    );
    assert!(
        Program::compile("BEGIN { fail(\"bad value %d\",7); }")
            .err()
            .unwrap()
            .contains("bad value 7")
    );
    for script in [
        "BEGIN { @x=hist(1,6); }",
        "BEGIN { @x=tseries(1,1s,4097); }",
        "BEGIN { print(ustack(raw,128)); }",
        "BEGIN { print(strncmp(\"a\",\"a\")); }",
    ] {
        assert!(Program::compile(script).is_err(), "{script}");
    }
    assert!(run("BEGIN { exit(256); }").is_err());
}
