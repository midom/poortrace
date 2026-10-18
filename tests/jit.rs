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
        "BEGIN { $x = comm; $x = 3; }",
        "BEGIN { printf(\"%d\", missing); }",
        "BEGIN { printf(\"%d\", $missing); }",
        "kprobe:bad-name { @x++; }",
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

#[test]
fn strings_functions_arrays_loops_and_deletion() {
    let text = execute(
        r#"
        fn identity($x) = $x;
        fn decorate($s) = identity(strcat($s,"!"));
        fn twice($x) = $x * 2;
        BEGIN {
            $s=decorate("hello"); $i=0;
            repeat(4) { $a[$i]=twice($i+1); $i++; }
            @sum=$a[0]+$a[3]; @by[$s]++;
            @remove[1]++; delete(@remove[1]);
            printf("%s %d %d %d %s %d %d\n",$s,strlen($s),strcontains($s,"ell"),startswith($s,"he"),substr($s,1,3),i8(255),u8(-1));
        }
    "#,
        &[0],
    );
    assert!(text.contains("hello! 6 1 1 ell -1 255\n"), "{text}");
    assert!(text.contains("@sum: 10"), "{text}");
    assert!(text.contains("@by[\"hello!\"]: 1"), "{text}");
    assert!(!text.contains("@remove"), "{text}");
    for source in [
        "BEGIN { repeat(1025) { @x++; } }",
        "fn x($a,$a) = $a; BEGIN { @x++; }",
        "fn x($a) = $a; BEGIN { @x=x(); }",
        "BEGIN { $s=\"x\"; $s++; }",
    ] {
        assert!(Program::compile(source).is_err(), "{source}");
    }
    for (source, message) in [
        ("BEGIN { $a[-1]=3; }", "array index"),
        (
            "BEGIN { repeat(1024) {repeat(1024){@x++;}} }",
            "loop iterations",
        ),
    ] {
        let program = Program::compile(source).unwrap();
        let mut state = program.state(Vec::new());
        program.invoke(0, &mut state, &Event::new(c"x", c"x"));
        assert!(
            state.error.as_ref().is_some_and(|e| e.contains(message)),
            "{:?}",
            state.error
        );
    }
}

#[test]
fn javascript_stack_types_depth_and_recorded_results() {
    let source = r#"BEGIN { $stack=jsstack(2); @frames[$stack]=count(); printf("%s",jsstack); }"#;
    let program = Program::compile(source).unwrap();
    assert!(program.needs_jsstack());
    assert!(!program.needs_ustack());
    for bad in ["jsstack(0)", "jsstack(128)", "jsstack(pid)", "jsstack(1,2)"] {
        assert!(Program::compile(&format!("BEGIN {{ printf(\"%s\",{bad}); }}")).is_err());
    }
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        // Replay does not need a live process or any V8 metadata.
        state.replay_helpers(
            [2, 127]
                .into_iter()
                .map(|length| poortrace::recording::Helper {
                    op: 51,
                    value: 0,
                    length,
                    number: 0,
                    descriptor: None,
                    text: Some("    leaf (example.js)\n".into()),
                    error: None,
                })
                .collect(),
        );
        program.invoke(0, &mut state, &Event::new(c"node", c"synthetic"));
        state.print_all();
        state.flush().unwrap();
    }
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("leaf (example.js)"));
    assert!(text.contains(": 1"));
}

#[test]
fn while_and_map_iteration_are_bounded_and_snapshot_values() {
    let text = execute(
        r#"BEGIN {
        $i=0; while ($i<4) { @numbers[$i]=$i+1; $i++; }
        for ($key,$value in @numbers) { @total=$value+@total; delete(@numbers[$key]); }
        @names["a"]=2; @names["b"]=3;
        for ($name,$amount in @names) { printf("%s=%d\n",$name,$amount); @names[$name]=99; }
        @empty[1]=1; clear(@empty);
        for ($unused,$zero in @empty) { @bad++; }
        while (0) { @bad++; }
    }"#,
        &[0],
    );
    assert!(text.contains("@total: 10"), "{text}");
    assert!(text.contains("a=2\nb=3\n"), "{text}");
    assert!(!text.contains("@numbers["), "{text}");
    assert!(!text.contains("@bad"), "{text}");
    let program = Program::compile("BEGIN { while(1) { @x++; } }").unwrap();
    let mut state = program.state(Vec::new());
    program.invoke(0, &mut state, &Event::new(c"x", c"x"));
    assert!(
        state
            .error
            .as_ref()
            .is_some_and(|e| e.contains("loop iterations")),
        "{:?}",
        state.error
    );
    for source in [
        "BEGIN { @x[1,2]++; for($k,$v in @x) { @y++; } }",
        "BEGIN { @x[1]=hist(2); for($k,$v in @x) { @y++; } }",
        "BEGIN { @x[1]++; for($k,$k in @x) { @y++; } }",
        "BEGIN { while(\"x\") { @x++; } }",
    ] {
        assert!(Program::compile(source).is_err(), "{source}");
    }
}

#[test]
fn tracepoint_helpers_are_typed_and_validate_missing_fields() {
    let program =
        Program::compile(r#"BEGIN { printf("%d %s\n",tp("value"),tpstr("name")); }"#).unwrap();
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        state
            .trace_fields
            .insert("value".into(), poortrace::kernel::Value::Integer(42));
        state.trace_fields.insert(
            "name".into(),
            poortrace::kernel::Value::String("worker".into()),
        );
        program.invoke(0, &mut state, &Event::new(c"x", c"x"));
        state.flush().unwrap();
    }
    assert_eq!(String::from_utf8(output).unwrap(), "42 worker\n");
    let mut state = program.state(Vec::new());
    program.invoke(0, &mut state, &Event::new(c"x", c"x"));
    assert!(
        state
            .error
            .as_ref()
            .is_some_and(|e| e.contains("unavailable"))
    );
}

#[test]
fn floating_point_locals_arithmetic_comparisons_and_casts() {
    let text = execute(
        r#"fn square($x)=$x*$x; BEGIN {
       $x=1.25; $x+=2.5; $x++; $x--;
       printf("%g %f %e %d %d %d %d %g\n",square($x),f64(2)/4,-0.5,3.0<4,3==3.0,!0.0,i64(-3.75),f32(1.25));
       printf("%g\n",5.5%2.0);
       $i=0.0; while($i<3) { $i++; } printf("%g\n",$i);
       printf("%d %d %d\n",(0.0/0.0)!=0.0,(0.0/0.0)==(0.0/0.0),1.0&&2.0);
    }"#,
        &[0],
    );
    assert_eq!(
        text,
        "14.0625 0.500000 -5.000000e-1 1 1 1 -3 1.25\n1.5\n3\n1 0 1\n"
    );
    for source in [
        "BEGIN { printf(\"%g\",1.0 & 2); }",
        "BEGIN { $x=1e999; }",
        "BEGIN { $x=1.25; $x=1; }",
    ] {
        assert!(Program::compile(source).is_err(), "{source}");
    }
}

#[test]
fn floating_point_maps_and_snapshot_iteration() {
    let text = execute(
        r#"BEGIN {
        @set=1.25; @set++; @set--;
        @sum=sum(1.5); @sum=sum(2.25);
        @min=min(2.5); @min=min(-1.25);
        @max=max(-1.5); @max=max(2.25);
        @avg=avg(1.0); @avg=avg(2.0);
        @values["x"]=1.25; @values["y"]=2.5;
        for($key,$value in @values) { printf("%s=%.2f\n",$key,$value); }
        printf("read=%.2f missing=%g\n",@sum,@values["missing"]);
    }"#,
        &[0],
    );
    for expected in [
        "@set: 1.25",
        "@sum: 3.75",
        "@min: -1.25",
        "@max: 2.25",
        "@avg: 1.5",
        "x=1.25\ny=2.50\n",
        "read=3.75 missing=0",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    for source in [
        "BEGIN { @x=1.0; @x=1; }",
        "BEGIN { @x=hist(1.0); @x=hist(1); }",
    ] {
        assert!(Program::compile(source).is_err(), "{source}");
    }
    let program = Program::compile("BEGIN { @x=1.0/0.0; }").unwrap();
    let mut state = program.state(Vec::new());
    program.invoke(0, &mut state, &Event::new(c"x", c"x"));
    assert!(
        state
            .error
            .as_ref()
            .is_some_and(|e| e.contains("remain finite"))
    );
}

#[test]
fn go_stacks_and_goroutine_snapshots_replay_without_a_runtime() {
    let program =
        Program::compile(r#"BEGIN { $s=gostack(2); printf("%s%s",$s,goroutines(8,16)); }"#)
            .unwrap();
    assert!(program.needs_jsstack());
    let mut output = Vec::new();
    {
        let mut state = program.state(&mut output);
        state.replay_helpers(vec![
            poortrace::recording::Helper {
                op: 52,
                value: 0,
                length: 2,
                number: 0,
                text: Some("goroutine 1\n    main.leaf\n".into()),
                error: None,
                descriptor: None,
            },
            poortrace::recording::Helper {
                op: 53,
                value: 16,
                length: 8,
                number: 0,
                text: Some("goroutine 2\n    main.parkedLeaf\n".into()),
                error: None,
                descriptor: None,
            },
        ]);
        program.invoke(0, &mut state, &Event::new(c"go", c"synthetic"));
        state.flush().unwrap();
    }
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("main.leaf"));
    assert!(text.contains("main.parkedLeaf"));
    for expression in [
        "gostack(0)",
        "gostack(128)",
        "goroutines(0,10)",
        "goroutines(2,1025)",
        "goroutines(2)",
    ] {
        assert!(
            Program::compile(&format!("BEGIN {{printf(\"%s\",{expression});}}")).is_err(),
            "{expression}"
        );
    }
}

#[test]
fn floating_point_keys_have_numeric_order_and_signed_zero_identity() {
    let text = execute(
        r#"BEGIN {
        @keys[-2.0]=2; @keys[-1.0]=1; @keys[0.0]=3; @keys[-0.0]=4; @keys[1.0]=5;
        for($key,$value in @keys) {printf("%g:%d\n",$key,$value);}
    }"#,
        &[0],
    );
    assert!(text.starts_with("-2:2\n-1:1\n0:4\n1:5\n"), "{text}");
    let program = Program::compile("BEGIN { @x[0.0/0.0]++; }").unwrap();
    let mut state = program.state(Vec::new());
    program.invoke(0, &mut state, &Event::new(c"x", c"x"));
    assert!(
        state
            .error
            .as_ref()
            .is_some_and(|e| e.contains("keys must be finite"))
    );
}

#[test]
fn tuple_map_iteration_float_arrays_and_float_histograms() {
    let text = execute(
        r#"BEGIN {
        @pairs["a",1,1.5]=2.25; @pairs["b",2,2.5]=3.25;
        for (($name,$index,$key),$value in @pairs) {printf("%s:%d:%g=%g\n",$name,$index,$key,$value);delete(@pairs[$name,$index,$key]);}
        $a[0]=1.25; $a[1]=2.5; $a[0]++; $a[1]--; $a[2]=$a[0]+$a[1]; printf("array=%g,%g,%g,%g\n",$a[0],$a[1],$a[2],$a[3]);
        @h=hist(0.0); @h=hist(0.25); @h=hist(0.5); @h=hist(1.5); @h=hist(-0.5);
        @l=lhist(0.25,0.0,1.0,0.25); @l=lhist(0.75,0.0,1.0,0.25); @l=lhist(1.0,0.0,1.0,0.25);
    }"#,
        &[0],
    );
    for expected in [
        "a:1:1.5=2.25\nb:2:2.5=3.25\n",
        "array=2.25,1.5,3.75,0",
        "[0.25, 0.5): 1",
        "[0.5, 1): 1",
        "[1, 2): 1",
        "[0.75, 1): 1",
        "[1, +inf): 1",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("@pairs["));
    for source in [
        "BEGIN{@x[1,2]++;for(($a,$a),$v in @x){@y++;}}",
        "BEGIN{$a[0]=1.0;$a[1]=1;}",
        "BEGIN{@x=lhist(0.5,0.0,1.0,0.0);}",
    ] {
        assert!(Program::compile(source).is_err(), "{source}");
    }
}

#[test]
fn recursive_expression_functions_are_native_and_bounded() {
    let source = r#"fn fact($n)=$n<=1?1:$n*fact($n-1); fn fib($n)=$n<2?$n:fib($n-1)+fib($n-2); BEGIN{printf("%d %d %d\n",fact(6),fib(10),0?1/0:42);}"#;
    assert_eq!(execute(source, &[0]), "720 55 42\n");
    assert_eq!(
        execute(
            r#"fn chain($n)=$n==0?"end":strcat("x",chain($n-1)); fn fractional($n)=$n<=0?0.5:fractional($n-1)+0.25; BEGIN {printf("%s %g\n",chain(2),fractional(3));}"#,
            &[0]
        ),
        "xxend 1.25\n"
    );
    let program = Program::compile(source).unwrap();
    assert!(program.ir.contains("define i64 @expr_fn_"));
    assert!(program.ir.len() < 30000);
    for source in [
        "fn forever($n)=forever($n+1); BEGIN{@x=forever(0);}",
        "fn fib($n)=$n<2?$n:fib($n-1)+fib($n-2); BEGIN{@x=fib(30);}",
    ] {
        let program = Program::compile(source).unwrap();
        let mut state = program.state(Vec::new());
        program.invoke(0, &mut state, &Event::new(c"x", c"x"));
        assert!(
            state
                .error
                .as_ref()
                .is_some_and(|e| e.contains("recursion") || e.contains("fuel")),
            "{:?}",
            state.error
        );
    }
}

#[test]
fn kernel_and_cooperative_managed_helpers_keep_stack_key_types() {
    for (helper, op) in [
        ("kstack", 120),
        ("asyncstack", 150),
        ("jstack", 151),
        ("dotnetstack", 152),
        ("wasmstack", 153),
    ] {
        let program = Program::compile(&format!(
            "BEGIN {{ $stack={helper}(8); @frames[$stack]=count(); printf(\"%s\",$stack); }}"
        ))
        .unwrap();
        let mut state = program.state(Vec::new());
        state.replay_helpers(vec![poortrace::recording::Helper {
            op,
            value: if op == 120 { 8 } else { 0 },
            length: if op == 120 { 0 } else { 8 },
            number: 0,
            text: Some("    captured_leaf\n".into()),
            error: None,
            descriptor: None,
        }]);
        program.invoke(0, &mut state, &Event::new(c"synthetic", c"BEGIN"));
        state.flush().unwrap();
        assert_eq!(program.needs_kstack(), op == 120);
    }
    for expression in [
        "ksym(ip)",
        "kfieldstr(ip,\"task_struct\",\"comm\")",
        "args_native()",
        "args_as(\"i32\")",
        "managedstacks",
        "managedstacks()",
        "managedstacks(8)",
    ] {
        Program::compile(&format!(
            "BEGIN {{$s={expression}; @values[$s]=count(); printf(\"%s\",$s);}}"
        ))
        .unwrap();
    }
}

#[test]
fn process_managed_snapshots_are_strings_including_recursive_function_returns() {
    for expression in [
        "managedstacks",
        "managedstacks()",
        "managedstacks(8)",
        "snapshot(2)",
    ] {
        let program = Program::compile(&format!(
            "fn snapshot($n) = $n ? snapshot($n-1) : managedstacks(8); BEGIN {{$s={expression}; @snapshots[$s]=count(); printf(\"%s\",$s);}}"
        ))
        .unwrap();
        let mut output = Vec::new();
        {
            let mut state = program.state(&mut output);
            state.replay_helpers(vec![poortrace::recording::Helper {
                op: 154,
                value: 0,
                length: if expression == "managedstacks" || expression == "managedstacks()" {
                    127
                } else {
                    8
                },
                number: 0,
                text: Some("thread17 java\n    leaf\nthread23 java\n    worker\n".into()),
                error: None,
                descriptor: None,
            }]);
            program.invoke(0, &mut state, &Event::new(c"synthetic", c"BEGIN"));
            state.flush().unwrap();
        }
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "thread17 java\n    leaf\nthread23 java\n    worker\n"
        );
    }
    assert!(Program::compile("BEGIN {printf(\"%s\",managedstacks(0));}").is_err());
}
