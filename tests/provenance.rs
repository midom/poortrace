use poortrace::report::{self, Options, Provenance, Row};
use std::process::Command;

#[test]
fn cli_json_and_recording_replay_preserve_measurement_context() {
    let dir = std::env::temp_dir().join(format!("poortrace-provenance-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let recording = dir.join("trace.jsonl");
    let sidecar = dir.join("metadata.json");
    let out = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--output-format", "json", "--record"])
        .arg(&recording)
        .arg("--report-metadata")
        .arg(&sidecar)
        .args(["-e", "BEGIN { @x=1; }"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let live: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(live["schema_version"], 1);
    assert_eq!(live["metadata"]["stack_mode"], "fp");
    assert_eq!(live["metadata"]["lost_samples"], 0);
    assert_eq!(live["metadata"]["replay"], false);
    assert!(live["metadata"]["elapsed_seconds"].as_f64().unwrap() >= 0.0);
    assert_eq!(live["rows"][0]["value"], 1);
    let journal = poortrace::recording::read_full(&recording).unwrap();
    assert_eq!(journal.header.provenance.as_ref().unwrap().backend, "perf");
    let out = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--output-format", "json", "--replay"])
        .arg(&recording)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let replay: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(replay["metadata"]["backend"], live["metadata"]["backend"]);
    assert_eq!(replay["metadata"]["replay"], true);
    assert_eq!(replay["rows"], live["rows"]);
    let metadata: Provenance = serde_json::from_slice(&std::fs::read(sidecar).unwrap()).unwrap();
    assert_eq!(metadata.stack_mode, "fp");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn report_envelopes_import_legacy_arrays_and_profiles_embed_labels_safely() {
    let rows = vec![Row {
        map: "x".into(),
        keys: vec![],
        value: 1,
        float_value: None,
        buckets: vec![],
    }];
    let metadata = Provenance {
        capture_mode: "stopped-target-wall-clock".into(),
        ..Default::default()
    };
    let path = std::env::temp_dir().join(format!("poortrace-baseline-{}.json", std::process::id()));
    for provenance in [None, Some(metadata.clone())] {
        let text = report::render(
            &rows,
            &Options {
                format: "json".into(),
                provenance,
                ..Default::default()
            },
        )
        .unwrap();
        std::fs::write(&path, text).unwrap();
        assert_eq!(report::baseline(&path).unwrap()[0].value, 1);
    }
    let speedscope = report::annotate_profile(
        "{\"profiles\":[{\"name\":\"weights\"}]}".into(),
        "speedscope",
        &metadata,
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&speedscope).unwrap();
    assert!(
        value["profiles"][0]["name"]
            .as_str()
            .unwrap()
            .contains("wall-clock")
    );
    assert!(value["poortrace"]["lost_samples"].is_null());
    let hostile = Provenance {
        capture_mode: "</metadata><script>&".into(),
        ..metadata
    };
    let svg = report::annotate_profile("<svg></svg>".into(), "flamegraph", &hostile).unwrap();
    assert!(!svg.contains("<script>"));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn replay_reports_archived_loss_and_keeps_reliable_mode() {
    use poortrace::{
        codegen::Program,
        recording::{Metadata, Recorder},
        runtime::Event,
    };
    let source = "BEGIN { @x=count(); }";
    let program = Program::compile(source).unwrap();
    let path = std::env::temp_dir().join(format!(
        "poortrace-loss-provenance-{}.jsonl",
        std::process::id()
    ));
    let context = Provenance {
        backend: "reliable".into(),
        capture_mode: "stopped-target-wall-clock".into(),
        stack_mode: "fp".into(),
        ..Default::default()
    };
    {
        let mut state = program.state(std::io::sink());
        state.recorder =
            Some(Recorder::create_with_provenance(&path, source, Some(&context)).unwrap());
        program.invoke(0, &mut state, &Event::new(c"fixture", c"BEGIN"));
        let recorder = state.recorder.as_mut().unwrap();
        recorder
            .metadata(&Metadata::Lost {
                cpu: 0,
                nsecs: 1,
                count: 42,
            })
            .unwrap();
        recorder
            .metadata(&Metadata::Discontinuity {
                cpu: 0,
                nsecs: 2,
                reason: "test gap".into(),
            })
            .unwrap();
        recorder.flush().unwrap();
    }
    let out = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--output-format", "json", "--replay"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["metadata"]["capture_mode"], context.capture_mode);
    assert_eq!(value["metadata"]["lost_samples"], 42);
    assert_eq!(value["metadata"]["discontinuities"], 1);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn metadata_sidecar_cannot_overwrite_the_report_or_an_input() {
    let path = std::env::temp_dir().join(format!(
        "poortrace-metadata-collision-{}.json",
        std::process::id()
    ));
    let out = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["--report-metadata"])
        .arg(&path)
        .arg("--output")
        .arg(&path)
        .args(["-e", "BEGIN {}"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("must differ"));
    assert!(!path.exists());
}
