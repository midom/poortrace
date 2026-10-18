use poortrace::report::{self, Options, Row};
fn row(value: f64) -> Row {
    Row {
        stats: None,
        series: Vec::new(),
        map: "value".into(),
        keys: vec![],
        value: 0,
        float_value: Some(value),
        buckets: vec![],
    }
}
#[test]
fn floating_reports_preserve_values_comparisons_and_percentages() {
    let current = vec![row(0.125)];
    let out = report::render(
        &current,
        &Options {
            format: "text".into(),
            percent: true,
            rate: true,
            elapsed: 0.5,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(out.contains(": 0.125 (100.00%) (0.250/s)"), "{out}");
    let json = report::render(
        &current,
        &Options {
            format: "json".into(),
            baseline: vec![row(0.375)],
            ..Default::default()
        },
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json[0]["float_value"], -0.25);
    let removed = report::render(
        &[],
        &Options {
            format: "text".into(),
            baseline: current,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(removed, "@value: -0.125\n");
}
#[test]
fn floating_reports_reject_nonfinite_values_and_integer_profile_exports() {
    assert!(report::render(&[row(f64::NAN)], &Options::default()).is_err());
    assert!(
        report::render(
            &[row(f64::MAX)],
            &Options {
                baseline: vec![row(-f64::MAX)],
                ..Default::default()
            }
        )
        .is_err()
    );
    for format in ["folded", "speedscope", "flamegraph"] {
        assert!(
            report::render(
                &[row(0.25)],
                &Options {
                    format: format.into(),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .contains("integer weights")
        );
    }
}

#[test]
fn histogram_comparisons_sort_fractional_and_scientific_bucket_bounds() {
    let mut current = row(0.0);
    current.float_value = None;
    current.buckets = vec![
        ("[1e-3, 2e-3)".into(), 2),
        ("[-0.5, 0)".into(), 2),
        ("[0, 1e-3)".into(), 2),
    ];
    let mut previous = current.clone();
    previous.buckets = vec![("[1e-3, 2e-3)".into(), 1)];
    let json = report::render(
        &[current],
        &Options {
            format: "json".into(),
            baseline: vec![previous],
            ..Default::default()
        },
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json[0]["buckets"][0][0], "[-0.5, 0)");
    assert_eq!(json[0]["buckets"][1][0], "[0, 1e-3)");
    assert_eq!(json[0]["buckets"][2][0], "[1e-3, 2e-3)");
}
