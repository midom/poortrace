//! Portable map reports and weighted stack profile exports.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Key {
    pub kind: String,
    pub value: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Row {
    pub map: String,
    pub keys: Vec<Key>,
    pub value: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub float_value: Option<f64>,
    #[serde(default)]
    pub buckets: Vec<(String, i64)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub series: Vec<(u64, i64)>,
}
/// Measurement context travels with exported results. Unknown loss is not zero loss.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Provenance {
    pub backend: String,
    pub capture_mode: String,
    pub stack_mode: String,
    pub probes: Vec<String>,
    #[serde(default)]
    pub observation_semantics: BTreeMap<String, String>,
    pub elapsed_seconds: f64,
    pub lost_samples: Option<u64>,
    pub discontinuities: Option<u64>,
    pub replay: bool,
}

/// Versioned CLI JSON envelope. Library callers without provenance retain legacy arrays.
pub fn json_document(
    rows: &impl Serialize,
    provenance: Option<&Provenance>,
    elapsed: f64,
) -> Result<String> {
    let value = if let Some(metadata) = provenance {
        let mut metadata = metadata.clone();
        metadata.elapsed_seconds = elapsed;
        serde_json::json!({"schema_version":1, "metadata":metadata, "rows":rows})
    } else {
        serde_json::to_value(rows).map_err(|e| e.to_string())?
    };
    serde_json::to_string_pretty(&value)
        .map(|s| s + "\n")
        .map_err(|e| e.to_string())
}

/// Embed provenance in self-contained profile formats without changing their weights.
pub fn annotate_profile(text: String, format: &str, metadata: &Provenance) -> Result<String> {
    match format {
        "speedscope" | "speedscope-timeline" | "speedscope-scheduler" => {
            let mut json: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| e.to_string())?;
            json["poortrace"] = serde_json::to_value(metadata).map_err(|e| e.to_string())?;
            if let Some(profiles) = json["profiles"].as_array_mut() {
                for profile in profiles {
                    let name = profile["name"].as_str().unwrap_or("poortrace");
                    profile["name"] = format!("{name} ({})", metadata.capture_mode).into();
                }
            }
            serde_json::to_string(&json)
                .map(|s| s + "\n")
                .map_err(|e| e.to_string())
        }
        "flamegraph" => {
            let json = serde_json::to_string(metadata)
                .map_err(|e| e.to_string())?
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            let Some(at) = text.find('>') else {
                return Err("invalid SVG report".into());
            };
            Ok(format!(
                "{}<metadata>{json}</metadata>{}",
                &text[..=at],
                &text[at + 1..]
            ))
        }
        _ => Ok(text),
    }
}

#[derive(Clone, Debug, Default)]
pub struct Options {
    pub format: String,
    pub top: Option<usize>,
    pub percent: bool,
    pub rate: bool,
    pub elapsed: f64,
    pub baseline: Vec<Row>,
    pub quantiles: Vec<f64>,
    pub provenance: Option<Provenance>,
}

pub fn baseline(path: &std::path::Path) -> Result<Vec<Row>> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("comparison profile exceeds 64 MiB".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let rows = if value.is_array() {
        value
    } else {
        if value["schema_version"] != 1 {
            return Err("unsupported JSON report schema".into());
        }
        value
            .get("rows")
            .cloned()
            .ok_or("JSON report is missing rows")?
    };
    serde_json::from_value(rows)
        .map_err(|e| format!("comparison requires a poortrace JSON report: {e}"))
}
fn bucket_order(a: &str, b: &str) -> std::cmp::Ordering {
    let lower = |s: &str| {
        s.trim_start_matches(['[', '('])
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_owned()
    };
    let (a, b) = (lower(a), lower(b));
    match (a.parse::<i128>(), b.parse::<i128>()) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => a
            .parse::<f64>()
            .unwrap_or(f64::NEG_INFINITY)
            .total_cmp(&b.parse::<f64>().unwrap_or(f64::NEG_INFINITY)),
    }
}
fn number(row: &Row) -> f64 {
    row.float_value.unwrap_or(row.value as f64)
}
fn identity(row: &Row) -> String {
    serde_json::to_string(&(&row.map, &row.keys)).unwrap()
}

pub fn render(rows: &[Row], options: &Options) -> Result<String> {
    if rows
        .iter()
        .chain(&options.baseline)
        .any(|r| r.float_value.is_some_and(|v| !v.is_finite()))
    {
        return Err("reports require finite floating-point values".into());
    }
    if rows
        .iter()
        .any(|row| row.stats.is_some() || !row.series.is_empty())
        && (!options.baseline.is_empty()
            || options.percent
            || options.rate
            || !options.quantiles.is_empty())
    {
        return Err("stats/tseries reports require text or JSON without scalar comparison/rate/percent options".into());
    }
    let mut rows = rows.to_vec();
    let mut old = BTreeMap::new();
    for row in &options.baseline {
        old.insert(identity(row), row.clone());
    }
    if !options.baseline.is_empty() {
        for row in &mut rows {
            if let Some(previous) = old.remove(&identity(row)) {
                if row.float_value.is_some() || previous.float_value.is_some() {
                    row.float_value = Some(number(row) - number(&previous));
                    row.value = 0;
                } else {
                    row.value = row.value.saturating_sub(previous.value);
                }
                let mut buckets: BTreeMap<_, _> = row.buckets.iter().cloned().collect();
                for (label, count) in previous.buckets {
                    let current = buckets.entry(label).or_default();
                    *current = current.saturating_sub(count);
                }
                row.buckets = buckets.into_iter().collect();
                row.buckets.sort_by(|(a, _), (b, _)| bucket_order(a, b));
            }
        }
        for row in &options.baseline {
            if old.remove(&identity(row)).is_some() {
                let mut missing = row.clone();
                missing.value = missing.value.saturating_neg();
                missing.float_value = missing.float_value.map(|v| -v);
                for (_, count) in &mut missing.buckets {
                    *count = count.saturating_neg();
                }
                rows.push(missing);
            }
        }
    }
    if rows
        .iter()
        .any(|r| r.float_value.is_some_and(|v| !v.is_finite()))
    {
        return Err("floating-point comparison overflow".into());
    }
    let totals: BTreeMap<String, f64> = rows.iter().fold(BTreeMap::new(), |mut totals, row| {
        *totals.entry(row.map.clone()).or_default() += number(row).abs();
        totals
    });
    if options.percent && totals.values().any(|v| !v.is_finite()) {
        return Err("report percentage total overflow".into());
    }
    if options.top.is_some() {
        rows.sort_by(|a, b| {
            a.map.cmp(&b.map).then_with(|| {
                if a.float_value.is_none() && b.float_value.is_none() {
                    b.value.unsigned_abs().cmp(&a.value.unsigned_abs())
                } else {
                    number(b).abs().total_cmp(&number(a).abs())
                }
            })
        });
        let mut seen = BTreeMap::new();
        rows.retain(|row| {
            let count = seen.entry(row.map.clone()).or_insert(0);
            *count += 1;
            *count <= options.top.unwrap()
        });
    }
    if options.rate
        && rows
            .iter()
            .any(|row| !(number(row) / options.elapsed.max(1e-9)).is_finite())
    {
        return Err("report rate overflow".into());
    }
    match options.format.as_str() {
        "json" => json_document(&rows, options.provenance.as_ref(), options.elapsed),
        "folded" | "speedscope" | "flamegraph" => {
            let text = profile(&rows, &options.format)?;
            if let Some(metadata) = &options.provenance {
                let mut metadata = metadata.clone();
                metadata.elapsed_seconds = options.elapsed;
                annotate_profile(text, &options.format, &metadata)
            } else {
                Ok(text)
            }
        }
        "" | "text" => {
            let mut out = String::new();
            for row in &rows {
                out.push('@');
                out.push_str(&row.map);
                if !row.keys.is_empty() {
                    out.push('[');
                    for (index, key) in row.keys.iter().enumerate() {
                        if index != 0 {
                            out.push_str(", ");
                        }
                        match key.kind.as_str() {
                            "stack" => {
                                out.push('\n');
                                out.push_str(&key.value);
                            }
                            "string" => out.push_str(&format!("{:?}", key.value)),
                            _ => out.push_str(&key.value),
                        }
                    }
                    out.push(']');
                }
                if let Some(stats) = &row.stats {
                    out.push_str(&format!(
                        ": count {}, average {}, total {}\n",
                        stats["count"], stats["average"], stats["total"]
                    ));
                    continue;
                }
                if !row.series.is_empty() {
                    out.push_str(":\n");
                    for (time, value) in &row.series {
                        out.push_str(&format!("  {time}: {value}\n"));
                    }
                    continue;
                }
                if !row.buckets.is_empty() {
                    out.push_str(":\n");
                    for (label, count) in &row.buckets {
                        out.push_str(&format!("  {label}: {count}\n"));
                    }
                    if row.buckets.iter().all(|(_, count)| *count >= 0) {
                        let total: u128 = row.buckets.iter().map(|(_, n)| *n as u128).sum();
                        for quantile in &options.quantiles {
                            let target = (total as f64 * quantile).ceil() as u128;
                            let mut seen = 0;
                            let bucket = row.buckets.iter().find(|(_, n)| {
                                seen += *n as u128;
                                seen >= target.max(1)
                            });
                            if let Some((label, _)) = bucket {
                                out.push_str(&format!(
                                    "  p{}: {label} (bucket estimate)\n",
                                    quantile * 100.0
                                ));
                            }
                        }
                    }
                    continue;
                }
                if let Some(value) = row.float_value {
                    out.push_str(&format!(": {value}"));
                } else {
                    out.push_str(&format!(": {}", row.value));
                }
                if options.percent {
                    out.push_str(&format!(
                        " ({:.2}%)",
                        number(row)
                            / if totals[&row.map] > 0.0 {
                                totals[&row.map]
                            } else {
                                1.0
                            }
                            * 100.0
                    ));
                }
                if options.rate {
                    out.push_str(&format!(
                        " ({:.3}/s)",
                        number(row) / options.elapsed.max(1e-9)
                    ));
                }
                out.push('\n');
                for (label, count) in &row.buckets {
                    out.push_str(&format!("  {label}: {count}\n"));
                }
            }
            Ok(out)
        }
        format => Err(format!("unknown report format '{format}'")),
    }
}

fn stacks(rows: &[Row], signed: bool) -> Result<Vec<(Vec<String>, i64)>> {
    if rows
        .iter()
        .any(|row| row.stats.is_some() || !row.series.is_empty())
    {
        return Err("stack profile weights require scalar maps, not stats/tseries".into());
    }

    if rows.iter().any(|row| row.float_value.is_some()) {
        return Err("stack profile exports require integer weights; use text or JSON for floating-point maps".into());
    }
    let mut output = Vec::new();
    for row in rows {
        if !row.keys.iter().any(|key| key.kind == "stack") {
            continue;
        }
        if row.value < 0 && !signed {
            return Err(
                "stack profiles require nonnegative weights; use text or JSON for comparisons"
                    .into(),
            );
        }
        if row.value == 0 {
            continue;
        }
        let mut frames = vec![format!("@{}", row.map)];
        for key in &row.keys {
            if key.kind == "stack" {
                frames.extend(
                    key.value
                        .lines()
                        .rev()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned),
                );
            } else {
                frames.push(key.value.clone());
            }
        }
        if frames.len() > 256 {
            return Err(
                "stack exports support at most 256 frames per row, including key labels".into(),
            );
        }
        output.push((frames, row.value));
    }
    Ok(output)
}
fn profile(rows: &[Row], format: &str) -> Result<String> {
    let stacks = stacks(rows, format == "flamegraph")?;
    if format == "folded" {
        return Ok(stacks
            .iter()
            .map(|(frames, weight)| {
                format!(
                    "{} {weight}\n",
                    frames
                        .iter()
                        .map(|s| s.replace([';', '\n', '\r'], "_"))
                        .collect::<Vec<_>>()
                        .join(";")
                )
            })
            .collect());
    }
    if format == "speedscope" {
        let mut ids = BTreeMap::new();
        let mut frames = Vec::new();
        let mut samples = Vec::new();
        let mut weights = Vec::new();
        for (stack, weight) in &stacks {
            let sample: Vec<usize> = stack
                .iter()
                .map(|frame| {
                    *ids.entry(frame.clone()).or_insert_with(|| {
                        let id = frames.len();
                        frames.push(serde_json::json!({"name":frame}));
                        id
                    })
                })
                .collect();
            samples.push(sample);
            weights.push(*weight);
        }
        return serde_json::to_string(&serde_json::json!({
            "$schema":"https://www.speedscope.app/file-format-schema.json", "name":"poortrace", "shared":{"frames":frames},
            "profiles":[{"type":"sampled", "name":"Aggregated stack weights", "unit":"none", "startValue":0,
                "endValue":weights.iter().map(|&v| v as u128).sum::<u128>(), "samples":samples, "weights":weights}]
        })).map(|text| text + "\n").map_err(|e| e.to_string());
    }
    #[derive(Default)]
    struct Node {
        weight: f64,
        delta: i128,
        children: BTreeMap<String, Node>,
    }
    let mut root = Node::default();
    let mut depth = 0;
    for (frames, weight) in stacks {
        root.weight += weight.unsigned_abs() as f64;
        root.delta += weight as i128;
        depth = depth.max(frames.len());
        let mut node = &mut root;
        for frame in frames {
            node = node.children.entry(frame).or_default();
            node.weight += weight.unsigned_abs() as f64;
            node.delta += weight as i128;
        }
    }
    fn escape(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
    fn draw(node: &Node, x: f64, y: usize, width: f64, out: &mut String) {
        let mut at = x;
        for (name, child) in &node.children {
            let w = width * child.weight / node.weight;
            let hue = if child.delta < 0 { 220 } else { 0 };
            out.push_str(&format!("<g><title>{}: {}</title><rect x=\"{at:.3}\" y=\"{y}\" width=\"{w:.3}\" height=\"19\" fill=\"hsl({hue},85%,65%)\" stroke=\"white\"/>", escape(name), child.delta));
            if w > 40.0 {
                let label: String = name.chars().take((w / 7.0) as usize).collect();
                out.push_str(&format!(
                    "<text x=\"{:.3}\" y=\"{}\">{}</text>",
                    at + 3.0,
                    y + 14,
                    escape(&label)
                ));
            }
            out.push_str("</g>");
            draw(child, at, y.saturating_sub(20), w, out);
            at += w;
        }
    }
    let mut out = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1200\" height=\"{}\" viewBox=\"0 0 1200 {}\"><style>text{{font:12px monospace}}g:hover rect{{stroke:black}}</style>",
        (depth + 1) * 20,
        (depth + 1) * 20
    );
    draw(&root, 0.0, depth * 20, 1200.0, &mut out);
    out.push_str("</svg>\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rows() -> Vec<Row> {
        vec![Row {
            stats: None,
            series: Vec::new(),
            map: "cpu".into(),
            keys: vec![Key {
                kind: "stack".into(),
                value: "    leaf\n    root\n".into(),
            }],
            value: 5,
            float_value: None,
            buckets: vec![],
        }]
    }
    #[test]
    fn exports_and_differences() {
        let rows = rows();
        assert_eq!(
            render(
                &rows,
                &Options {
                    format: "folded".into(),
                    ..Options::default()
                }
            )
            .unwrap(),
            "@cpu;root;leaf 5\n"
        );
        let json = render(
            &rows,
            &Options {
                format: "speedscope".into(),
                ..Options::default()
            },
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["profiles"][0]["weights"][0], 5);
        assert!(
            render(
                &rows,
                &Options {
                    format: "flamegraph".into(),
                    ..Options::default()
                }
            )
            .unwrap()
            .contains("<svg")
        );
        let text = render(
            &rows,
            &Options {
                baseline: rows.clone(),
                ..Options::default()
            },
        )
        .unwrap();
        assert!(text.ends_with(": 0\n"));
    }
    #[test]
    fn signed_histogram_differences_and_percentile_buckets() {
        let current = vec![Row {
            stats: None,
            series: Vec::new(),
            map: "h".into(),
            keys: vec![],
            value: 0,
            float_value: None,
            buckets: vec![("[1, 2)".into(), 1), ("[2, 4)".into(), 3)],
        }];
        let old = vec![Row {
            stats: None,
            series: Vec::new(),
            map: "h".into(),
            keys: vec![],
            value: 0,
            float_value: None,
            buckets: vec![("[1, 2)".into(), 2), ("[4, 8)".into(), 1)],
        }];
        let text = render(
            &current,
            &Options {
                format: "text".into(),
                baseline: old,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            text.contains("[1, 2): -1") && text.contains("[4, 8): -1"),
            "{text}"
        );
        let text = render(
            &current,
            &Options {
                format: "text".into(),
                quantiles: vec![0.5],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(text.contains("p50: [2, 4) (bucket estimate)"), "{text}");
        let negative = vec![Row {
            stats: None,
            series: Vec::new(),
            map: "cpu".into(),
            keys: vec![Key {
                kind: "stack".into(),
                value: "    leaf\n".into(),
            }],
            value: -3,
            float_value: None,
            buckets: vec![],
        }];
        let svg = render(
            &negative,
            &Options {
                format: "flamegraph".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(svg.contains("hsl(220") && svg.contains("leaf: -3"), "{svg}");
    }
}
