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
    #[serde(default)]
    pub buckets: Vec<(String, u64)>,
}
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub format: String,
    pub top: Option<usize>,
    pub percent: bool,
    pub rate: bool,
    pub elapsed: f64,
    pub baseline: Vec<Row>,
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
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("comparison requires a poortrace JSON report: {e}"))
}
fn identity(row: &Row) -> String {
    serde_json::to_string(&(&row.map, &row.keys)).unwrap()
}

pub fn render(rows: &[Row], options: &Options) -> Result<String> {
    let mut rows = rows.to_vec();
    let mut old = BTreeMap::new();
    for row in &options.baseline {
        old.insert(identity(row), row.value);
    }
    if !options.baseline.is_empty() {
        for row in &mut rows {
            row.value = row
                .value
                .saturating_sub(old.remove(&identity(row)).unwrap_or(0));
        }
        for row in &options.baseline {
            if old.remove(&identity(row)).is_some() {
                let mut missing = row.clone();
                missing.value = missing.value.saturating_neg();
                rows.push(missing);
            }
        }
    }
    let totals: BTreeMap<String, f64> = rows.iter().fold(BTreeMap::new(), |mut totals, row| {
        *totals.entry(row.map.clone()).or_default() += (row.value as f64).abs();
        totals
    });
    if options.top.is_some() {
        rows.sort_by(|a, b| {
            a.map
                .cmp(&b.map)
                .then_with(|| b.value.unsigned_abs().cmp(&a.value.unsigned_abs()))
        });
        let mut seen = BTreeMap::new();
        rows.retain(|row| {
            let count = seen.entry(row.map.clone()).or_insert(0);
            *count += 1;
            *count <= options.top.unwrap()
        });
    }
    match options.format.as_str() {
        "json" => serde_json::to_string_pretty(&rows)
            .map(|text| text + "\n")
            .map_err(|e| e.to_string()),
        "folded" | "speedscope" | "flamegraph" => profile(&rows, &options.format),
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
                if !row.buckets.is_empty() {
                    out.push_str(":\n");
                    for (label, count) in &row.buckets {
                        out.push_str(&format!("  {label}: {count}\n"));
                    }
                    continue;
                }
                out.push_str(&format!(": {}", row.value));
                if options.percent {
                    out.push_str(&format!(
                        " ({:.2}%)",
                        row.value as f64 * 100.0 / totals[&row.map].max(1.0)
                    ));
                }
                if options.rate {
                    out.push_str(&format!(
                        " ({:.3}/s)",
                        row.value as f64 / options.elapsed.max(1e-9)
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

fn stacks(rows: &[Row]) -> Result<Vec<(Vec<String>, u64)>> {
    let mut output = Vec::new();
    for row in rows {
        if !row.keys.iter().any(|key| key.kind == "stack") {
            continue;
        }
        if row.value < 0 {
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
        output.push((frames, row.value as u64));
    }
    Ok(output)
}
fn profile(rows: &[Row], format: &str) -> Result<String> {
    let stacks = stacks(rows)?;
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
        children: BTreeMap<String, Node>,
    }
    let mut root = Node::default();
    let mut depth = 0;
    for (frames, weight) in stacks {
        root.weight += weight as f64;
        depth = depth.max(frames.len());
        let mut node = &mut root;
        for frame in frames {
            node = node.children.entry(frame).or_default();
            node.weight += weight as f64;
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
            let color = name
                .bytes()
                .fold(0u32, |sum, b| sum.wrapping_mul(31).wrapping_add(b as u32))
                % 70;
            out.push_str(&format!("<g><title>{}: {}</title><rect x=\"{at:.3}\" y=\"{y}\" width=\"{w:.3}\" height=\"19\" fill=\"hsl({color},85%,65%)\" stroke=\"white\"/>", escape(name), child.weight));
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
            map: "cpu".into(),
            keys: vec![Key {
                kind: "stack".into(),
                value: "    leaf\n    root\n".into(),
            }],
            value: 5,
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
}
