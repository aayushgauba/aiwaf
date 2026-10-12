//! Batch training preparation. Framework route resolution stays in Python.
use pyo3::{exceptions::PyValueError, prelude::*};
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

type Fields = (String, String, String, String, f64);

#[pyclass]
struct TrainingCSVReader {
    reader: csv::Reader<Box<dyn std::io::Read + Send>>,
    indices: [usize; 4],
    elapsed: Option<usize>,
    milliseconds: bool,
}
#[pymethods]
impl TrainingCSVReader {
    #[new]
    fn new(py: Python<'_>, path: String) -> PyResult<Self> {
        py.allow_threads(|| {
            let file = std::fs::File::open(&path)
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
            let input: Box<dyn std::io::Read + Send> = if path.ends_with(".gz") {
                Box::new(flate2::read::MultiGzDecoder::new(file))
            } else {
                Box::new(file)
            };
            let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(input);
            let headers = reader
                .headers()
                .map_err(|e| PyValueError::new_err(e.to_string()))?
                .clone();
            let mut indices = [0; 4];
            for (i, key) in ["ip", "timestamp", "path", "status_code"]
                .iter()
                .enumerate()
            {
                indices[i] = headers.iter().position(|v| v == *key).ok_or_else(|| {
                    PyValueError::new_err(format!("Missing training CSV column: {key}"))
                })?;
            }
            let milliseconds = headers.iter().any(|v| v == "response_time_ms");
            let elapsed = headers.iter().position(|v| {
                v == if milliseconds {
                    "response_time_ms"
                } else {
                    "response_time"
                }
            });
            Ok(Self {
                reader,
                indices,
                elapsed,
                milliseconds,
            })
        })
    }
    fn next_batch(&mut self, py: Python<'_>, size: usize) -> PyResult<(usize, Vec<Fields>)> {
        if size == 0 || size > 65536 {
            return Err(PyValueError::new_err("Batch size must be 1..65536"));
        }
        py.allow_threads(|| {
            let (mut count, mut output) = (0, Vec::new());
            let mut row = csv::StringRecord::new();
            while count < size
                && self
                    .reader
                    .read_record(&mut row)
                    .map_err(|e| PyValueError::new_err(e.to_string()))?
            {
                count += 1;
                let Some(ip) = row.get(self.indices[0]) else {
                    continue;
                };
                let Some(ts) = row.get(self.indices[1]) else {
                    continue;
                };
                let Some(path) = row.get(self.indices[2]) else {
                    continue;
                };
                let Some(status) = row.get(self.indices[3]) else {
                    continue;
                };
                let Some(elapsed) = self
                    .elapsed
                    .and_then(|i| row.get(i))
                    .unwrap_or("0")
                    .trim()
                    .parse::<f64>()
                    .ok()
                else {
                    continue;
                };
                output.push((
                    ip.into(),
                    ts.into(),
                    path.into(),
                    status.into(),
                    if self.milliseconds {
                        elapsed / 1000.0
                    } else {
                        elapsed
                    },
                ));
            }
            Ok((count, output))
        })
    }
}
static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
fn patterns() -> &'static Vec<Regex> {
    PATTERNS.get_or_init(|| [
        r#"(\S+).*\[(.*?)\].*"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP/.*?" (\d{3}).*?"(.*?)" "(.*?)".*?response-time=(\d+\.\d+)"#,
        r#"(\S+).*\[(.*?)\].*"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP/.*?" (\d{3}) (\d+) "(.*?)" "(.*?)""#,
        r#"(\S+).*\[(.*?)\].*"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP/.*?" (\d{3}) (\d+)"#,
    ].iter().map(|s| Regex::new(s).unwrap()).collect())
}

#[pyfunction]
fn training_parse_lines(py: Python<'_>, lines: Vec<String>) -> Vec<Vec<Fields>> {
    py.allow_threads(|| {
        lines
            .iter()
            .map(|line| {
                patterns()
                    .iter()
                    .filter_map(|pattern| {
                        let m = pattern.captures(line)?;
                        // Preserve Python's unusual "first float-like group" rule exactly.
                        let rt = (5..m.len())
                            .filter_map(|i| m.get(i))
                            .map(|v| v.as_str())
                            .filter(|s| s.contains('.'))
                            .find_map(|s| s.parse::<f64>().ok())
                            .unwrap_or(0.0);
                        Some((m[1].into(), m[2].into(), m[3].into(), m[4].into(), rt))
                    })
                    .collect()
            })
            .collect()
    })
}

#[pyfunction]
fn training_parse_csv(py: Python<'_>, text: String) -> PyResult<Vec<Fields>> {
    py.allow_threads(|| {
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_reader(text.as_bytes());
        let headers = reader
            .headers()
            .map_err(|e| PyValueError::new_err(e.to_string()))?
            .clone();
        let index = |key: &str| headers.iter().position(|v| v == key);
        let (Some(ip), Some(ts), Some(path), Some(status)) = (
            index("ip"),
            index("timestamp"),
            index("path"),
            index("status_code"),
        ) else {
            return Err(PyValueError::new_err("Missing training CSV columns"));
        };
        let rt = index("response_time_ms");
        let mut output = Vec::new();
        for row in reader.records() {
            let row = row.map_err(|e| PyValueError::new_err(e.to_string()))?;
            let (Some(ip), Some(ts), Some(path), Some(status)) =
                (row.get(ip), row.get(ts), row.get(path), row.get(status))
            else {
                continue;
            };
            let elapsed = match rt.and_then(|i| row.get(i)).unwrap_or("0").parse::<f64>() {
                Ok(value) => value / 1000.0,
                Err(_) => continue,
            };
            output.push((ip.into(), ts.into(), path.into(), status.into(), elapsed));
        }
        Ok(output)
    })
}

#[pyfunction]
fn training_aggregate(
    py: Python<'_>,
    records: Vec<(String, String, String)>,
    exempt: HashSet<String>,
) -> (
    HashMap<String, usize>,
    HashMap<String, usize>,
    HashMap<String, Vec<usize>>,
) {
    py.allow_threads(|| {
        let (mut errors, mut exempt_errors, mut indices) =
            (HashMap::new(), HashMap::new(), HashMap::new());
        for (i, (ip, path, status)) in records.into_iter().enumerate() {
            indices.entry(ip.clone()).or_insert_with(Vec::new).push(i);
            if status == "404" {
                let target = if exempt.contains(&path) {
                    &mut exempt_errors
                } else {
                    &mut errors
                };
                *target.entry(ip).or_insert(0) += 1;
            }
        }
        (errors, exempt_errors, indices)
    })
}

fn malicious(path: &str, status: &str, static_kw: &HashSet<String>) -> bool {
    let segments: Vec<_> = path
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .collect();
    segments.iter().filter(|s| static_kw.contains(**s)).count() > 1
        || [
            "../",
            "..\\",
            ".env",
            "wp-admin",
            "phpmyadmin",
            "config",
            "backup",
            "database",
            "mysql",
            "passwd",
            "shadow",
            "xmlrpc",
            "shell",
            "cmd",
            "exec",
            "eval",
            "system",
            "union+select",
            "drop+table",
            "<script",
            "javascript:",
            "${",
            "{{",
            "onload=",
            "onerror=",
            "file://",
            "http://",
            "%2e%2e",
            "%252e",
            "%c0%ae",
            "%3c%73%63%72%69%70%74",
        ]
        .iter()
        .any(|s| path.contains(s))
        || (status == "404"
            && (path.len() > 50
                || path.matches('/').count() > 10
                || path.chars().any(|c| "<>{}$`".contains(c))))
}

#[pyfunction]
fn training_keywords(
    py: Python<'_>,
    records: Vec<(String, String)>,
    known: HashSet<String>,
    exempt: HashSet<String>,
    static_kw: HashSet<String>,
    legitimate: HashSet<String>,
    top_n: i64,
) -> Option<Vec<(String, usize, Vec<String>)>> {
    if records.iter().any(|(p, _)| !p.is_ascii()) {
        return None;
    }
    py.allow_threads(|| {
        let (mut counts, mut order) = (HashMap::<String, usize>::new(), Vec::<String>::new());
        for (path, status) in &records {
            if !(status.starts_with('4') || status.starts_with('5'))
                || known.contains(path)
                || exempt.contains(path)
            {
                continue;
            }
            let lower = path.to_ascii_lowercase();
            if !malicious(&lower, status, &static_kw) {
                continue;
            }
            for token in lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                if token.len() > 3 && !static_kw.contains(token) && !legitimate.contains(token) {
                    if !counts.contains_key(token) {
                        order.push(token.to_owned());
                    }
                    *counts.entry(token.to_owned()).or_default() += 1;
                }
            }
        }
        // Stable ties match Counter.most_common's first-observed order.
        order.sort_by_key(|s| std::cmp::Reverse(counts[s]));
        let mut result = Vec::new();
        for token in order.into_iter().take(top_n.max(0) as usize) {
            let count = counts[&token];
            let examples: Vec<_> = records
                .iter()
                .filter(|(p, s)| {
                    p.to_ascii_lowercase().contains(&token)
                        && (s.starts_with('4') || s.starts_with('5'))
                        && !known.contains(p)
                })
                .map(|(p, _)| p.clone())
                .collect();
            if count >= 2
                && examples
                    .iter()
                    .take(3)
                    .any(|p| malicious(&p.to_ascii_lowercase(), "404", &static_kw))
            {
                result.push((token, count, examples.into_iter().take(2).collect()));
            }
        }
        Some(result)
    })
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TrainingCSVReader>()?;
    m.add_function(wrap_pyfunction!(training_parse_lines, m)?)?;
    m.add_function(wrap_pyfunction!(training_parse_csv, m)?)?;
    m.add_function(wrap_pyfunction!(training_aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(training_keywords, m)?)?;
    m.add_function(wrap_pyfunction!(training_anomaly_stats, m)?)?;
    m.add_function(wrap_pyfunction!(training_keyword_counts, m)?)?;
    Ok(())
}

/// Streaming keyword counts retain first-observed order and at most five examples.
#[pyfunction]
fn training_keyword_counts(
    py: Python<'_>,
    records: Vec<(String, String)>,
    known: HashSet<String>,
    exempt: HashSet<String>,
    static_kw: HashSet<String>,
    legitimate: HashSet<String>,
) -> Option<Vec<(String, usize, Vec<String>)>> {
    if records.iter().any(|(p, _)| !p.is_ascii()) {
        return None;
    }
    py.allow_threads(|| {
        let mut counts = HashMap::<String, (usize, Vec<String>)>::new();
        let mut order = Vec::new();
        for (path, status) in records {
            if !(status.starts_with('4') || status.starts_with('5'))
                || known.contains(&path)
                || exempt.contains(&path)
            {
                continue;
            }
            let lower = path.to_ascii_lowercase();
            if !malicious(&lower, &status, &static_kw) {
                continue;
            }
            for token in lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                if token.len() > 3 && !static_kw.contains(token) && !legitimate.contains(token) {
                    if !counts.contains_key(token) {
                        order.push(token.to_owned());
                    }
                    let entry = counts.entry(token.to_owned()).or_default();
                    entry.0 += 1;
                    if entry.1.len() < 5 {
                        entry.1.push(path.clone());
                    }
                }
            }
        }
        Some(
            order
                .into_iter()
                .map(|token| {
                    let (count, examples) = counts.remove(&token).unwrap();
                    (token, count, examples)
                })
                .collect(),
        )
    })
}

#[pyfunction]
fn training_anomaly_stats(
    py: Python<'_>,
    rows: Vec<(String, f64, f64, f64)>,
    predictions: Vec<i32>,
) -> PyResult<HashMap<String, (f64, f64, f64, usize)>> {
    if rows.len() != predictions.len() {
        return Err(PyValueError::new_err("Prediction count mismatch"));
    }
    py.allow_threads(|| {
        let mut groups = HashMap::<String, (f64, usize, f64, f64, usize, usize, bool)>::new();
        for ((ip, kw, errors, burst), prediction) in rows.into_iter().zip(predictions) {
            let g = groups
                .entry(ip)
                .or_insert((0.0, 0, f64::NAN, 0.0, 0, 0, false));
            if !kw.is_nan() {
                g.0 += kw;
                g.1 += 1;
            }
            if !errors.is_nan() {
                g.2 = g.2.max(errors);
            }
            if !burst.is_nan() {
                g.3 += burst;
                g.4 += 1;
            }
            g.5 += 1;
            g.6 |= prediction == -1;
        }
        Ok(groups
            .into_iter()
            .filter(|(_, g)| g.6)
            .map(|(ip, g)| (ip, (g.0 / g.1 as f64, g.2, g.3 / g.4 as f64, g.5)))
            .collect())
    })
}
