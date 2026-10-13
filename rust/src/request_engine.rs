//! Compiled, callback-free SQL/keyword stage. Framework buffering/order stays outside.
use pyo3::prelude::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

type Decision = (
    Option<String>,
    i32,
    Option<String>,
    Vec<String>,
    Vec<String>,
);

#[pyclass]
pub struct NativeRequestEngine {
    sql: bool,
    max_bytes: usize,
    learning: bool,
    top_n: usize,
    file: String,
    counts: bool,
    static_kw: HashSet<String>,
    legitimate: HashSet<String>,
    exempt: HashSet<String>,
    prefixes: Vec<String>,
    malicious: HashSet<String>,
    processed: AtomicU64,
}

fn decode_ascii(input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let value = input[i];
        if value == b'%' && i + 2 < input.len() {
            let a = (input[i + 1] as char).to_digit(16);
            let b = (input[i + 2] as char).to_digit(16);
            if let (Some(a), Some(b)) = (a, b) {
                output.push((a * 16 + b) as u8);
                i += 3;
                continue;
            }
        }
        output.push(if value == b'+' { b' ' } else { value });
        i += 1;
    }
    output.is_ascii().then_some(output)
}

#[pymethods]
impl NativeRequestEngine {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        sql: bool,
        max_bytes: usize,
        learning: bool,
        top_n: usize,
        file: String,
        counts: bool,
        static_kw: HashSet<String>,
        legitimate: HashSet<String>,
        exempt: HashSet<String>,
        prefixes: Vec<String>,
        malicious: HashSet<String>,
    ) -> Self {
        Self {
            sql,
            max_bytes,
            learning,
            top_n,
            file,
            counts,
            static_kw,
            legitimate,
            exempt,
            prefixes,
            malicious,
            processed: AtomicU64::new(0),
        }
    }

    #[getter]
    fn processed_requests(&self) -> u64 {
        self.processed.load(Ordering::Relaxed)
    }

    #[pyo3(signature = (query, body, path, query_context, query_keys, exists, added_date, now))]
    fn evaluate(
        &self,
        py: Python<'_>,
        query: Vec<u8>,
        body: Option<Vec<u8>>,
        path: String,
        query_context: String,
        query_keys: HashSet<String>,
        exists: bool,
        added_date: String,
        now: f64,
    ) -> PyResult<Option<Decision>> {
        if !path.is_ascii() || !now.is_finite() {
            return Ok(None);
        }
        if self.sql {
            // Structured bodies and non-ASCII decoding use the bounded existing
            // inspector. Return before any learning/write on unsupported inputs.
            if body.as_ref().is_some_and(|b| !b.is_empty())
                || !query.is_ascii()
                || query.contains(&0)
            {
                return Ok(None);
            }
            if query.len() > self.max_bytes {
                self.processed.fetch_add(1, Ordering::Relaxed);
                return Ok(Some((
                    Some("payload_inspection_limit".into()),
                    413,
                    None,
                    vec![],
                    vec![],
                )));
            }
            let Some(decoded) = decode_ascii(&query).and_then(|q| decode_ascii(&q)) else {
                return Ok(None);
            };
            let text = String::from_utf8(decoded).expect("ASCII decoder");
            if let Some(rule) = py.allow_threads(|| crate::runtime_policy::sql_signature(&text)) {
                self.processed.fetch_add(1, Ordering::Relaxed);
                return Ok(Some((Some(rule), 403, None, vec![], vec![])));
            }
            if text.trim_start().starts_with(['{', '[']) {
                return Ok(None);
            }
        }
        let dynamic = if self.learning {
            if self.counts {
                let raw = crate::csv_runtime::csv_kv_get(
                    py,
                    self.file.clone(),
                    "keyword_counts".into(),
                    now,
                )?;
                match raw {
                    None => HashSet::new(),
                    Some(raw) => {
                        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
                            return Ok(None);
                        };
                        if value.is_null() {
                            HashSet::new()
                        } else {
                            let Some(values) = value.as_object() else {
                                return Ok(None);
                            };
                            if values.len() > self.top_n || values.values().any(|v| !v.is_i64()) {
                                return Ok(None);
                            }
                            values.keys().cloned().collect()
                        }
                    }
                }
            } else {
                if !std::path::Path::new(&self.file).is_file() {
                    return Ok(None);
                }
                let values = crate::csv_runtime::csv_read_set(
                    py,
                    self.file.clone(),
                    "keyword".into(),
                    true,
                )?;
                // Selecting a subset of a Python set has process-specific order.
                // Preserve that API through fallback rather than inventing a rank.
                if values.len() > self.top_n {
                    return Ok(None);
                }
                values
            }
        } else {
            HashSet::new()
        };
        let decision = crate::runtime_policy::policy_keyword_flask(
            py,
            path,
            query_context,
            query_keys,
            exists,
            self.learning,
            self.static_kw.clone(),
            dynamic,
            self.legitimate.clone(),
            self.exempt.clone(),
            self.prefixes.clone(),
            self.malicious.clone(),
        );
        if self.learning && !decision.1.is_empty() {
            if self.counts {
                crate::csv_runtime::csv_runtime_keywords_update(
                    py,
                    self.file.clone(),
                    decision.1.iter().map(|kw| (kw.clone(), 1)).collect(),
                    HashSet::new(),
                    now,
                )?;
            } else {
                crate::csv_runtime::csv_keywords_update(
                    py,
                    self.file.clone(),
                    added_date,
                    decision.1.clone(),
                    HashSet::new(),
                )?;
            }
        }
        self.processed.fetch_add(1, Ordering::Relaxed);
        Ok(Some((None, 403, decision.0, decision.1, decision.2)))
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeRequestEngine>()?;
    Ok(())
}
