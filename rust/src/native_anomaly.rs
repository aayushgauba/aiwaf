//! Immutable request-history snapshots; framework route callbacks remain Python.
use aiwaf_core::{BehaviorAnalysis, RecentEntryInput, analyze_recent_behavior};
use pyo3::{exceptions::PyIndexError, prelude::*};
use std::sync::Arc;

type Entry = (f64, String, i32, f64);
type Stats = (f64, i32, f64, i32, i32, i32, bool);

fn stats(value: BehaviorAnalysis) -> Stats {
    (
        value.avg_kw_hits,
        value.max_404s,
        value.avg_burst,
        value.total_requests,
        value.scanning_404s,
        value.legitimate_404s,
        value.should_block,
    )
}

#[pyclass]
pub struct NativeAnomalyHistory {
    entries: Vec<Arc<Entry>>,
}

#[pymethods]
impl NativeAnomalyHistory {
    #[new]
    fn new(entries: Vec<Entry>) -> Self {
        Self {
            entries: entries.into_iter().map(Arc::new).collect(),
        }
    }
    fn __len__(&self) -> usize {
        self.entries.len()
    }
    fn __getitem__(&self, index: isize) -> PyResult<Entry> {
        let index = if index < 0 {
            self.entries.len() as isize + index
        } else {
            index
        };
        if index < 0 {
            return Err(PyIndexError::new_err("History index out of range"));
        }
        self.entries
            .get(index as usize)
            .map(|entry| (**entry).clone())
            .ok_or_else(|| PyIndexError::new_err("History index out of range"))
    }
    fn supports_ascii(&self) -> bool {
        self.entries.iter().all(|entry| entry.1.is_ascii())
    }
    fn trimmed(&self, py: Python<'_>, now: f64, window: f64) -> Self {
        py.allow_threads(|| Self {
            entries: self
                .entries
                .iter()
                .filter(|entry| now - entry.0 < window.max(1.0))
                .cloned()
                .collect(),
        })
    }
    fn appended(&self, now: f64, path: String, status: i32, response_time: f64) -> Self {
        let mut entries = self.entries.clone();
        entries.push(Arc::new((now, path, status, response_time)));
        Self { entries }
    }
    #[pyo3(signature = (model, path, status, response_time, now, kw_check, keywords, status_values, include_features=false))]
    fn predict_current(
        &self,
        py: Python<'_>,
        model: PyRef<'_, crate::IsolationForest>,
        path: String,
        status: i32,
        response_time: f64,
        now: f64,
        kw_check: bool,
        keywords: Vec<String>,
        status_values: Vec<String>,
        include_features: bool,
    ) -> (i32, Option<Vec<f64>>) {
        let forest = &model.inner;
        py.allow_threads(|| {
            let lower = path.to_ascii_lowercase();
            let hits = if kw_check {
                keywords
                    .iter()
                    .filter(|kw| !kw.is_empty() && lower.contains(kw.as_str()))
                    .count()
            } else {
                0
            };
            let status_index = status_values
                .iter()
                .position(|value| value == &status.to_string())
                .map(|i| i as i32)
                .unwrap_or(-1);
            let burst = self
                .entries
                .iter()
                .filter(|entry| now - entry.0 <= 10.0)
                .count();
            let missing = self.entries.iter().filter(|entry| entry.2 == 404).count();
            let features = vec![
                path.len() as f64,
                hits as f64,
                response_time,
                status_index as f64,
                burst as f64,
                missing as f64,
            ];
            let prediction = forest.predict(std::slice::from_ref(&features))[0];
            (
                prediction,
                if include_features {
                    Some(features)
                } else {
                    None
                },
            )
        })
    }
    fn recent_paths(&self, now: f64) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| now - entry.0 <= 300.0)
            .map(|entry| entry.1.clone())
            .collect()
    }
    fn analyze(
        &self,
        py: Python<'_>,
        now: f64,
        keywords: Vec<String>,
        checks: Vec<bool>,
    ) -> PyResult<Option<Stats>> {
        let recent: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| now - entry.0 <= 300.0)
            .collect();
        if recent.len() != checks.len() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Eligibility count mismatch",
            ));
        }
        let entries = recent
            .into_iter()
            .zip(checks)
            .map(|(entry, kw_check)| RecentEntryInput {
                path_lower: entry.1.to_ascii_lowercase(),
                timestamp: entry.0,
                status: entry.2,
                kw_check,
            })
            .collect();
        Ok(py.allow_threads(|| analyze_recent_behavior(entries, keywords).map(stats)))
    }
}

#[pyfunction]
fn analyze_recent_tuples(
    py: Python<'_>,
    entries: Vec<(String, f64, i32, bool)>,
    keywords: Vec<String>,
) -> Option<Stats> {
    let entries = entries
        .into_iter()
        .map(
            |(path_lower, timestamp, status, kw_check)| RecentEntryInput {
                path_lower,
                timestamp,
                status,
                kw_check,
            },
        )
        .collect();
    py.allow_threads(|| analyze_recent_behavior(entries, keywords).map(stats))
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeAnomalyHistory>()?;
    module.add_function(wrap_pyfunction!(analyze_recent_tuples, module)?)?;
    Ok(())
}
