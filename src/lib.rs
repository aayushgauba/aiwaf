use once_cell::sync::Lazy;
use pyo3::exceptions::PyKeyError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use pyo3::FromPyObject;
use regex::Regex;
use std::collections::HashMap;

static LEGITIMATE_BOTS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"googlebot").unwrap(),
        Regex::new(r"bingbot").unwrap(),
        Regex::new(r"slurp").unwrap(),
        Regex::new(r"duckduckbot").unwrap(),
        Regex::new(r"baiduspider").unwrap(),
        Regex::new(r"yandexbot").unwrap(),
        Regex::new(r"facebookexternalhit").unwrap(),
        Regex::new(r"twitterbot").unwrap(),
        Regex::new(r"linkedinbot").unwrap(),
        Regex::new(r"whatsapp").unwrap(),
        Regex::new(r"telegrambot").unwrap(),
        Regex::new(r"applebot").unwrap(),
        Regex::new(r"pingdom").unwrap(),
        Regex::new(r"uptimerobot").unwrap(),
        Regex::new(r"statuscake").unwrap(),
        Regex::new(r"site24x7").unwrap(),
    ]
});

static SUSPICIOUS_UA: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        (r"bot", Regex::new(r"bot").unwrap()),
        (r"crawler", Regex::new(r"crawler").unwrap()),
        (r"spider", Regex::new(r"spider").unwrap()),
        (r"scraper", Regex::new(r"scraper").unwrap()),
        (r"curl", Regex::new(r"curl").unwrap()),
        (r"wget", Regex::new(r"wget").unwrap()),
        (r"python", Regex::new(r"python").unwrap()),
        (r"java", Regex::new(r"java").unwrap()),
        (r"node", Regex::new(r"node").unwrap()),
        (r"go-http", Regex::new(r"go-http").unwrap()),
        (r"axios", Regex::new(r"axios").unwrap()),
        (r"okhttp", Regex::new(r"okhttp").unwrap()),
        (r"libwww", Regex::new(r"libwww").unwrap()),
        (r"lwp-trivial", Regex::new(r"lwp-trivial").unwrap()),
        (r"mechanize", Regex::new(r"mechanize").unwrap()),
        (r"requests", Regex::new(r"requests").unwrap()),
        (r"urllib", Regex::new(r"urllib").unwrap()),
        (r"httpie", Regex::new(r"httpie").unwrap()),
        (r"postman", Regex::new(r"postman").unwrap()),
        (r"insomnia", Regex::new(r"insomnia").unwrap()),
        (r"^$", Regex::new(r"^$").unwrap()),
        (r"mozilla/4\.0$", Regex::new(r"mozilla/4\.0$").unwrap()),
    ]
});

fn get_header(headers: &Bound<'_, PyDict>, key: &str) -> Option<String> {
    headers
        .get_item(key)
        .ok()
        .flatten()
        .and_then(|v| v.str().ok())
        .and_then(|s| s.to_str().ok().map(|v| v.to_string()))
}

fn has_header(headers: &Bound<'_, PyDict>, key: &str) -> bool {
    match get_header(headers, key) {
        Some(value) => !value.is_empty(),
        None => false,
    }
}

fn check_user_agent(user_agent: &str) -> Option<String> {
    if user_agent.is_empty() {
        return Some("Empty user agent".to_string());
    }

    let ua_lower = user_agent.to_lowercase();

    for legit in LEGITIMATE_BOTS.iter() {
        if legit.is_match(&ua_lower) {
            return None;
        }
    }

    for (pattern, regex) in SUSPICIOUS_UA.iter() {
        if regex.is_match(&ua_lower) {
            return Some(format!("Pattern: {}", pattern));
        }
    }

    if user_agent.len() < 10 {
        return Some("Too short".to_string());
    }
    if user_agent.len() > 500 {
        return Some("Too long".to_string());
    }

    None
}

#[pyfunction]
fn validate_headers(headers: Bound<'_, PyDict>) -> PyResult<Option<String>> {
    let mut missing = Vec::new();
    if !has_header(&headers, "HTTP_USER_AGENT") {
        missing.push("user-agent".to_string());
    }
    if !has_header(&headers, "HTTP_ACCEPT") {
        missing.push("accept".to_string());
    }

    if !missing.is_empty() {
        return Ok(Some(format!(
            "Missing required headers: {}",
            missing.join(", ")
        )));
    }

    let user_agent = get_header(&headers, "HTTP_USER_AGENT").unwrap_or_default();
    if let Some(reason) = check_user_agent(&user_agent) {
        return Ok(Some(format!("Suspicious user agent: {}", reason)));
    }

    let server_protocol = get_header(&headers, "SERVER_PROTOCOL").unwrap_or_default();
    let accept = get_header(&headers, "HTTP_ACCEPT").unwrap_or_default();
    let accept_language = get_header(&headers, "HTTP_ACCEPT_LANGUAGE").unwrap_or_default();
    let accept_encoding = get_header(&headers, "HTTP_ACCEPT_ENCODING").unwrap_or_default();
    let connection = get_header(&headers, "HTTP_CONNECTION").unwrap_or_default();

    if server_protocol.starts_with("HTTP/2") && user_agent.to_lowercase().contains("mozilla/4.0") {
        return Ok(Some(
            "Suspicious headers: HTTP/2 with old browser user agent".to_string(),
        ));
    }
    if !user_agent.is_empty() && accept.is_empty() {
        return Ok(Some(
            "Suspicious headers: User-Agent present but no Accept header".to_string(),
        ));
    }
    if accept == "*/*" && accept_language.is_empty() && accept_encoding.is_empty() {
        return Ok(Some(
            "Suspicious headers: Generic Accept header without language/encoding".to_string(),
        ));
    }
    if !user_agent.is_empty()
        && accept_language.is_empty()
        && accept_encoding.is_empty()
        && connection.is_empty()
    {
        return Ok(Some(
            "Suspicious headers: Missing all browser-standard headers".to_string(),
        ));
    }
    if !user_agent.is_empty()
        && server_protocol == "HTTP/1.0"
        && user_agent.to_lowercase().contains("chrome")
    {
        return Ok(Some(
            "Suspicious headers: Modern browser with HTTP/1.0".to_string(),
        ));
    }

    let mut score = 0;
    if has_header(&headers, "HTTP_USER_AGENT") {
        score += 2;
    }
    if has_header(&headers, "HTTP_ACCEPT") {
        score += 2;
    }

    for header in [
        "HTTP_ACCEPT_LANGUAGE",
        "HTTP_ACCEPT_ENCODING",
        "HTTP_CONNECTION",
        "HTTP_CACHE_CONTROL",
    ] {
        if has_header(&headers, header) {
            score += 1;
        }
    }

    if !accept_language.is_empty() && !accept_encoding.is_empty() {
        score += 1;
    }
    if connection == "keep-alive" {
        score += 1;
    }
    if accept.contains("text/html") && accept.contains("application/xml") {
        score += 1;
    }

    if score < 3 {
        return Ok(Some(format!("Low header quality score: {}", score)));
    }

    Ok(None)
}

#[derive(Clone)]
struct FeatureRecordInput {
    ip: String,
    path_lower: String,
    path_len: usize,
    timestamp: f64,
    response_time: f64,
    status_idx: i32,
    kw_check: bool,
    total_404: i32,
}

impl<'py> FromPyObject<'py> for FeatureRecordInput {
    fn extract(ob: &'py PyAny) -> PyResult<Self> {
        let dict: &PyDict = ob.downcast()?;

        let get_required = |key: &str| -> PyResult<&PyAny> {
            dict.get_item(key)?
                .ok_or_else(|| PyErr::new::<PyKeyError, _>(key.to_string()))
        };

        Ok(Self {
            ip: get_required("ip")?.extract()?,
            path_lower: get_required("path_lower")?.extract()?,
            path_len: get_required("path_len")?.extract()?,
            timestamp: get_required("timestamp")?.extract()?,
            response_time: get_required("response_time")?.extract()?,
            status_idx: get_required("status_idx")?.extract()?,
            kw_check: get_required("kw_check")?.extract()?,
            total_404: get_required("total_404")?.extract()?,
        })
    }
}

#[derive(Clone)]
struct RecentEntryInput {
    path_lower: String,
    timestamp: f64,
    status: i32,
    kw_check: bool,
}

impl<'py> FromPyObject<'py> for RecentEntryInput {
    fn extract(ob: &'py PyAny) -> PyResult<Self> {
        let dict: &PyDict = ob.downcast()?;

        let get_required = |key: &str| -> PyResult<&PyAny> {
            dict.get_item(key)?
                .ok_or_else(|| PyErr::new::<PyKeyError, _>(key.to_string()))
        };

        Ok(Self {
            path_lower: get_required("path_lower")?.extract()?,
            timestamp: get_required("timestamp")?.extract()?,
            status: get_required("status")?.extract()?,
            kw_check: get_required("kw_check")?.extract()?,
        })
    }
}

fn build_timestamp_index(records: &[FeatureRecordInput]) -> HashMap<String, Vec<f64>> {
    let mut map: HashMap<String, Vec<f64>> = HashMap::new();
    for rec in records {
        map.entry(rec.ip.clone())
            .or_default()
            .push(rec.timestamp);
    }
    for timestamps in map.values_mut() {
        timestamps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    }
    map
}

fn count_burst(timestamps: Option<&Vec<f64>>, current: f64) -> i32 {
    if let Some(ts) = timestamps {
        let min_ts = current - 10.0;
        ts.iter()
            .filter(|value| **value >= min_ts && **value <= current)
            .count() as i32
    } else {
        0
    }
}

fn keyword_hits(path_lower: &str, keywords: &[String], enabled: bool) -> i32 {
    if !enabled {
        return 0;
    }
    keywords
        .iter()
        .filter(|kw| path_lower.contains(kw.as_str()))
        .count() as i32
}

fn lower_bound(values: &[f64], target: f64) -> usize {
    let mut left = 0usize;
    let mut right = values.len();
    while left < right {
        let mid = (left + right) / 2;
        if values[mid] < target {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    left
}

fn upper_bound(values: &[f64], target: f64) -> usize {
    let mut left = 0usize;
    let mut right = values.len();
    while left < right {
        let mid = (left + right) / 2;
        if values[mid] <= target {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    left
}

fn is_scanning_path(path_lower: &str) -> bool {
    let scanning_patterns = [
        "wp-admin",
        "wp-content",
        "wp-includes",
        "wp-config",
        "xmlrpc.php",
        "admin",
        "phpmyadmin",
        "adminer",
        "config",
        "configuration",
        "settings",
        "setup",
        "install",
        "installer",
        "backup",
        "database",
        "db",
        "mysql",
        "sql",
        "dump",
        ".env",
        ".git",
        ".htaccess",
        ".htpasswd",
        "passwd",
        "shadow",
        "robots.txt",
        "sitemap.xml",
        "cgi-bin",
        "scripts",
        "shell",
        "cmd",
        "exec",
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
        ".cgi",
        ".pl",
    ];

    if scanning_patterns.iter().any(|pat| path_lower.contains(pat)) {
        return true;
    }
    if path_lower.contains("../") || path_lower.contains("..\\") {
        return true;
    }
    let encoded = ["%2e%2e", "%252e", "%c0%ae"];
    if encoded.iter().any(|enc| path_lower.contains(enc)) {
        return true;
    }
    false
}

#[pyfunction]
fn extract_features<'py>(
    py: Python<'py>,
    records: Vec<FeatureRecordInput>,
    static_keywords: Vec<String>,
) -> PyResult<Vec<Py<PyDict>>> {
    if records.is_empty() {
        return Ok(Vec::new());
    }

    let keywords: Vec<String> = static_keywords
        .into_iter()
        .map(|kw| kw.to_lowercase())
        .collect();

    let timestamp_index = build_timestamp_index(&records);
    let mut output = Vec::with_capacity(records.len());

    for rec in records.into_iter() {
        let timestamps = timestamp_index.get(&rec.ip);
        let burst = count_burst(timestamps, rec.timestamp);
        let kw = keyword_hits(&rec.path_lower, &keywords, rec.kw_check);

        let feature = PyDict::new_bound(py);
        feature.set_item("ip", rec.ip.clone())?;
        feature.set_item("path_len", rec.path_len)?;
        feature.set_item("kw_hits", kw)?;
        feature.set_item("resp_time", rec.response_time)?;
        feature.set_item("status_idx", rec.status_idx)?;
        feature.set_item("burst_count", burst)?;
        feature.set_item("total_404", rec.total_404)?;
        output.push(feature.into());
    }

    Ok(output)
}

#[pyfunction]
fn analyze_recent_behavior<'py>(
    py: Python<'py>,
    entries: Vec<RecentEntryInput>,
    static_keywords: Vec<String>,
) -> PyResult<Option<Py<PyDict>>> {
    if entries.is_empty() {
        return Ok(None);
    }

    let keywords: Vec<String> = static_keywords
        .into_iter()
        .map(|kw| kw.to_lowercase())
        .collect();
    let mut timestamps: Vec<f64> = entries.iter().map(|e| e.timestamp).collect();
    timestamps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let mut total_kw_hits = 0f64;
    let mut total_burst = 0f64;
    let mut max_404s = 0i32;
    let mut scanning_404s = 0i32;

    for entry in entries.iter() {
        if entry.status == 404 {
            max_404s += 1;
            if is_scanning_path(&entry.path_lower) {
                scanning_404s += 1;
            }
        }
        let kw = keyword_hits(&entry.path_lower, &keywords, entry.kw_check);
        total_kw_hits += kw as f64;

        let lower = lower_bound(&timestamps, entry.timestamp - 10.0);
        let upper = upper_bound(&timestamps, entry.timestamp + 10.0);
        let burst = (upper.saturating_sub(lower)) as i32;
        total_burst += burst as f64;
    }

    let total_requests = entries.len() as i32;
    let avg_kw_hits = if total_requests > 0 {
        total_kw_hits / total_requests as f64
    } else {
        0.0
    };
    let avg_burst = if total_requests > 0 {
        total_burst / total_requests as f64
    } else {
        0.0
    };
    let legitimate_404s = (max_404s - scanning_404s).max(0);

    let mut should_block = true;
    if max_404s == 0 && avg_kw_hits == 0.0 && scanning_404s == 0 {
        should_block = false;
    } else if avg_kw_hits < 3.0
        && scanning_404s < 5
        && legitimate_404s < 20
        && avg_burst < 25.0
        && total_requests < 150
    {
        should_block = false;
    }

    let result = PyDict::new_bound(py);
    result.set_item("avg_kw_hits", avg_kw_hits)?;
    result.set_item("max_404s", max_404s)?;
    result.set_item("avg_burst", avg_burst)?;
    result.set_item("total_requests", total_requests)?;
    result.set_item("scanning_404s", scanning_404s)?;
    result.set_item("legitimate_404s", legitimate_404s)?;
    result.set_item("should_block", should_block)?;

    Ok(Some(result.into()))
}

#[pymodule]
fn aiwaf_rust(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(validate_headers, m)?)?;
    m.add_function(wrap_pyfunction!(extract_features, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_recent_behavior, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;

    fn dict_from_pairs(py: Python<'_>, pairs: &[(&str, &str)]) -> Bound<'_, PyDict> {
        let dict = PyDict::new_bound(py);
        for (k, v) in pairs {
            dict.set_item(*k, *v).unwrap();
        }
        dict
    }

    #[test]
    fn validate_headers_blocks_missing_required() {
        Python::with_gil(|py| {
            let headers = dict_from_pairs(py, &[("HTTP_USER_AGENT", "Mozilla/5.0")]);
            let result = validate_headers(headers).unwrap();
            assert!(matches!(result, Some(msg) if msg.contains("Missing required headers")));
        });
    }

    #[test]
    fn validate_headers_blocks_suspicious_user_agent() {
        Python::with_gil(|py| {
            let headers = dict_from_pairs(py, &[
                ("HTTP_USER_AGENT", "python-requests/2.25.1"),
                ("HTTP_ACCEPT", "*/*"),
            ]);
            let result = validate_headers(headers).unwrap();
            assert!(matches!(result, Some(msg) if msg.contains("Suspicious user agent")));
        });
    }

    #[test]
    fn validate_headers_blocks_suspicious_combinations() {
        Python::with_gil(|py| {
            let headers = dict_from_pairs(py, &[
                ("HTTP_USER_AGENT", "Mozilla/4.0"),
                ("HTTP_ACCEPT", "text/html"),
                ("SERVER_PROTOCOL", "HTTP/2"),
            ]);
            let result = validate_headers(headers).unwrap();
            assert!(matches!(result, Some(msg) if msg.contains("Suspicious headers")));
        });
    }

    #[test]
    fn validate_headers_allows_legit_browser() {
        Python::with_gil(|py| {
            let headers = dict_from_pairs(py, &[
                ("HTTP_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
                ("HTTP_ACCEPT", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                ("HTTP_ACCEPT_LANGUAGE", "en-US,en;q=0.5"),
                ("HTTP_ACCEPT_ENCODING", "gzip, deflate"),
                ("HTTP_CONNECTION", "keep-alive"),
            ]);
            let result = validate_headers(headers).unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn validate_headers_allows_legit_bot() {
        Python::with_gil(|py| {
            let headers = dict_from_pairs(py, &[
                ("HTTP_USER_AGENT", "Googlebot/2.1 (+http://www.google.com/bot.html)"),
                ("HTTP_ACCEPT", "*/*"),
                ("HTTP_ACCEPT_LANGUAGE", "en-US"),
            ]);
            let result = validate_headers(headers).unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn validate_headers_blocks_accept_star_missing_lang_encoding() {
        Python::with_gil(|py| {
            let headers = dict_from_pairs(py, &[
                ("HTTP_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
                ("HTTP_ACCEPT", "*/*"),
            ]);
            let result = validate_headers(headers).unwrap();
            assert!(matches!(result, Some(msg) if msg.contains("Generic Accept header")));
        });
    }

    #[test]
    fn validate_headers_blocks_http10_chrome() {
        Python::with_gil(|py| {
            let headers = dict_from_pairs(py, &[
                ("HTTP_USER_AGENT", "Mozilla/5.0 Chrome/120.0.0.0"),
                ("HTTP_ACCEPT", "text/html"),
                ("HTTP_ACCEPT_LANGUAGE", "en-US"),
                ("SERVER_PROTOCOL", "HTTP/1.0"),
            ]);
            let result = validate_headers(headers).unwrap();
            assert!(matches!(result, Some(msg) if msg.contains("HTTP/1.0")));
        });
    }
}
