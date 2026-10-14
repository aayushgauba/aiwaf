use once_cell::sync::Lazy;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::f64;

/// Match literal keywords while preserving the configured keyword order.
pub struct KeywordMatcher {
    keywords: Vec<String>,
    set: RegexSet,
}

impl KeywordMatcher {
    pub fn new(keywords: Vec<String>) -> Result<Self, regex::Error> {
        let patterns: Vec<String> = keywords.iter().map(|kw| regex::escape(kw)).collect();
        Ok(Self {
            keywords,
            set: RegexSet::new(patterns)?,
        })
    }

    pub fn first_match(&self, path: &str) -> Option<&str> {
        self.set
            .matches(path)
            .iter()
            .next()
            .map(|index| self.keywords[index].as_str())
    }
}

/// Match the deepest configured path prefix without scanning every rule.
/// Inputs are normalized by the host adapter to preserve framework semantics.
pub struct RouteMatcher {
    by_prefix: HashMap<String, usize>,
}

impl RouteMatcher {
    pub fn new(prefixes: Vec<String>) -> Self {
        let mut by_prefix = HashMap::with_capacity(prefixes.len());
        for (index, prefix) in prefixes.into_iter().enumerate() {
            let base = prefix.trim_end_matches('/');
            let base = if base.is_empty() { "/" } else { base };
            by_prefix.entry(base.to_string()).or_insert(index);
        }
        Self { by_prefix }
    }

    pub fn match_index(&self, normalized_path: &str) -> Option<usize> {
        let path = normalized_path.trim_end_matches('/');
        let mut candidate = if path.is_empty() { "/" } else { path };
        loop {
            if let Some(index) = self.by_prefix.get(candidate) {
                return Some(*index);
            }
            if candidate == "/" {
                return None;
            }
            candidate = match candidate.rfind('/') {
                Some(0) => "/",
                Some(position) => &candidate[..position],
                None => return None,
            };
        }
    }
}

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

fn get_header(headers: &HashMap<String, String>, key: &str) -> Option<String> {
    headers.get(key).cloned()
}

fn has_header(headers: &HashMap<String, String>, key: &str) -> bool {
    match get_header(headers, key) {
        Some(value) => !value.is_empty(),
        None => false,
    }
}

fn check_user_agent(user_agent: &str) -> Option<String> {
    if user_agent.is_empty() {
        return None;
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

    if user_agent.chars().count() < 10 {
        return Some("Too short".to_string());
    }
    if user_agent.chars().count() > 500 {
        return Some("Too long".to_string());
    }

    None
}

/// The default Python header policy, including caps and arbitrary required headers.
/// This is a separate entry point so older callers keep their existing API.
pub fn validate_headers_full_default(
    headers: &HashMap<String, String>,
    required: &[String],
    min_score: i32,
) -> Option<String> {
    let mut total_chars = 0usize;
    let mut header_count = 0usize;
    for (key, value) in headers {
        if key.starts_with("HTTP_") || key == "CONTENT_TYPE" || key == "CONTENT_LENGTH" {
            header_count += 1;
            total_chars += key.chars().count() + value.chars().count();
        }
    }
    if total_chars > 32 * 1024 {
        return Some("Header bytes exceed 32768".to_string());
    }
    if header_count > 100 {
        return Some("Header count exceeds 100".to_string());
    }

    let ua = get_header(headers, "HTTP_USER_AGENT").unwrap_or_default();
    if ua.chars().count() > 500 {
        return Some("User-Agent longer than 500 chars".to_string());
    }
    let accept = get_header(headers, "HTTP_ACCEPT").unwrap_or_default();
    if accept.chars().count() > 4096 {
        return Some("Accept header longer than 4096 chars".to_string());
    }

    let missing: Vec<String> = required
        .iter()
        .filter(|name| !has_header(headers, name))
        .map(|name| name.replace("HTTP_", "").replace('_', "-").to_lowercase())
        .collect();
    if !missing.is_empty() {
        return Some(format!("Missing required headers: {}", missing.join(", ")));
    }

    if let Some(reason) = check_user_agent(&ua) {
        return Some(format!("Suspicious user agent: {}", reason));
    }

    if !required.is_empty() {
        let protocol = get_header(headers, "SERVER_PROTOCOL").unwrap_or_default();
        let language = get_header(headers, "HTTP_ACCEPT_LANGUAGE").unwrap_or_default();
        let encoding = get_header(headers, "HTTP_ACCEPT_ENCODING").unwrap_or_default();
        let connection = get_header(headers, "HTTP_CONNECTION").unwrap_or_default();
        if protocol.starts_with("HTTP/2") && ua.to_lowercase().contains("mozilla/4.0") {
            return Some("Suspicious headers: HTTP/2 with old browser user agent".to_string());
        }
        if !ua.is_empty() && accept.is_empty() && required.iter().any(|h| h == "HTTP_ACCEPT") {
            return Some("Suspicious headers: User-Agent present but no Accept header".to_string());
        }
        if accept == "*/*"
            && !headers.contains_key("HTTP_ACCEPT_LANGUAGE")
            && !headers.contains_key("HTTP_ACCEPT_ENCODING")
        {
            return Some(
                "Suspicious headers: Generic Accept header without language/encoding".to_string(),
            );
        }
        if !ua.is_empty() && language.is_empty() && encoding.is_empty() && connection.is_empty() {
            return Some("Suspicious headers: Missing all browser-standard headers".to_string());
        }
        if headers.contains_key("HTTP_USER_AGENT")
            && protocol == "HTTP/1.0"
            && ua.to_lowercase().contains("chrome")
        {
            return Some("Suspicious headers: Modern browser with HTTP/1.0".to_string());
        }
    }

    let mut score = 0;
    if has_header(headers, "HTTP_USER_AGENT") {
        score += 2;
    }
    if has_header(headers, "HTTP_ACCEPT") {
        score += 2;
    }
    for name in [
        "HTTP_ACCEPT_LANGUAGE",
        "HTTP_ACCEPT_ENCODING",
        "HTTP_CONNECTION",
        "HTTP_CACHE_CONTROL",
    ] {
        if has_header(headers, name) {
            score += 1;
        }
    }
    if has_header(headers, "HTTP_ACCEPT_LANGUAGE") && has_header(headers, "HTTP_ACCEPT_ENCODING") {
        score += 1;
    }
    if get_header(headers, "HTTP_CONNECTION").as_deref() == Some("keep-alive") {
        score += 1;
    }
    if accept.contains("text/html") && accept.contains("application/xml") {
        score += 1;
    }
    if !required.is_empty() && score < min_score {
        return Some(format!("Low header quality score: {score}"));
    }
    None
}

pub fn validate_headers(headers: &HashMap<String, String>) -> Option<String> {
    validate_headers_with_config(headers, None, None)
}

/// Reject control characters that cannot safely appear in an HTTP URL.
pub fn validate_url(url: &str) -> Option<&'static str> {
    if url.chars().any(char::is_control) {
        return Some("url_control_character");
    }
    None
}

/// Keep default body checks conservative because body content can be arbitrary text.
pub fn validate_content(content: &str) -> Option<&'static str> {
    if content.contains('\0') {
        return Some("content_nul_byte");
    }
    None
}

pub fn validate_headers_with_config(
    headers: &HashMap<String, String>,
    required_headers: Option<Vec<String>>,
    min_score: Option<i32>,
) -> Option<String> {
    let required = required_headers
        .unwrap_or_else(|| vec!["HTTP_USER_AGENT".to_string(), "HTTP_ACCEPT".to_string()]);
    let required_set: HashSet<String> = required.iter().cloned().collect();
    let check_required = !required.is_empty();

    let mut missing = Vec::new();
    if check_required {
        if required_set.contains("HTTP_USER_AGENT") && !has_header(headers, "HTTP_USER_AGENT") {
            missing.push("user-agent".to_string());
        }
        if required_set.contains("HTTP_ACCEPT") && !has_header(headers, "HTTP_ACCEPT") {
            missing.push("accept".to_string());
        }
    }

    if !missing.is_empty() {
        return Some(format!("Missing required headers: {}", missing.join(", ")));
    }

    let user_agent = get_header(headers, "HTTP_USER_AGENT").unwrap_or_default();
    if let Some(reason) = check_user_agent(&user_agent) {
        return Some(format!("Suspicious user agent: {}", reason));
    }

    let server_protocol = get_header(headers, "SERVER_PROTOCOL").unwrap_or_default();
    let accept = get_header(headers, "HTTP_ACCEPT").unwrap_or_default();
    let accept_language = get_header(headers, "HTTP_ACCEPT_LANGUAGE").unwrap_or_default();
    let accept_encoding = get_header(headers, "HTTP_ACCEPT_ENCODING").unwrap_or_default();
    let connection = get_header(headers, "HTTP_CONNECTION").unwrap_or_default();

    if check_required {
        if server_protocol.starts_with("HTTP/2")
            && user_agent.to_lowercase().contains("mozilla/4.0")
        {
            return Some("Suspicious headers: HTTP/2 with old browser user agent".to_string());
        }
        if !user_agent.is_empty() && accept.is_empty() && required_set.contains("HTTP_ACCEPT") {
            return Some("Suspicious headers: User-Agent present but no Accept header".to_string());
        }
        if accept == "*/*" && accept_language.is_empty() && accept_encoding.is_empty() {
            return Some(
                "Suspicious headers: Generic Accept header without language/encoding".to_string(),
            );
        }
        if !user_agent.is_empty()
            && accept_language.is_empty()
            && accept_encoding.is_empty()
            && connection.is_empty()
        {
            return Some("Suspicious headers: Missing all browser-standard headers".to_string());
        }
        if !user_agent.is_empty()
            && server_protocol == "HTTP/1.0"
            && user_agent.to_lowercase().contains("chrome")
        {
            return Some("Suspicious headers: Modern browser with HTTP/1.0".to_string());
        }
    }

    let mut score = 0;
    if has_header(headers, "HTTP_USER_AGENT") {
        score += 2;
    }
    if has_header(headers, "HTTP_ACCEPT") {
        score += 2;
    }

    for header in [
        "HTTP_ACCEPT_LANGUAGE",
        "HTTP_ACCEPT_ENCODING",
        "HTTP_CONNECTION",
        "HTTP_CACHE_CONTROL",
    ] {
        if has_header(headers, header) {
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

    let min_score = min_score.unwrap_or(3);
    if min_score > 0 && score < min_score {
        return Some(format!("Low header quality score: {}", score));
    }

    None
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FeatureRecordInput {
    pub ip: String,
    pub path_lower: String,
    pub path_len: usize,
    pub timestamp: f64,
    pub response_time: f64,
    pub status_idx: i32,
    pub kw_check: bool,
    pub total_404: i32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ParsedFeatureRecord {
    pub ip: String,
    pub path: String,
    pub response_time: f64,
    pub status: i32,
    pub timestamp: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BuiltFeatureRecord {
    pub ip: String,
    pub path_len: usize,
    pub path_lower: String,
    pub resp_time: f64,
    pub status_idx: i32,
    pub timestamp: f64,
    pub timestamp_epoch: f64,
    pub kw_check: bool,
    pub total_404: i32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FeatureRecordOutput {
    pub ip: String,
    pub path_len: usize,
    pub kw_hits: i32,
    pub resp_time: f64,
    pub status_idx: i32,
    pub burst_count: i32,
    pub total_404: i32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecentEntryInput {
    pub path_lower: String,
    pub timestamp: f64,
    pub status: i32,
    pub kw_check: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FeatureState {
    pub timestamps_by_ip: HashMap<String, Vec<f64>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FeatureBatchResult {
    pub features: Vec<FeatureRecordOutput>,
    pub state: FeatureState,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RawFeatureRecord {
    pub ip: String,
    pub path: String,
    pub timestamp: f64,
    pub response_time: f64,
    pub status: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BehaviorAnalysis {
    pub avg_kw_hits: f64,
    pub max_404s: i32,
    pub avg_burst: f64,
    pub total_requests: i32,
    pub scanning_404s: i32,
    pub legitimate_404s: i32,
    pub should_block: bool,
}

pub fn build_records<P, E>(
    parsed: Vec<ParsedFeatureRecord>,
    ip_404: &HashMap<String, i32>,
    mut path_exists_fn: P,
    mut path_exempt_fn: E,
    status_idx_list: &[i32],
) -> Vec<BuiltFeatureRecord>
where
    P: FnMut(&str) -> Result<bool, ()>,
    E: FnMut(&str) -> Result<bool, ()>,
{
    let mut records = Vec::with_capacity(parsed.len());
    let mut known_cache: HashMap<String, bool> = HashMap::new();
    let mut exempt_cache: HashMap<String, bool> = HashMap::new();

    for record in parsed {
        let known_path = match known_cache.get(&record.path) {
            Some(value) => *value,
            None => {
                let value = path_exists_fn(&record.path).unwrap_or(false);
                known_cache.insert(record.path.clone(), value);
                value
            }
        };

        let exempt = match exempt_cache.get(&record.path) {
            Some(value) => *value,
            None => {
                let value = path_exempt_fn(&record.path).unwrap_or(false);
                exempt_cache.insert(record.path.clone(), value);
                value
            }
        };

        let status_idx = status_idx_list
            .iter()
            .position(|status| *status == record.status)
            .map(|idx| idx as i32)
            .unwrap_or(-1);

        records.push(BuiltFeatureRecord {
            ip: record.ip.clone(),
            path_len: record.path.chars().count(),
            path_lower: record.path.to_lowercase(),
            resp_time: record.response_time,
            status_idx,
            timestamp: record.timestamp,
            timestamp_epoch: record.timestamp,
            kw_check: !known_path && !exempt,
            total_404: ip_404.get(&record.ip).copied().unwrap_or(0),
        });
    }

    records
}

pub fn rust_payload_from_records(records: &[BuiltFeatureRecord]) -> Vec<FeatureRecordInput> {
    records
        .iter()
        .map(|rec| FeatureRecordInput {
            ip: rec.ip.clone(),
            path_lower: rec.path_lower.clone(),
            path_len: rec.path_len,
            timestamp: rec.timestamp_epoch,
            response_time: rec.resp_time,
            status_idx: rec.status_idx,
            kw_check: rec.kw_check,
            total_404: rec.total_404,
        })
        .collect()
}

fn build_timestamp_index(records: &[FeatureRecordInput]) -> HashMap<String, Vec<f64>> {
    let mut map: HashMap<String, Vec<f64>> = HashMap::new();
    for rec in records {
        map.entry(rec.ip.clone()).or_default().push(rec.timestamp);
    }
    for timestamps in map.values_mut() {
        timestamps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    }
    map
}

fn count_burst(timestamps: Option<&Vec<f64>>, current: f64) -> i32 {
    if let Some(ts) = timestamps {
        let min_ts = current - 10.0;
        (upper_bound(ts, current) - lower_bound(ts, min_ts)) as i32
    } else {
        0
    }
}

fn count_burst_around(timestamps: Option<&Vec<f64>>, current: f64) -> i32 {
    if let Some(ts) = timestamps {
        (upper_bound(ts, current + 10.0) - lower_bound(ts, current - 10.0)) as i32
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

pub fn extract_features(
    records: Vec<FeatureRecordInput>,
    static_keywords: Vec<String>,
) -> Vec<FeatureRecordOutput> {
    extract_features_with_window(records, static_keywords, false)
}

/// Training uses a symmetric ten-second window, matching the existing JS trainer.
pub fn extract_training_features(
    records: Vec<FeatureRecordInput>,
    static_keywords: Vec<String>,
) -> Vec<FeatureRecordOutput> {
    extract_features_with_window(records, static_keywords, true)
}

/// Build feature inputs and extract features in one Rust batch.
/// `eligible_paths` is keyed by the original path; absent paths are eligible.
/// A supplied 404 map preserves callers' precomputed counts.
pub fn extract_raw_features(
    records: Vec<RawFeatureRecord>,
    static_keywords: Vec<String>,
    status_indices: &[String],
    eligible_paths: &HashMap<String, bool>,
    ip_404_override: Option<&HashMap<String, i32>>,
    symmetric_burst: bool,
) -> Vec<FeatureRecordOutput> {
    let computed_404 = if ip_404_override.is_none() {
        let mut counts = HashMap::new();
        for record in &records {
            if record.status == "404" {
                *counts.entry(record.ip.clone()).or_insert(0) += 1;
            }
        }
        counts
    } else {
        HashMap::new()
    };
    let ip_404 = ip_404_override.unwrap_or(&computed_404);
    let inputs = records
        .into_iter()
        .map(|record| FeatureRecordInput {
            path_len: if symmetric_burst {
                record.path.encode_utf16().count()
            } else {
                record.path.chars().count()
            },
            path_lower: record.path.to_lowercase(),
            timestamp: record.timestamp,
            response_time: record.response_time,
            status_idx: status_indices
                .iter()
                .position(|status| status == &record.status)
                .map(|index| index as i32)
                .unwrap_or(-1),
            kw_check: eligible_paths.get(&record.path).copied().unwrap_or(true),
            total_404: ip_404.get(&record.ip).copied().unwrap_or(0),
            ip: record.ip,
        })
        .collect();
    extract_features_with_window(inputs, static_keywords, symmetric_burst)
}

fn extract_features_with_window(
    records: Vec<FeatureRecordInput>,
    static_keywords: Vec<String>,
    symmetric_burst: bool,
) -> Vec<FeatureRecordOutput> {
    if records.is_empty() {
        return Vec::new();
    }

    let keywords: Vec<String> = static_keywords
        .into_iter()
        .map(|kw| kw.to_lowercase())
        .collect();

    let timestamp_index = build_timestamp_index(&records);
    let mut output = Vec::with_capacity(records.len());

    for rec in records.into_iter() {
        let timestamps = timestamp_index.get(&rec.ip);
        let burst = if symmetric_burst {
            count_burst_around(timestamps, rec.timestamp)
        } else {
            count_burst(timestamps, rec.timestamp)
        };
        let kw = keyword_hits(&rec.path_lower, &keywords, rec.kw_check);

        output.push(FeatureRecordOutput {
            ip: rec.ip,
            path_len: rec.path_len,
            kw_hits: kw,
            resp_time: rec.response_time,
            status_idx: rec.status_idx,
            burst_count: burst,
            total_404: rec.total_404,
        });
    }

    output
}

pub fn extract_features_batch_with_state(
    records: Vec<FeatureRecordInput>,
    static_keywords: Vec<String>,
    state: Option<FeatureState>,
) -> FeatureBatchResult {
    let keywords: Vec<String> = static_keywords
        .into_iter()
        .map(|kw| kw.to_lowercase())
        .collect();

    let mut timestamp_index = state.map(|s| s.timestamps_by_ip).unwrap_or_default();

    for rec in records.iter() {
        timestamp_index
            .entry(rec.ip.clone())
            .or_default()
            .push(rec.timestamp);
    }
    for timestamps in timestamp_index.values_mut() {
        timestamps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    }

    let mut features: Vec<FeatureRecordOutput> = Vec::with_capacity(records.len());
    for rec in records.into_iter() {
        let timestamps = timestamp_index.get(&rec.ip);
        let burst = count_burst(timestamps, rec.timestamp);
        let kw = keyword_hits(&rec.path_lower, &keywords, rec.kw_check);

        features.push(FeatureRecordOutput {
            ip: rec.ip,
            path_len: rec.path_len,
            kw_hits: kw,
            resp_time: rec.response_time,
            status_idx: rec.status_idx,
            burst_count: burst,
            total_404: rec.total_404,
        });
    }

    FeatureBatchResult {
        features,
        state: FeatureState {
            timestamps_by_ip: timestamp_index,
        },
    }
}

pub fn finalize_feature_state() -> FeatureBatchResult {
    FeatureBatchResult {
        features: Vec::new(),
        state: FeatureState {
            timestamps_by_ip: HashMap::new(),
        },
    }
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

pub fn analyze_recent_behavior(
    entries: Vec<RecentEntryInput>,
    static_keywords: Vec<String>,
) -> Option<BehaviorAnalysis> {
    if entries.is_empty() {
        return None;
    }

    let keywords: Vec<String> = static_keywords
        .into_iter()
        .map(|kw| kw.to_lowercase())
        .collect();
    let mut timestamps: Vec<f64> = entries.iter().map(|e| e.timestamp).collect();
    timestamps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let mut total_kw_hits = 0f64;
    // Sorted finite timestamps admit a linear sweep after the existing sort.
    // Retain the established binary-search behavior for NaN/infinite inputs.
    let total_burst = if timestamps.iter().all(|t| t.is_finite()) {
        let mut lower = 0usize;
        let mut upper = 0usize;
        let mut total = 0f64;
        for timestamp in &timestamps {
            while lower < timestamps.len() && timestamps[lower] < timestamp - 10.0 {
                lower += 1;
            }
            while upper < timestamps.len() && timestamps[upper] <= timestamp + 10.0 {
                upper += 1;
            }
            total += (upper.saturating_sub(lower)) as i32 as f64;
        }
        total
    } else {
        entries
            .iter()
            .map(|entry| {
                let lower = lower_bound(&timestamps, entry.timestamp - 10.0);
                let upper = upper_bound(&timestamps, entry.timestamp + 10.0);
                (upper.saturating_sub(lower)) as i32 as f64
            })
            .sum()
    };
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

    Some(BehaviorAnalysis {
        avg_kw_hits,
        max_404s,
        avg_burst,
        total_requests,
        scanning_404s,
        legitimate_404s,
        should_block,
    })
}

fn avg_path_len(n: usize) -> f64 {
    if n <= 1 {
        return 0.0;
    }
    if n == 2 {
        return 1.0;
    }
    let n_f = n as f64;
    2.0 * ((n_f - 1.0).ln() + 0.5772156649) - (2.0 * (n_f - 1.0) / n_f)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IsolationTreeState {
    pub depth: usize,
    pub max_depth: usize,
    pub split_attr: Option<usize>,
    pub split_value: Option<f64>,
    pub size: usize,
    pub left: Option<Box<IsolationTreeState>>,
    pub right: Option<Box<IsolationTreeState>>,
}

#[derive(Clone)]
struct IsolationTree {
    depth: usize,
    max_depth: usize,
    left: Option<Box<IsolationTree>>,
    right: Option<Box<IsolationTree>>,
    split_attr: Option<usize>,
    split_value: Option<f64>,
    size: usize,
}

impl IsolationTree {
    fn new(depth: usize, max_depth: usize) -> Self {
        Self {
            depth,
            max_depth,
            left: None,
            right: None,
            split_attr: None,
            split_value: None,
            size: 0,
        }
    }

    fn fit<R: Rng + ?Sized>(
        &mut self,
        data: &[Vec<f64>],
        y: &[f64],
        rng: &mut R,
        feature_subset: &[usize],
    ) {
        self.size = data.len();
        if self.depth >= self.max_depth || data.len() <= 1 {
            return;
        }
        if feature_subset.is_empty() {
            return;
        }
        let n = data.len() as f64;
        let (sum, sumsq) = y.iter().fold((0.0, 0.0), |(s, ss), v| (s + v, ss + v * v));
        let parent_var = if n > 0.0 {
            sumsq / n - (sum / n).powi(2)
        } else {
            0.0
        };

        let mut best_gain = f64::NEG_INFINITY;
        let mut best_attr = None;
        let mut best_value = 0.0;

        for &attr in feature_subset {
            let mut min_val = f64::INFINITY;
            let mut max_val = f64::NEG_INFINITY;
            for row in data.iter() {
                if let Some(v) = row.get(attr) {
                    if *v < min_val {
                        min_val = *v;
                    }
                    if *v > max_val {
                        max_val = *v;
                    }
                }
            }
            if !min_val.is_finite() || !max_val.is_finite() || min_val == max_val {
                continue;
            }
            let split_value = min_val + rng.r#gen::<f64>() * (max_val - min_val);

            let mut l_count = 0.0;
            let mut r_count = 0.0;
            let mut l_sum = 0.0;
            let mut r_sum = 0.0;
            let mut l_sumsq = 0.0;
            let mut r_sumsq = 0.0;

            for (row, &yv) in data.iter().zip(y.iter()) {
                if row[attr] < split_value {
                    l_count += 1.0;
                    l_sum += yv;
                    l_sumsq += yv * yv;
                } else {
                    r_count += 1.0;
                    r_sum += yv;
                    r_sumsq += yv * yv;
                }
            }

            if l_count == 0.0 || r_count == 0.0 {
                continue;
            }

            let l_var = l_sumsq / l_count - (l_sum / l_count).powi(2);
            let r_var = r_sumsq / r_count - (r_sum / r_count).powi(2);
            let gain = parent_var - (l_count / n) * l_var - (r_count / n) * r_var;

            if gain > best_gain {
                best_gain = gain;
                best_attr = Some(attr);
                best_value = split_value;
            }
        }

        let Some(split_attr) = best_attr else {
            return;
        };

        let split_value = best_value;
        let mut left_data: Vec<Vec<f64>> = Vec::new();
        let mut right_data: Vec<Vec<f64>> = Vec::new();
        let mut left_y: Vec<f64> = Vec::new();
        let mut right_y: Vec<f64> = Vec::new();
        for (row, &yv) in data.iter().zip(y.iter()) {
            if row[split_attr] < split_value {
                left_data.push(row.clone());
                left_y.push(yv);
            } else {
                right_data.push(row.clone());
                right_y.push(yv);
            }
        }

        self.split_attr = Some(split_attr);
        self.split_value = Some(split_value);
        let mut left = IsolationTree::new(self.depth + 1, self.max_depth);
        let mut right = IsolationTree::new(self.depth + 1, self.max_depth);
        left.fit(&left_data, &left_y, rng, feature_subset);
        right.fit(&right_data, &right_y, rng, feature_subset);
        self.left = Some(Box::new(left));
        self.right = Some(Box::new(right));
    }

    fn path_length(&self, point: &[f64]) -> f64 {
        match (&self.left, &self.right, self.split_attr, self.split_value) {
            (Some(left), Some(right), Some(attr), Some(split)) => {
                if point[attr] < split {
                    left.path_length(point)
                } else {
                    right.path_length(point)
                }
            }
            _ => self.depth as f64 + avg_path_len(self.size),
        }
    }

    fn to_state(&self) -> IsolationTreeState {
        IsolationTreeState {
            depth: self.depth,
            max_depth: self.max_depth,
            split_attr: self.split_attr,
            split_value: self.split_value,
            size: self.size,
            left: self.left.as_ref().map(|l| Box::new(l.to_state())),
            right: self.right.as_ref().map(|r| Box::new(r.to_state())),
        }
    }

    fn from_state(state: IsolationTreeState) -> Self {
        Self {
            depth: state.depth,
            max_depth: state.max_depth,
            split_attr: state.split_attr,
            split_value: state.split_value,
            size: state.size,
            left: state.left.map(|l| Box::new(IsolationTree::from_state(*l))),
            right: state.right.map(|r| Box::new(IsolationTree::from_state(*r))),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum MaxSamples {
    Auto,
    Int(usize),
    Float(f64),
}

impl MaxSamples {
    pub fn resolve(&self, n_samples: usize) -> usize {
        match *self {
            MaxSamples::Auto => 256.min(n_samples.max(1)),
            MaxSamples::Int(v) => v.min(n_samples).max(1),
            MaxSamples::Float(v) => ((v * n_samples as f64).floor() as usize)
                .min(n_samples)
                .max(1),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum MaxFeatures {
    Int(usize),
    Float(f64),
}

impl MaxFeatures {
    pub fn resolve(&self, n_features: usize) -> usize {
        match *self {
            MaxFeatures::Int(v) => v.min(n_features).max(1),
            MaxFeatures::Float(v) => {
                let calc = (v * n_features as f64).floor() as usize;
                calc.max(1).min(n_features)
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Contamination {
    Auto,
    Fixed(f64),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IsolationForestState {
    pub n_estimators: usize,
    pub max_samples: MaxSamples,
    pub contamination: Contamination,
    pub max_features: MaxFeatures,
    pub bootstrap: bool,
    pub random_state: Option<u64>,
    pub verbose: usize,
    pub warm_start: bool,
    pub max_samples_: usize,
    pub max_features_: usize,
    pub offset_: f64,
    pub n_features_in_: usize,
    pub trees: Vec<IsolationTreeState>,
    pub estimators_features: Vec<Vec<usize>>,
}

#[derive(Clone)]
pub struct IsolationForest {
    n_estimators: usize,
    max_samples: MaxSamples,
    contamination: Contamination,
    max_features: MaxFeatures,
    bootstrap: bool,
    random_state: Option<u64>,
    verbose: usize,
    warm_start: bool,
    trees: Vec<IsolationTree>,
    estimators_features: Vec<Vec<usize>>,
    max_samples_: usize,
    max_features_: usize,
    offset_: f64,
    n_features_in_: usize,
}

impl IsolationForest {
    pub fn new(
        n_estimators: usize,
        max_samples: MaxSamples,
        contamination: Contamination,
        max_features: MaxFeatures,
        bootstrap: bool,
        random_state: Option<u64>,
        verbose: usize,
        warm_start: bool,
    ) -> Self {
        Self {
            n_estimators,
            max_samples,
            contamination,
            max_features,
            bootstrap,
            random_state,
            verbose,
            warm_start,
            trees: Vec::new(),
            estimators_features: Vec::new(),
            max_samples_: 0,
            max_features_: 0,
            offset_: -0.5,
            n_features_in_: 0,
        }
    }

    pub fn fit(&mut self, data: Vec<Vec<f64>>) {
        let reset = !self.warm_start || self.trees.is_empty();
        if reset {
            self.trees.clear();
            self.estimators_features.clear();
        }
        self.fit_internal(data, reset);
    }

    pub fn retrain(&mut self, data: Vec<Vec<f64>>) {
        let prev_warm = self.warm_start;
        self.warm_start = true;
        self.fit(data);
        self.warm_start = prev_warm;
    }

    pub fn anomaly_score(&self, point: &[f64]) -> f64 {
        self.raw_score(point)
    }

    pub fn is_anomaly(&self, point: &[f64], thresh: f64) -> bool {
        self.anomaly_score(point) > thresh
    }

    pub fn score_samples(&self, data: &[Vec<f64>]) -> Vec<f64> {
        data.iter().map(|row| -self.raw_score(row)).collect()
    }

    pub fn decision_function(&self, data: &[Vec<f64>]) -> Vec<f64> {
        self.score_samples(data)
            .into_iter()
            .map(|s| s - self.offset_)
            .collect()
    }

    pub fn predict(&self, data: &[Vec<f64>]) -> Vec<i32> {
        self.decision_function(data)
            .into_iter()
            .map(|s| if s < 0.0 { -1 } else { 1 })
            .collect()
    }

    pub fn to_state(&self) -> IsolationForestState {
        IsolationForestState {
            n_estimators: self.n_estimators,
            max_samples: self.max_samples.clone(),
            contamination: self.contamination.clone(),
            max_features: self.max_features.clone(),
            bootstrap: self.bootstrap,
            random_state: self.random_state,
            verbose: self.verbose,
            warm_start: self.warm_start,
            max_samples_: self.max_samples_,
            max_features_: self.max_features_,
            offset_: self.offset_,
            n_features_in_: self.n_features_in_,
            trees: self.trees.iter().map(|t| t.to_state()).collect(),
            estimators_features: self.estimators_features.clone(),
        }
    }

    pub fn from_state(state: IsolationForestState) -> Self {
        Self {
            n_estimators: state.n_estimators,
            max_samples: state.max_samples,
            contamination: state.contamination,
            max_features: state.max_features,
            bootstrap: state.bootstrap,
            random_state: state.random_state,
            verbose: state.verbose,
            warm_start: state.warm_start,
            max_samples_: state.max_samples_,
            max_features_: state.max_features_,
            offset_: state.offset_,
            n_features_in_: state.n_features_in_,
            trees: state
                .trees
                .into_iter()
                .map(IsolationTree::from_state)
                .collect(),
            estimators_features: state.estimators_features,
        }
    }

    fn fit_internal(&mut self, data: Vec<Vec<f64>>, reset: bool) {
        if data.is_empty() || self.n_estimators == 0 {
            return;
        }
        self.n_features_in_ = data[0].len();
        if self.n_features_in_ == 0 {
            return;
        }

        let max_samples = self.max_samples.resolve(data.len());
        self.max_samples_ = max_samples;
        let max_features = self.max_features.resolve(self.n_features_in_);
        self.max_features_ = max_features;
        let height_limit = (max_samples as f64).log2().ceil() as usize;

        let mut rng = match self.random_state {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };

        let start_idx = if reset { 0 } else { self.trees.len() };
        let target = self.n_estimators;
        if !reset && self.trees.len() > target {
            self.trees.truncate(target);
            self.estimators_features.truncate(target);
        }

        for _ in start_idx..target {
            let feature_subset = sample_features(&mut rng, self.n_features_in_, max_features);
            let sample = sample_rows(&mut rng, &data, max_samples, self.bootstrap);
            let y: Vec<f64> = (0..sample.len()).map(|_| rng.r#gen::<f64>()).collect();
            let mut tree = IsolationTree::new(0, height_limit);
            tree.fit(&sample, &y, &mut rng, &feature_subset);
            self.trees.push(tree);
            self.estimators_features.push(feature_subset);
        }

        match self.contamination {
            Contamination::Auto => {
                self.offset_ = -0.5;
            }
            Contamination::Fixed(c) => {
                let mut scores: Vec<f64> = data.iter().map(|row| -self.raw_score(row)).collect();
                self.offset_ = percentile(&mut scores, c);
            }
        }
    }

    fn raw_score(&self, point: &[f64]) -> f64 {
        if self.trees.is_empty() || self.max_samples_ == 0 {
            return 0.0;
        }
        let mut sum = 0.0;
        for tree in self.trees.iter() {
            sum += tree.path_length(point);
        }
        let avg_path = sum / self.trees.len() as f64;
        2f64.powf(-avg_path / avg_path_len(self.max_samples_))
    }
}

fn sample_rows<R: Rng + ?Sized>(
    rng: &mut R,
    data: &[Vec<f64>],
    sample_size: usize,
    bootstrap: bool,
) -> Vec<Vec<f64>> {
    let n = data.len();
    if n == 0 {
        return Vec::new();
    }
    if !bootstrap {
        let mut idxs: Vec<usize> = (0..n).collect();
        idxs.shuffle(rng);
        idxs.truncate(sample_size.min(n));
        idxs.into_iter().map(|i| data[i].clone()).collect()
    } else {
        let mut out = Vec::with_capacity(sample_size.min(n).max(sample_size));
        for _ in 0..sample_size {
            let idx = rng.gen_range(0..n);
            out.push(data[idx].clone());
        }
        out
    }
}

fn sample_features<R: Rng + ?Sized>(
    rng: &mut R,
    n_features: usize,
    max_features: usize,
) -> Vec<usize> {
    let mut idxs: Vec<usize> = (0..n_features).collect();
    idxs.shuffle(rng);
    idxs.truncate(max_features.min(n_features));
    idxs
}

fn percentile(values: &mut [f64], contamination: f64) -> f64 {
    if values.is_empty() {
        return -0.5;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let pct = (100.0 * contamination).clamp(0.0, 50.0);
    let k = ((pct / 100.0) * (values.len() as f64 - 1.0)).round() as usize;
    values[k.min(values.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_headers_blocks_missing_required() {
        let mut headers = HashMap::new();
        headers.insert("HTTP_USER_AGENT".to_string(), "Mozilla/5.0".to_string());
        let result = validate_headers(&headers);
        assert!(matches!(result, Some(msg) if msg.contains("Missing required headers")));
    }

    #[test]
    fn url_and_content_checks_are_conservative() {
        assert_eq!(validate_url("https://example.com/docs?q=script"), None);
        assert_eq!(validate_url("/api/item\nX-Injected: yes"), Some("url_control_character"));
        assert_eq!(validate_content("<script>example documentation</script>"), None);
        assert_eq!(validate_content("before\0after"), Some("content_nul_byte"));
    }

    #[test]
    fn validate_headers_with_config_allows_empty_required() {
        let mut headers = HashMap::new();
        headers.insert(
            "HTTP_USER_AGENT".to_string(),
            "EmailScanner/1.0".to_string(),
        );
        let result = validate_headers_with_config(&headers, Some(vec![]), Some(0));
        assert!(result.is_none());
    }

    #[test]
    fn full_header_policy_checks_caps_and_custom_required_headers() {
        let mut headers = HashMap::new();
        headers.insert("HTTP_USER_AGENT".to_string(), "Mozilla/5.0".to_string());
        headers.insert("HTTP_ACCEPT".to_string(), "text/html".to_string());
        assert_eq!(
            validate_headers_full_default(&headers, &["HTTP_X_AUTH".to_string()], 0),
            Some("Missing required headers: x-auth".to_string())
        );
        headers.insert("HTTP_X_AUTH".to_string(), "yes".to_string());
        headers.insert("HTTP_ACCEPT_LANGUAGE".to_string(), "en-US".to_string());
        assert_eq!(
            validate_headers_full_default(&headers, &["HTTP_X_AUTH".to_string()], 0),
            None
        );
        headers.insert("HTTP_ACCEPT".to_string(), "a".repeat(4097));
        assert_eq!(
            validate_headers_full_default(&headers, &[], 0),
            Some("Accept header longer than 4096 chars".to_string())
        );
    }

    #[test]
    fn full_header_policy_allows_empty_user_agent_when_not_required() {
        let headers = HashMap::new();
        assert_eq!(validate_headers_full_default(&headers, &[], 0), None);
    }

    #[test]
    fn validate_headers_blocks_suspicious_user_agent() {
        let mut headers = HashMap::new();
        headers.insert(
            "HTTP_USER_AGENT".to_string(),
            "python-requests/2.25.1".to_string(),
        );
        headers.insert("HTTP_ACCEPT".to_string(), "*/*".to_string());
        let result = validate_headers(&headers);
        assert!(matches!(result, Some(msg) if msg.contains("Suspicious user agent")));
    }

    #[test]
    fn validate_headers_allows_legit_bot() {
        let mut headers = HashMap::new();
        headers.insert(
            "HTTP_USER_AGENT".to_string(),
            "Googlebot/2.1 (+http://www.google.com/bot.html)".to_string(),
        );
        headers.insert("HTTP_ACCEPT".to_string(), "*/*".to_string());
        headers.insert("HTTP_ACCEPT_LANGUAGE".to_string(), "en-US".to_string());
        let result = validate_headers(&headers);
        assert!(result.is_none());
    }

    #[test]
    fn validate_headers_allows_unicode_user_agent() {
        let mut headers = HashMap::new();
        headers.insert("HTTP_USER_AGENT".to_string(), "Mozilla/5.0 ✅".to_string());
        headers.insert("HTTP_ACCEPT".to_string(), "text/html".to_string());
        headers.insert("HTTP_ACCEPT_LANGUAGE".to_string(), "en-US".to_string());
        headers.insert(
            "HTTP_ACCEPT_ENCODING".to_string(),
            "gzip, deflate".to_string(),
        );
        headers.insert("HTTP_CONNECTION".to_string(), "keep-alive".to_string());
        let result = validate_headers(&headers);
        assert!(result.is_none());
    }

    #[test]
    fn extract_features_basic() {
        let records = vec![
            FeatureRecordInput {
                ip: "1.2.3.4".to_string(),
                path_lower: "/wp-admin".to_string(),
                path_len: 9,
                timestamp: 100.0,
                response_time: 0.1,
                status_idx: 3,
                kw_check: true,
                total_404: 5,
            },
            FeatureRecordInput {
                ip: "1.2.3.4".to_string(),
                path_lower: "/index".to_string(),
                path_len: 6,
                timestamp: 105.0,
                response_time: 0.05,
                status_idx: 1,
                kw_check: true,
                total_404: 5,
            },
        ];
        let features = extract_features(records, vec!["wp".to_string()]);
        assert_eq!(features.len(), 2);
        assert_eq!(features[0].kw_hits, 1);
        assert!(features[0].burst_count >= 1);
    }

    #[test]
    fn raw_training_batch_builds_counts_statuses_and_symmetric_bursts() {
        let records = vec![
            RawFeatureRecord {
                ip: "203.0.113.1".into(),
                path: "/a.php".into(),
                timestamp: 0.0,
                response_time: 7.0,
                status: "404".into(),
            },
            RawFeatureRecord {
                ip: "203.0.113.1".into(),
                path: "/safe".into(),
                timestamp: 10.0,
                response_time: 8.0,
                status: "200".into(),
            },
            RawFeatureRecord {
                ip: "203.0.113.1".into(),
                path: "/safe".into(),
                timestamp: 21.0,
                response_time: 9.0,
                status: "200".into(),
            },
        ];
        let output = extract_raw_features(
            records,
            vec![".php".into()],
            &["200".into(), "404".into()],
            &HashMap::new(),
            None,
            true,
        );
        assert_eq!(output.len(), 3);
        assert_eq!(output[0].kw_hits, 1);
        assert_eq!(output[0].status_idx, 1);
        assert_eq!(output[0].total_404, 1);
        assert_eq!(output[0].burst_count, 2);
        assert_eq!(output[1].burst_count, 2);
        assert_eq!(output[2].burst_count, 1);
    }

    #[test]
    fn raw_python_batch_honors_path_eligibility_and_supplied_404_counts() {
        let records = vec![RawFeatureRecord {
            ip: "203.0.113.2".into(),
            path: "/known.php".into(),
            timestamp: 10.0,
            response_time: 0.2,
            status: "200".into(),
        }];
        let output = extract_raw_features(
            records,
            vec![".php".into()],
            &["200".into(), "404".into()],
            &HashMap::from([("/known.php".into(), false)]),
            Some(&HashMap::from([("203.0.113.2".into(), 3)])),
            false,
        );
        assert_eq!(output[0].kw_hits, 0);
        assert_eq!(output[0].total_404, 3);
        assert_eq!(output[0].burst_count, 1);
    }

    #[test]
    fn keyword_matcher_uses_literal_patterns_in_configured_order() {
        let matcher = KeywordMatcher::new(vec![".env".to_string(), "admin".to_string()]).unwrap();
        assert_eq!(matcher.first_match("/admin/.env"), Some(".env"));
        assert_eq!(matcher.first_match("/safe"), None);
    }

    #[test]
    fn route_matcher_selects_deepest_prefix_and_first_duplicate() {
        let matcher = RouteMatcher::new(vec![
            "/".into(),
            "/api/".into(),
            "/api/admin/".into(),
            "/api/".into(),
        ]);
        assert_eq!(matcher.match_index("/api/admin/users"), Some(2));
        assert_eq!(matcher.match_index("/api/admin"), Some(2));
        assert_eq!(matcher.match_index("/api/items"), Some(1));
        assert_eq!(matcher.match_index("/apix"), Some(0));
        assert_eq!(matcher.match_index("/other"), Some(0));
        assert_eq!(RouteMatcher::new(vec!["/api/".into()]).match_index("/other"), None);
    }

    #[test]
    fn discovery_paths_are_not_scanning_paths() {
        assert!(!is_scanning_path("/robots.txt"));
        assert!(!is_scanning_path("/sitemap.xml"));
    }

    #[test]
    fn extract_features_empty() {
        let features = extract_features(Vec::new(), vec![]);
        assert!(features.is_empty());
    }

    #[test]
    fn extract_features_burst_excludes_future_and_old_requests() {
        let timestamps = [89.0, 90.0, 100.0, 100.0, 101.0];
        let records: Vec<FeatureRecordInput> = timestamps
            .iter()
            .map(|timestamp| FeatureRecordInput {
                ip: "1.2.3.4".to_string(),
                path_lower: "/".to_string(),
                path_len: 1,
                timestamp: *timestamp,
                response_time: 0.0,
                status_idx: 0,
                kw_check: false,
                total_404: 0,
            })
            .collect();
        let features = extract_features(records, vec![]);
        assert_eq!(features[2].burst_count, 3); // 90, 100, 100; not 89 or 101.
    }

    #[test]
    fn extract_training_features_counts_symmetric_window() {
        let timestamps = [89.0, 90.0, 100.0, 100.0, 101.0, 110.0, 111.0];
        let records: Vec<FeatureRecordInput> = timestamps
            .iter()
            .map(|timestamp| FeatureRecordInput {
                ip: "1.2.3.4".to_string(),
                path_lower: "/".to_string(),
                path_len: 1,
                timestamp: *timestamp,
                response_time: 0.0,
                status_idx: 0,
                kw_check: false,
                total_404: 0,
            })
            .collect();
        let features = extract_training_features(records, vec![]);
        assert_eq!(features[2].burst_count, 5); // 90, 100, 100, 101, 110.
    }

    #[test]
    fn build_records_caches_path_checks_and_converts_payload() {
        let parsed = vec![
            ParsedFeatureRecord {
                ip: "1.2.3.4".to_string(),
                path: "/wp-admin".to_string(),
                response_time: 0.1,
                status: 404,
                timestamp: 10.0,
            },
            ParsedFeatureRecord {
                ip: "1.2.3.4".to_string(),
                path: "/wp-admin".to_string(),
                response_time: 0.2,
                status: 500,
                timestamp: 12.0,
            },
        ];
        let mut ip_404 = HashMap::new();
        ip_404.insert("1.2.3.4".to_string(), 7);
        let mut exists_calls = 0;
        let mut exempt_calls = 0;

        let records = build_records(
            parsed,
            &ip_404,
            |_| {
                exists_calls += 1;
                Ok(false)
            },
            |_| {
                exempt_calls += 1;
                Ok(false)
            },
            &[200, 404],
        );

        assert_eq!(exists_calls, 1);
        assert_eq!(exempt_calls, 1);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].path_len, 9);
        assert_eq!(records[0].path_lower, "/wp-admin");
        assert_eq!(records[0].status_idx, 1);
        assert_eq!(records[1].status_idx, -1);
        assert!(records[0].kw_check);
        assert_eq!(records[0].total_404, 7);

        let payload = rust_payload_from_records(&records);
        assert_eq!(payload[0].timestamp, 10.0);
        assert_eq!(payload[0].response_time, 0.1);
        assert_eq!(payload[0].status_idx, 1);
    }

    #[test]
    fn extract_features_batch_with_state_updates_state() {
        let records = vec![
            FeatureRecordInput {
                ip: "1.2.3.4".to_string(),
                path_lower: "/a".to_string(),
                path_len: 2,
                timestamp: 10.0,
                response_time: 0.1,
                status_idx: 1,
                kw_check: false,
                total_404: 0,
            },
            FeatureRecordInput {
                ip: "1.2.3.4".to_string(),
                path_lower: "/b".to_string(),
                path_len: 2,
                timestamp: 12.0,
                response_time: 0.1,
                status_idx: 1,
                kw_check: false,
                total_404: 0,
            },
        ];
        let result = extract_features_batch_with_state(records, vec![], None);
        assert_eq!(result.features.len(), 2);
        assert!(result.state.timestamps_by_ip.contains_key("1.2.3.4"));
    }

    #[test]
    fn analyze_recent_behavior_blocks_scan() {
        let entries = (0..12)
            .map(|i| RecentEntryInput {
                path_lower: if i % 2 == 0 {
                    "/wp-admin".to_string()
                } else {
                    "/.env".to_string()
                },
                timestamp: i as f64,
                status: 404,
                kw_check: true,
            })
            .collect();
        let result = analyze_recent_behavior(entries, vec!["wp".to_string()]);
        assert!(matches!(result, Some(r) if r.should_block));
    }

    #[test]
    fn analyze_recent_behavior_allows_benign() {
        let entries = vec![RecentEntryInput {
            path_lower: "/".to_string(),
            timestamp: 1.0,
            status: 200,
            kw_check: false,
        }];
        let result = analyze_recent_behavior(entries, vec![]);
        assert!(matches!(result, Some(r) if !r.should_block));
    }

    #[test]
    fn analyze_recent_behavior_empty_returns_none() {
        let result = analyze_recent_behavior(Vec::new(), vec![]);
        assert!(result.is_none());
    }

    #[test]
    fn burst_sweep_matches_previous_searches() {
        for times in [
            vec![20.0, 0.0, 10.0, 10.0, -0.01, 30.01],
            (0..2000)
                .map(|i| ((i * 7919) % 1031) as f64 / 10.0)
                .collect(),
            vec![f64::NEG_INFINITY, 0.0, 10.0, f64::INFINITY],
            vec![0.0, f64::NAN, 10.0],
            vec![f64::MAX, -f64::MAX, 0.0],
        ] {
            let mut sorted = times.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let total: f64 = times
                .iter()
                .map(|t| {
                    (upper_bound(&sorted, t + 10.0).saturating_sub(lower_bound(&sorted, t - 10.0)))
                        as i32 as f64
                })
                .sum();
            let entries = times
                .iter()
                .map(|t| RecentEntryInput {
                    path_lower: "/docs".into(),
                    timestamp: *t,
                    status: 200,
                    kw_check: false,
                })
                .collect();
            let result = analyze_recent_behavior(entries, vec![]).unwrap();
            assert_eq!(result.avg_burst, total / times.len() as f64);
            assert!(!result.should_block);
        }
    }

    #[test]
    fn isolation_forest_fit_score_predict() {
        let mut forest = IsolationForest::new(
            50,
            MaxSamples::Auto,
            Contamination::Auto,
            MaxFeatures::Float(1.0),
            false,
            Some(42),
            0,
            false,
        );
        let data = vec![
            vec![0.1, 0.2],
            vec![0.2, 0.1],
            vec![0.15, 0.18],
            vec![10.0, 10.0],
        ];
        forest.fit(data.clone());
        let score_inlier = forest.anomaly_score(&data[0]);
        let score_outlier = forest.anomaly_score(&data[3]);
        assert!(score_outlier >= score_inlier);

        let preds = forest.predict(&data);
        assert_eq!(preds.len(), 4);
    }

    #[test]
    fn isolation_forest_deterministic_with_seed() {
        let data = vec![
            vec![0.1, 0.2],
            vec![0.2, 0.1],
            vec![0.15, 0.18],
            vec![10.0, 10.0],
        ];
        let mut a = IsolationForest::new(
            25,
            MaxSamples::Int(8),
            Contamination::Auto,
            MaxFeatures::Float(1.0),
            false,
            Some(123),
            0,
            false,
        );
        let mut b = IsolationForest::new(
            25,
            MaxSamples::Int(8),
            Contamination::Auto,
            MaxFeatures::Float(1.0),
            false,
            Some(123),
            0,
            false,
        );
        a.fit(data.clone());
        b.fit(data.clone());
        let score_a = a.anomaly_score(&data[3]);
        let score_b = b.anomaly_score(&data[3]);
        assert!((score_a - score_b).abs() < 1e-9);
    }

    #[test]
    fn isolation_forest_max_features_int() {
        let mut forest = IsolationForest::new(
            10,
            MaxSamples::Int(6),
            Contamination::Auto,
            MaxFeatures::Int(1),
            false,
            Some(9),
            0,
            false,
        );
        forest.fit(vec![vec![0.0, 1.0], vec![1.0, 0.0], vec![2.0, 2.0]]);
        let scores = forest.score_samples(&vec![vec![0.5, 0.5]]);
        assert_eq!(scores.len(), 1);
    }

    #[test]
    fn isolation_forest_state_roundtrip() {
        let mut forest = IsolationForest::new(
            10,
            MaxSamples::Int(8),
            Contamination::Auto,
            MaxFeatures::Float(1.0),
            false,
            Some(7),
            0,
            false,
        );
        let data = vec![vec![0.0], vec![1.0], vec![2.0], vec![10.0]];
        forest.fit(data);
        let state = forest.to_state();
        let forest2 = IsolationForest::from_state(state.clone());
        assert_eq!(forest2.n_estimators, state.n_estimators);
        assert_eq!(forest2.max_samples_, state.max_samples_);
    }

    #[test]
    fn isolation_forest_retrain_appends() {
        let mut forest = IsolationForest::new(
            5,
            MaxSamples::Int(4),
            Contamination::Auto,
            MaxFeatures::Float(1.0),
            false,
            Some(3),
            0,
            true,
        );
        forest.fit(vec![vec![0.0], vec![1.0], vec![2.0], vec![3.0]]);
        let initial = forest.trees.len();
        forest.retrain(vec![vec![4.0], vec![5.0], vec![6.0], vec![7.0]]);
        assert!(forest.trees.len() >= initial);
    }

    #[test]
    fn contamination_percentile_sets_offset() {
        let mut forest = IsolationForest::new(
            25,
            MaxSamples::Int(8),
            Contamination::Fixed(0.1),
            MaxFeatures::Float(1.0),
            false,
            Some(11),
            0,
            false,
        );
        forest.fit(vec![vec![0.0], vec![0.1], vec![0.2], vec![10.0]]);
        assert!(forest.offset_.is_finite());
    }
}
pub mod training_evidence;
