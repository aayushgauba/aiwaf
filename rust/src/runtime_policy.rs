//! Pure enforcement decisions. Framework request/session extraction stays in adapters.
use pyo3::prelude::*;
use regex::Regex;
use std::{collections::HashSet, sync::OnceLock};

#[pyfunction]
pub fn policy_rate(
    timestamps: Vec<f64>,
    now: f64,
    window: f64,
    max_requests: i64,
    flood: i64,
) -> (String, usize, Vec<f64>) {
    let mut trimmed: Vec<f64> = timestamps
        .into_iter()
        .filter(|t| now - t < window.max(1.0))
        .collect();
    trimmed.push(now);
    let count = trimmed.len();
    let action = if count as i64 > flood {
        "flood_block"
    } else if count as i64 > max_requests {
        "throttle"
    } else {
        "allow"
    };
    (action.to_owned(), count, trimmed)
}

#[pyfunction]
pub fn policy_geo(
    country: String,
    allow: HashSet<String>,
    block: HashSet<String>,
    dynamic: HashSet<String>,
) -> (bool, String, String) {
    let country = country.trim().to_uppercase();
    let blocked = !country.is_empty()
        && if !allow.is_empty() {
            !allow.contains(&country)
        } else {
            block.contains(&country) || dynamic.contains(&country)
        };
    let reason = if blocked {
        format!("Geo blocked: {country}")
    } else {
        String::new()
    };
    (blocked, country, reason)
}

#[pyfunction]
#[pyo3(signature = (now, get_time, path, min_time, max_time))]
pub fn policy_form(
    now: f64,
    get_time: Option<f64>,
    path: String,
    min_time: f64,
    max_time: f64,
) -> (String, Option<String>, Option<i32>, Option<String>) {
    let Some(get_time) = get_time else {
        return ("allow".into(), None, None, None);
    };
    let elapsed = now - get_time;
    if elapsed > max_time {
        return (
            "page_expired".into(),
            None,
            Some(409),
            Some("Page has expired. Please reload and try again.".into()),
        );
    }
    let path = path.to_lowercase();
    let minimum = if [
        "/admin/login/",
        "/login/",
        "/accounts/login/",
        "/auth/login/",
        "/signin/",
    ]
    .iter()
    .any(|s| path.starts_with(s))
    {
        0.1
    } else {
        min_time
    };
    if elapsed < minimum {
        return (
            "block".into(),
            Some(format!("Form submitted too quickly ({elapsed:.2}s)")),
            Some(403),
            None,
        );
    }
    ("allow".into(), None, None, None)
}

#[pyfunction]
pub fn policy_uuid(text: String) -> bool {
    // Match Python's length/pattern check followed by uuid.UUID: misplaced hyphens
    // are accepted only when removing them leaves exactly 32 hexadecimal digits.
    let text = text.trim().to_lowercase();
    text.len() == 36
        && text.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
        && text.chars().filter(|c| *c != '-').count() == 32
}

#[pyfunction]
pub fn policy_reputation(
    score: i64,
    offenses: i64,
    old_reasons: Vec<String>,
    reason: String,
) -> (i64, i64, Vec<String>, bool, Option<i64>) {
    let normalized = if reason.trim().is_empty() {
        "unknown"
    } else {
        reason.trim()
    };
    let mut reasons = Vec::new();
    let mut seen = HashSet::new();
    for raw in old_reasons
        .into_iter()
        .chain(std::iter::once(normalized.to_owned()))
    {
        let value = if raw.trim().is_empty() {
            "unknown".to_owned()
        } else {
            raw.trim().to_owned()
        };
        if seen.insert(value.to_lowercase()) {
            reasons.push(value);
        }
    }
    let lower = normalized.to_lowercase();
    let weight = [
        ("scanner", 20),
        ("scan", 20),
        ("sqli", 40),
        ("sql injection", 40),
        ("xss", 30),
        ("bruteforce", 25),
        ("brute force", 25),
        ("flood", 25),
        ("rate limit", 20),
        ("honeypot", 30),
        ("uuid", 25),
        ("header", 15),
        ("geo", 20),
        ("keyword", 20),
    ]
    .into_iter()
    .find(|(token, _)| lower.contains(token))
    .map(|(_, w)| w)
    .unwrap_or(10);
    let score = (score + weight).min(100);
    let offenses = offenses + 1;
    let duration = if score < 60 {
        None
    } else if score >= 80 || offenses >= 3 {
        Some(86400)
    } else if offenses == 2 {
        Some(3600)
    } else {
        Some(900)
    };
    (score, offenses, reasons, score >= 60, duration)
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn policy_keyword(
    path: String,
    query_keys: HashSet<String>,
    exists: bool,
    learning: bool,
    static_kw: HashSet<String>,
    dynamic_kw: HashSet<String>,
    legitimate: HashSet<String>,
    exempt: HashSet<String>,
    prefixes: Vec<String>,
    malicious: HashSet<String>,
    contexts: HashSet<String>,
) -> (Option<String>, Vec<String>, Vec<String>) {
    static SPLIT: OnceLock<Regex> = OnceLock::new();
    static PROBE: OnceLock<Regex> = OnceLock::new();
    let path = path.to_lowercase();
    let normalized = path.trim_start_matches('/');
    let segments: Vec<String> = SPLIT
        .get_or_init(|| Regex::new(r"\W+").unwrap())
        .split(normalized)
        .filter(|s| s.chars().count() > 3)
        .map(str::to_owned)
        .collect();
    let learned: Vec<String> = if learning && !exists {
        segments
            .iter()
            .filter(|s| !legitimate.contains(*s) && !exempt.contains(*s) && contexts.contains(*s))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    if !exists && PROBE.get_or_init(|| Regex::new(r"(^|/)\.(env|git|htaccess|htpasswd)(/|$)|\.(php|asp|aspx|jsp|cgi|bak|sql)(/|$)|xmlrpc\.php").unwrap()).is_match(&path) {
        return (Some("Keyword block: Inherently suspicious: probe path".into()), learned, segments);
    }
    let safe = prefixes
        .iter()
        .any(|p| !p.is_empty() && normalized.starts_with(p));
    let suspicious: HashSet<String> = static_kw
        .union(&dynamic_kw)
        .filter(|kw| {
            !exempt.contains(*kw)
                && !(legitimate.contains(*kw) && exists && !contexts.contains(*kw))
                && !safe
        })
        .cloned()
        .collect();
    let strong_count = [
        path.contains("../"),
        path.contains("..\\"),
        ["cmd", "exec", "system"]
            .iter()
            .any(|k| query_keys.contains(*k)),
        path.chars().filter(|c| *c == '%').count() > 5,
        segments.iter().filter(|s| malicious.contains(*s)).count() > 2,
    ]
    .into_iter()
    .filter(|v| *v)
    .count();
    let strong = strong_count >= 2
        || [
            "union+select",
            "drop+table",
            "<script",
            "javascript:",
            "onload=",
            "onerror=",
            "${",
            "{{",
            "eval(",
        ]
        .iter()
        .any(|s| path.contains(s));
    for segment in &segments {
        let reason = if suspicious.contains(segment) {
            Some(format!("Learned keyword: {segment}"))
        } else if !exists
            && !legitimate.contains(segment)
            && (contexts.contains(segment)
                || [
                    "hack",
                    "exploit",
                    "attack",
                    "malicious",
                    "evil",
                    "backdoor",
                    "inject",
                    "xss",
                ]
                .iter()
                .any(|s| segment.contains(s)))
        {
            Some(format!("Inherently suspicious: {segment}"))
        } else {
            None
        };
        if let Some(reason) = reason {
            if (!exists || strong) && (contexts.contains(segment) || !exists) {
                return (Some(format!("Keyword block: {reason}")), learned, segments);
            }
        }
    }
    (None, learned, segments)
}

/// Flask's context checks operate on plain request data, without Python callbacks.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn policy_keyword_flask(
    py: Python<'_>,
    path: String,
    query: String,
    query_keys: HashSet<String>,
    exists: bool,
    learning: bool,
    static_kw: HashSet<String>,
    dynamic_kw: HashSet<String>,
    legitimate: HashSet<String>,
    exempt: HashSet<String>,
    prefixes: Vec<String>,
    malicious: HashSet<String>,
) -> (Option<String>, Vec<String>, Vec<String>) {
    py.allow_threads(|| {
        let path = path.to_lowercase();
        let query = query.to_lowercase();
        static SPLIT: OnceLock<Regex> = OnceLock::new();
        let mut candidates: HashSet<String> = SPLIT
            .get_or_init(|| Regex::new(r"\W+").unwrap())
            .split(path.trim_start_matches('/'))
            .filter(|s| s.chars().count() > 3)
            .map(str::to_owned)
            .collect();
        candidates.extend(static_kw.iter().cloned());
        candidates.extend(dynamic_kw.iter().cloned());
        let traversal = path.contains("../") || path.contains("..\\");
        let query_attack = [
            "union", "select", "drop", "insert", "script", "alert", "eval",
        ]
        .iter()
        .any(|s| query.contains(s));
        let contexts = candidates
            .into_iter()
            .filter(|s| {
                (query_attack && query.contains(s.as_str()))
                    || traversal
                    || (!exists
                        && (s.starts_with('.')
                            || [".php", ".asp", ".jsp", ".cgi"]
                                .iter()
                                .any(|ext| s.contains(ext))))
            })
            .collect();
        policy_keyword(
            path, query_keys, exists, learning, static_kw, dynamic_kw, legitimate, exempt,
            prefixes, malicious, contexts,
        )
    })
}

#[pyfunction]
pub fn policy_sql_signature(py: Python<'_>, text: String) -> Option<String> {
    py.allow_threads(|| {
        static COMMENTS: OnceLock<Regex> = OnceLock::new();
        static RULES: OnceLock<Vec<(&str, Regex)>> = OnceLock::new();
        let text = COMMENTS.get_or_init(|| Regex::new(r"/\*[\s\S]*?\*/").unwrap())
            .replace_all(&text, " ");
        RULES.get_or_init(|| vec![
            ("sql_union_select", Regex::new(r"(?i)\bunion\s+(?:all\s+)?select\b").unwrap()),
            ("sql_boolean_tautology", Regex::new(r#"(?i)['"`]\s*(?:or|and)\s*(?:true\b|\d+\s*=\s*\d+|['"][^'"\r\n]{0,80}['"]\s*=\s*['"])"#).unwrap()),
            ("sql_quote_comment", Regex::new(r#"(?i)['"`]\s*(?:--|#)"#).unwrap()),
            ("sql_stacked_statement", Regex::new(r"(?i);\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set)\b").unwrap()),
        ]).iter().find(|(_, rule)| rule.is_match(&text)).map(|(name, _)| (*name).to_owned())
    })
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(policy_sql_signature, m)?)?;
    m.add_function(wrap_pyfunction!(policy_keyword_flask, m)?)?;
    m.add_function(wrap_pyfunction!(policy_rate, m)?)?;
    m.add_function(wrap_pyfunction!(policy_geo, m)?)?;
    m.add_function(wrap_pyfunction!(policy_form, m)?)?;
    m.add_function(wrap_pyfunction!(policy_uuid, m)?)?;
    m.add_function(wrap_pyfunction!(policy_reputation, m)?)?;
    m.add_function(wrap_pyfunction!(policy_keyword, m)?)?;
    Ok(())
}
