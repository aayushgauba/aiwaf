//! Stateful, bounded Node/WASM request processing. Filesystem I/O belongs to Node.
use aiwaf_core::{
    IsolationForest, RecentEntryInput, analyze_recent_behavior, validate_headers_full_default,
    validate_url,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

pub const STAGES: [&str; 8] = [
    "geo_block",
    "ip_keyword_block",
    "rate_limit",
    "ai_anomaly",
    "honeypot",
    "uuid_tamper",
    "header_validation",
    "logging",
];
static NEXT_CONTEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Profile {
    enabled: HashSet<String>,
    exempt_paths: Vec<String>,
    exempt_ips: HashSet<String>,
    static_keywords: Vec<String>,
    dynamic_keywords: HashSet<String>,
    legitimate_keywords: Vec<String>,
    learning: bool,
    geo_allow: HashSet<String>,
    geo_block: HashSet<String>,
    #[serde(rename = "blacklist", alias = "blocklist")]
    blocklist: HashMap<String, f64>,
    rate_window: f64,
    rate_max: usize,
    rate_flood: usize,
    rate_key_mode: String,
    min_form_time: f64,
    max_page_time: f64,
    skip_authenticated: bool,
    honeypot_field: String,
    allowed_methods: Vec<String>,
    uuid_prefix: String,
    uuid_window: f64,
    uuid_threshold: usize,
    anomaly_window: f64,
    required_headers: Vec<String>,
    header_min_score: i32,
    sql_mode: String,
    max_bytes: usize,
    block_duration: f64,
    max_clients: usize,
    max_history: usize,
    max_pending: usize,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            enabled: STAGES.map(str::to_owned).into(),
            exempt_paths: vec![
                "/health".into(),
                "/robots.txt".into(),
                "/sitemap.xml".into(),
            ],
            exempt_ips: HashSet::new(),
            static_keywords: [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "shell"]
                .map(str::to_owned)
                .into(),
            dynamic_keywords: HashSet::new(),
            legitimate_keywords: [
                "profile",
                "users",
                "account",
                "settings",
                "dashboard",
                "search",
                "admin",
                "login",
                "register",
                "api",
            ]
            .map(str::to_owned)
            .into(),
            learning: true,
            geo_allow: HashSet::new(),
            geo_block: HashSet::new(),
            blocklist: HashMap::new(),
            rate_window: 10.0,
            rate_max: 20,
            rate_flood: 40,
            rate_key_mode: "ip_path".into(),
            min_form_time: 1.0,
            max_page_time: 240.0,
            skip_authenticated: true,
            honeypot_field: String::new(),
            allowed_methods: vec![],
            uuid_prefix: "/user/".into(),
            uuid_window: 60.0,
            uuid_threshold: 5,
            anomaly_window: 60.0,
            required_headers: vec!["HTTP_USER_AGENT".into(), "HTTP_ACCEPT".into()],
            header_min_score: 3,
            sql_mode: "block".into(),
            max_bytes: 65536,
            block_duration: 86400.0,
            max_clients: 100000,
            max_history: 1000,
            max_pending: 10000,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    ip: String,
    path: String,
    method: String,
    headers: HashMap<String, String>,
    query: String,
    body: Value,
    now: f64,
    country: String,
    authenticated: bool,
    exists: bool,
    #[serde(default)]
    parsed_query: Value,
    #[serde(default)]
    disabled: HashSet<String>,
    #[serde(default)]
    payload_exhausted: bool,
    #[serde(default)]
    defer_body: bool,
}
struct Pending {
    request: Request,
    status: u16,
    reason: String,
    apply: HashSet<String>,
}
#[derive(Default)]
struct Client {
    rates: HashMap<String, VecDeque<f64>>,
    honey: Option<f64>,
    uuid: VecDeque<(f64, usize)>,
    history: VecDeque<RecentEntryInput>,
    last: f64,
}
#[derive(Serialize)]
struct Begin {
    context: String,
    status: u16,
    reason: String,
}
pub struct Engine {
    profile: Profile,
    clients: HashMap<String, Client>,
    pending: HashMap<String, Pending>,
    blocks: HashMap<String, f64>,
    learned: HashSet<String>,
    last_cleanup: f64,
    processed: usize,
    predictions: usize,
    pub model: Option<IsolationForest>,
}
impl Engine {
    pub fn new(profile: &str) -> Result<Self, String> {
        let mut p: Profile = serde_json::from_str(profile).map_err(|e| e.to_string())?;
        if p.enabled.iter().any(|s| !STAGES.contains(&s.as_str())) {
            return Err("Unknown stage".into());
        }
        if !["off", "block"].contains(&p.sql_mode.as_str())
            || !["ip", "ip_path"].contains(&p.rate_key_mode.as_str())
        {
            return Err("Unsupported native policy".into());
        }
        if !(1..=1048576).contains(&p.max_bytes)
            || p.rate_max == 0
            || p.rate_flood < p.rate_max
            || p.rate_flood > 100000
            || p.max_history == 0
            || p.max_history > 10000
            || p.max_clients == 0
            || p.max_pending == 0
            || p.uuid_threshold == 0
        {
            return Err("Invalid native limits".into());
        }
        if [
            p.rate_window,
            p.max_page_time,
            p.uuid_window,
            p.anomaly_window,
            p.block_duration,
        ]
        .iter()
        .any(|v| !v.is_finite() || *v <= 0.0)
            || !p.min_form_time.is_finite()
            || p.min_form_time < 0.0
        {
            return Err("Invalid native timing".into());
        }
        if p.blocklist.values().any(|v| !v.is_finite() || *v < 0.0) {
            return Err("Invalid blocklist expiry (0 means permanent)".into());
        }
        p.static_keywords = p
            .static_keywords
            .into_iter()
            .map(|s| s.to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        p.legitimate_keywords = p
            .legitimate_keywords
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();
        p.exempt_paths = p
            .exempt_paths
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();
        p.geo_allow = p.geo_allow.into_iter().map(|s| s.to_uppercase()).collect();
        p.geo_block = p.geo_block.into_iter().map(|s| s.to_uppercase()).collect();
        let blocks = p.blocklist.clone();
        let learned = p
            .dynamic_keywords
            .iter()
            .map(|s| s.to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(Self {
            profile: p,
            clients: HashMap::new(),
            pending: HashMap::new(),
            blocks,
            learned,
            last_cleanup: 0.0,
            processed: 0,
            predictions: 0,
            model: None,
        })
    }
    pub fn set_model(&mut self, model: IsolationForest) -> Result<(), String> {
        let state = model.to_state();
        if state.n_features_in_ != 6 || state.trees.is_empty() {
            return Err("A fitted six-feature Rust model is required".into());
        }
        self.model = Some(model);
        Ok(())
    }
    fn cleanup(&mut self, now: f64) {
        if now - self.last_cleanup < 30.0 {
            return;
        }
        let keep = self
            .profile
            .rate_window
            .max(self.profile.anomaly_window)
            .max(self.profile.uuid_window)
            .max(self.profile.max_page_time + 300.0);
        self.clients.retain(|_, c| now - c.last <= keep);
        for c in self.clients.values_mut() {
            c.rates.retain(|_, times| {
                times.retain(|t| now - *t < self.profile.rate_window);
                !times.is_empty()
            });
            c.uuid.retain(|(t, _)| now - *t < self.profile.uuid_window);
            c.history
                .retain(|e| now - e.timestamp < self.profile.anomaly_window);
        }
        self.blocks
            .retain(|_, expires| *expires == 0.0 || *expires > now);
        // Pending count is bounded. Live streams retain their context until finish/close.
        self.last_cleanup = now;
    }
    pub fn inspect_payload(&self, payload: &str) -> Result<String, String> {
        if payload.len()
            > self
                .profile
                .max_bytes
                .saturating_mul(8)
                .saturating_add(8192)
        {
            return Ok(json!({"status":413,"rule":"payload_inspection_limit"}).to_string());
        }
        let value: Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        let result = if self.profile.sql_mode == "off" {
            None
        } else {
            inspect(&value, self.profile.max_bytes)
        };
        Ok(result
            .map(|(status, rule)| json!({"status":status,"rule":rule}))
            .unwrap_or(Value::Null)
            .to_string())
    }
    pub fn begin(&mut self, input: &str) -> Result<String, String> {
        if input.len()
            > self
                .profile
                .max_bytes
                .saturating_mul(8)
                .saturating_add(65536)
        {
            return Err("Request envelope limit exceeded".into());
        }
        let mut r: Request = serde_json::from_str(input).map_err(|e| e.to_string())?;
        if !r.now.is_finite() || r.ip.len() > 512 || r.path.len() > 8192 {
            return Err("Invalid request facts".into());
        }
        if r.disabled.iter().any(|s| !STAGES.contains(&s.as_str())) {
            return Err("Unknown disabled stage".into());
        }
        r.path = r.path.to_lowercase();
        r.method = r.method.to_uppercase();
        self.cleanup(r.now);
        if self.pending.len() >= self.profile.max_pending {
            return Err("Pending request limit exceeded".into());
        }
        if self.clients.len() >= self.profile.max_clients && !self.clients.contains_key(&r.ip) {
            return Err("Client state limit exceeded".into());
        }
        let mut apply: HashSet<String> = self
            .profile
            .enabled
            .difference(&r.disabled)
            .cloned()
            .collect();
        if self.profile.exempt_ips.contains(&r.ip)
            || self
                .profile
                .exempt_paths
                .iter()
                .any(|p| r.path.starts_with(p))
        {
            apply.retain(|s| s == "logging");
        }
        let mut status = 0u16;
        let mut reason = String::new();
        let p = &self.profile;
        let country = r.country.to_uppercase();
        if apply.contains("geo_block")
            && !country.is_empty()
            && (if p.geo_allow.is_empty() {
                p.geo_block.contains(&country)
            } else {
                !p.geo_allow.contains(&country)
            })
        {
            status = 403;
            reason = "geo_block".into();
        }
        if status == 0 && apply.contains("ip_keyword_block") {
            if self
                .blocks
                .get(&r.ip)
                .is_some_and(|expiry| *expiry == 0.0 || *expiry > r.now)
            {
                status = 403;
                reason = "blocklist".into();
            } else if let Some(k) = validate_url(&r.path).or_else(|| validate_url(&r.query)) {
                status = 403;
                reason = k.into();
            } else if r.payload_exhausted && p.sql_mode != "off" {
                status = 413;
                reason = "payload_inspection_limit".into();
            } else if p.sql_mode != "off" {
                if let Some((s, k)) =
                    inspect(&json!([r.query, r.body, r.parsed_query]), p.max_bytes)
                {
                    status = s;
                    reason = k.into();
                }
            }
            if status == 0
                && !p
                    .legitimate_keywords
                    .iter()
                    .any(|s| r.path.trim_matches('/') == s)
                && p.static_keywords
                    .iter()
                    .chain(self.learned.iter())
                    .any(|s| r.path.contains(s))
            {
                status = 403;
                reason = "keyword".into();
            }
        }
        let c = self.clients.entry(r.ip.clone()).or_default();
        c.last = r.now;
        if status == 0 && apply.contains("rate_limit") {
            let key = if p.rate_key_mode == "ip" {
                String::new()
            } else {
                r.path.clone()
            };
            // Bound path buckets even for a single hostile client.
            if c.rates.len() >= p.max_history && !c.rates.contains_key(&key) {
                status = 429;
                reason = "rate_bucket_limit".into();
            } else {
                let times = c.rates.entry(key).or_default();
                while times.front().is_some_and(|t| r.now - *t >= p.rate_window) {
                    times.pop_front();
                }
                // A denied flood cannot grow an unbounded timestamp list.
                if times.len() <= p.rate_flood {
                    times.push_back(r.now);
                }
                let burst = times.len();
                if burst > p.rate_flood {
                    status = 403;
                    reason = "flood".into();
                } else if burst > p.rate_max {
                    status = 429;
                    reason = "rate_limit".into();
                }
            }
        }
        if status == 0
            && apply.contains("ai_anomaly")
            && self
                .blocks
                .get(&r.ip)
                .is_some_and(|e| *e == 0.0 || *e > r.now)
        {
            status = 403;
            reason = "blocklist".into();
        }
        if status == 0 && apply.contains("honeypot") && !r.defer_body {
            if !p.allowed_methods.is_empty() && !p.allowed_methods.contains(&r.method) {
                status = 405;
                reason = "method_not_allowed".into();
            } else if !p.honeypot_field.is_empty()
                && r.body
                    .get(&p.honeypot_field)
                    .is_some_and(|v| !v.is_null() && v != false && v != "" && v != 0)
            {
                status = 403;
                reason = "honeypot_field".into();
            } else if !(p.skip_authenticated && r.authenticated) {
                if r.method == "GET" {
                    c.honey = Some(r.now);
                }
                if r.method == "POST" {
                    if let Some(start) = c.honey {
                        let elapsed = (r.now - start).max(0.0);
                        let min =
                            if r.path.starts_with("/login") || r.path.starts_with("/admin/login") {
                                p.min_form_time.min(0.1)
                            } else {
                                p.min_form_time
                            };
                        if elapsed > p.max_page_time {
                            c.honey = None;
                            status = 409;
                            reason = "page_expired".into();
                        } else if elapsed < min {
                            status = 403;
                            reason = "honeypot_too_fast".into();
                        }
                    }
                }
            }
        }
        if status == 0 && apply.contains("uuid_tamper") && r.path.starts_with(&p.uuid_prefix) {
            let uid = r.path[p.uuid_prefix.len()..].trim_end_matches('/');
            static UUID: OnceLock<Regex> = OnceLock::new();
            let valid = UUID.get_or_init(|| {
                Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
                    .unwrap()
            });
            if !uid.contains('/') && !valid.is_match(uid) {
                status = 403;
                reason = "uuid_malformed".into();
            }
        }
        if status == 0 && apply.contains("header_validation") {
            if let Some(k) =
                validate_headers_full_default(&r.headers, &p.required_headers, p.header_min_score)
            {
                status = 403;
                reason = format!("header:{k}");
            }
        }
        if status == 403 && reason != "blocklist" {
            self.blocks.insert(r.ip.clone(), r.now + p.block_duration);
        }
        // Only response facts are retained; streaming responses must not pin request payloads.
        r.body = Value::Null;
        r.parsed_query = Value::Null;
        r.query.clear();
        r.headers.retain(|key, _| key == "HTTP_USER_AGENT");
        let context = NEXT_CONTEXT.fetch_add(1, Ordering::Relaxed).to_string();
        self.pending.insert(
            context.clone(),
            Pending {
                request: r,
                status,
                reason: reason.clone(),
                apply,
            },
        );
        self.processed += 1;
        serde_json::to_string(&Begin {
            context,
            status,
            reason,
        })
        .map_err(|e| e.to_string())
    }
    pub fn inspect_body(
        &mut self,
        context: &str,
        payload: &str,
        exhausted: bool,
        authenticated: bool,
        now: f64,
    ) -> Result<String, String> {
        if !now.is_finite() {
            return Err("Invalid body time".into());
        }
        let item = self
            .pending
            .get_mut(context)
            .ok_or("Unknown, foreign or completed context")?;
        if !item.request.defer_body {
            return Err("Request body is not deferred".into());
        }
        item.request.defer_body = false;
        if item.status != 0 {
            return Ok(json!({"status":item.status,"rule":item.reason}).to_string());
        }
        let limit = payload.len()
            > self
                .profile
                .max_bytes
                .saturating_mul(8)
                .saturating_add(8192);
        let body: Value = if limit || exhausted {
            Value::Null
        } else {
            serde_json::from_str(payload).map_err(|e| e.to_string())?
        };
        let mut finding = None;
        if item.apply.contains("ip_keyword_block") && self.profile.sql_mode != "off" {
            finding = if limit || exhausted {
                Some((413, "payload_inspection_limit"))
            } else {
                inspect(&body, self.profile.max_bytes)
            };
        }
        if finding.is_none() && item.apply.contains("honeypot") {
            let r = &item.request;
            let p = &self.profile;
            let c = self.clients.entry(r.ip.clone()).or_default();
            if !p.allowed_methods.is_empty() && !p.allowed_methods.contains(&r.method) {
                finding = Some((405, "method_not_allowed"));
            } else if !p.honeypot_field.is_empty()
                && body
                    .get(&p.honeypot_field)
                    .is_some_and(|v| !v.is_null() && v != false && v != "" && v != 0)
            {
                finding = Some((403, "honeypot_field"));
            } else if !(p.skip_authenticated && authenticated) {
                if r.method == "GET" {
                    c.honey = Some(now);
                }
                if r.method == "POST" {
                    if let Some(start) = c.honey {
                        let min =
                            if r.path.starts_with("/login") || r.path.starts_with("/admin/login") {
                                p.min_form_time.min(0.1)
                            } else {
                                p.min_form_time
                            };
                        if now - start > p.max_page_time {
                            c.honey = None;
                            finding = Some((409, "page_expired"));
                        } else if (now - start).max(0.0) < min {
                            finding = Some((403, "honeypot_too_fast"));
                        }
                    }
                }
            }
        }
        if let Some((status, rule)) = finding {
            item.status = status;
            item.reason = rule.into();
            if status == 403 {
                self.blocks
                    .insert(item.request.ip.clone(), now + self.profile.block_duration);
            }
            return Ok(json!({"status":status,"rule":rule}).to_string());
        }
        Ok("null".into())
    }
    pub fn finish(
        &mut self,
        context: &str,
        status: u16,
        elapsed_ms: f64,
        now: f64,
    ) -> Result<String, String> {
        if !(100..=599).contains(&status)
            || !elapsed_ms.is_finite()
            || elapsed_ms < 0.0
            || !now.is_finite()
        {
            return Err("Invalid response facts".into());
        }
        let item = self
            .pending
            .remove(context)
            .ok_or("Unknown, foreign or completed context")?;
        let r = &item.request;
        let c = self.clients.entry(r.ip.clone()).or_default();
        c.last = now;
        let mut block = if item.status == 403 && item.reason != "blocklist" {
            Some((
                item.reason.clone(),
                self.blocks
                    .get(&r.ip)
                    .copied()
                    .unwrap_or(now + self.profile.block_duration),
            ))
        } else {
            None
        };
        if item.status == 0
            && item.apply.contains("uuid_tamper")
            && r.path.starts_with(&self.profile.uuid_prefix)
        {
            while c
                .uuid
                .front()
                .is_some_and(|(t, _)| now - *t >= self.profile.uuid_window)
            {
                c.uuid.pop_front();
            }
            if status == 404 {
                c.uuid.push_back((now, 1));
            } else if status < 400 {
                c.uuid.pop_front();
                c.uuid.pop_front();
            }
            if c.uuid.iter().map(|(_, s)| s).sum::<usize>() >= self.profile.uuid_threshold {
                block = Some((
                    "uuid_repeated_404".into(),
                    now + self.profile.block_duration,
                ));
            }
        }
        let mut learned = None;
        if item.status == 0 && item.apply.contains("ai_anomaly") {
            while c
                .history
                .front()
                .is_some_and(|e| now - e.timestamp >= self.profile.anomaly_window)
            {
                c.history.pop_front();
            }
            if c.history.len() >= self.profile.max_history {
                c.history.pop_front();
            }
            c.history.push_back(RecentEntryInput {
                path_lower: r.path.clone(),
                timestamp: now,
                status: status as i32,
                kw_check: !r.exists,
            });
            let hits = self
                .profile
                .static_keywords
                .iter()
                .filter(|s| r.path.contains(*s))
                .count();
            if let Some(model) = &self.model {
                // Preserve Node's model contract: status before response time (milliseconds).
                let code = [200, 403, 404, 500]
                    .iter()
                    .position(|v| *v == status)
                    .map(|v| v as f64)
                    .unwrap_or(-1.0);
                let burst = c
                    .history
                    .iter()
                    .filter(|e| now - e.timestamp < 10.0)
                    .count();
                let f = vec![
                    r.path.encode_utf16().count() as f64,
                    hits as f64,
                    code,
                    elapsed_ms,
                    burst as f64,
                    c.history.iter().filter(|e| e.status == 404).count() as f64,
                ];
                let anomaly = model.predict(&[f])[0] == -1;
                self.predictions += 1;
                if !r.exists
                    && anomaly
                    && analyze_recent_behavior(
                        c.history.iter().cloned().collect(),
                        self.profile.static_keywords.clone(),
                    )
                    .is_some_and(|s| s.should_block)
                {
                    block = Some(("ai_anomaly".into(), now + self.profile.block_duration));
                }
            }
            if self.profile.learning
                && status == 404
                && !r.exists
                && hits > 0
                && self.learned.len() < 4096
            {
                // Only learn a probe segment, never arbitrary application vocabulary.
                if let Some(segment) = r.path.split('/').find(|s| {
                    s.len() >= 3 && self.profile.static_keywords.iter().any(|k| s.contains(k))
                }) {
                    if !self
                        .profile
                        .legitimate_keywords
                        .iter()
                        .any(|s| segment.contains(s))
                        && self.learned.insert(segment.to_owned())
                    {
                        learned = Some(segment.to_owned());
                    }
                }
            }
        }
        if let Some((_, expiry)) = &block {
            self.blocks.insert(r.ip.clone(), *expiry);
        }
        let blocked = item.status != 0;
        let log = if item.apply.contains("logging") {
            Some(csv_row(&[
                now.to_string(),
                r.ip.clone(),
                r.method.clone(),
                r.path.clone(),
                status.to_string(),
                elapsed_ms.to_string(),
                blocked.to_string(),
                item.reason.clone(),
                r.country.clone(),
                r.headers
                    .get("HTTP_USER_AGENT")
                    .cloned()
                    .unwrap_or_default(),
            ]))
        } else {
            None
        };
        let block_csv = block
            .as_ref()
            .map(|(reason, expiry)| csv_row(&[r.ip.clone(), expiry.to_string(), reason.clone()]));
        let keyword_csv = learned.as_ref().map(|keyword| csv_row(&[keyword.clone()]));
        Ok(json!({"log_csv":log,"block_csv":block_csv,"keyword_csv":keyword_csv}).to_string())
    }
    pub fn diagnostics(&self) -> String {
        json!({"native":true,"model":self.model.is_some(),"processed_requests":self.processed,"model_predictions":self.predictions,"clients":self.clients.len(),"pending":self.pending.len(),"blocked":self.blocks.len(),"learned_keywords":self.learned.len()}).to_string()
    }
}
fn csv_row(values: &[String]) -> String {
    values
        .iter()
        .map(|v| {
            if v.contains([',', '"', '\n', '\r']) {
                format!("\"{}\"", v.replace('"', "\"\""))
            } else {
                v.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
        + "\n"
}
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = (bytes[i + 1] as char).to_digit(16);
            let l = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (h, l) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
fn inspect(value: &Value, max_bytes: usize) -> Option<(u16, &'static str)> {
    static RULES: OnceLock<Vec<(&str, Regex)>> = OnceLock::new();
    static COMMENTS: OnceLock<Regex> = OnceLock::new();
    let rules=RULES.get_or_init(||vec![
        ("sql_union_select",Regex::new(r"(?i)\bunion\s+(?:all\s+)?select\b").unwrap()),
        ("sql_boolean_tautology",Regex::new(r#"(?i)['"`]\s*(?:or|and)\s+(?:true\b|\d+\s*=\s*\d+|['"][^'"\r\n]{0,80}['"]\s*=\s*['"])"#).unwrap()),
        ("sql_quote_comment",Regex::new(r#"['"`]\s*(?:--|#)"#).unwrap()),
        ("sql_stacked_statement",Regex::new(r"(?i);\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set)\b").unwrap())]);
    fn visit(
        v: &Value,
        depth: usize,
        nodes: &mut usize,
        bytes: &mut usize,
        max: usize,
        rules: &[(&str, Regex)],
    ) -> Option<(u16, &'static str)> {
        *nodes += 1;
        if *nodes > 4096 || depth > 16 {
            return Some((413, "payload_inspection_limit"));
        }
        match v {
            Value::String(s) => {
                if s.contains('\0') {
                    return Some((403, "content_nul_byte"));
                }
                *bytes += s.len();
                if *bytes > max {
                    return Some((413, "payload_inspection_limit"));
                }
                let normalized = decode(&decode(s));
                if normalized.trim_start().starts_with(['{', '[']) {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&normalized) {
                        if let Some(k) = visit(&parsed, depth + 1, nodes, bytes, max, rules) {
                            return Some(k);
                        }
                    }
                }
                let clean = COMMENTS
                    .get_or_init(|| Regex::new(r"(?s)/\*.*?\*/").unwrap())
                    .replace_all(&normalized, " ");
                for (k, re) in rules {
                    if re.is_match(&clean) {
                        return Some((
                            403,
                            match *k {
                                "sql_union_select" => "sql_union_select",
                                "sql_boolean_tautology" => "sql_boolean_tautology",
                                "sql_quote_comment" => "sql_quote_comment",
                                _ => "sql_stacked_statement",
                            },
                        ));
                    }
                }
            }
            Value::Array(items) => {
                for v in items {
                    if let Some(k) = visit(v, depth + 1, nodes, bytes, max, rules) {
                        return Some(k);
                    }
                }
            }
            Value::Object(items) => {
                for (k, v) in items {
                    if let Some(k) = visit(
                        &Value::String(k.clone()),
                        depth + 1,
                        nodes,
                        bytes,
                        max,
                        rules,
                    )
                    .or_else(|| visit(v, depth + 1, nodes, bytes, max, rules))
                    {
                        return Some(k);
                    }
                }
            }
            _ => {}
        }
        None
    }
    visit(value, 0, &mut 0, &mut 0, max_bytes, rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(ip: &str, path: &str, method: &str, now: f64, body: Value) -> String {
        json!({"ip":ip,"path":path,"method":method,"now":now,"body":body,"query":"","headers":{"HTTP_USER_AGENT":"Mozilla/5.0 Chrome/130 Safari/537.36","HTTP_ACCEPT":"text/html","HTTP_ACCEPT_LANGUAGE":"en","HTTP_ACCEPT_ENCODING":"gzip","HTTP_CONNECTION":"keep-alive"},"country":"","exists":true,"authenticated":false}).to_string()
    }
    fn begin(e: &mut Engine, r: String) -> Value {
        serde_json::from_str(&e.begin(&r).unwrap()).unwrap()
    }
    fn finish(e: &mut Engine, d: &Value, status: u16, now: f64) -> Value {
        serde_json::from_str(
            &e.finish(d["context"].as_str().unwrap(), status, 1.0, now)
                .unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn startup_limits() {
        for p in [
            r#"{"unknown":true}"#,
            r#"{"rate_backend":"redis"}"#,
            r#"{"sql_mode":"monitor"}"#,
            r#"{"rate_flood":1}"#,
            r#"{"max_history":0}"#,
        ] {
            assert!(Engine::new(p).is_err());
        }
    }
    #[test]
    fn blocklist_and_previous_wire_key_enforce_identically() {
        for key in ["blocklist", "blacklist"] {
            let mut profile = json!({"enabled":["ip_keyword_block"], "exempt_paths":[]});
            profile[key] = json!({"8.8.8.8": 1000.0});
            let mut engine = Engine::new(&profile.to_string()).unwrap();
            let decision = begin(&mut engine, request("8.8.8.8", "/api", "GET", 100.0, json!(null)));
            assert_eq!(decision["status"], 403);
        }
    }
    #[test]
    fn structured_sql_and_limits() {
        assert_eq!(
            inspect(&json!({"a":{"b":"%2527+OR+1%253D1--"}}), 65536)
                .unwrap()
                .0,
            403
        );
        assert!(inspect(&json!({"a":"%€ ordinary UTF-8"}), 65536).is_none());
        assert_eq!(inspect(&json!({"a":"abcdef"}), 3).unwrap().0, 413);
        assert_eq!(
            inspect(&json!(r#"{"x":"\u0027 OR 1=1--"}"#), 65536)
                .unwrap()
                .0,
            403
        );
        assert!(inspect(&json!({"name":"O'Reilly","notes":"select a color"}), 65536).is_none());
        assert_eq!(
            inspect(&json!("embedded\0null"), 65536).unwrap().1,
            "content_nul_byte"
        );
    }
    #[test]
    fn rate_atomic_and_isolation() {
        let mut e = Engine::new(r#"{"rate_max":2,"rate_flood":3}"#).unwrap();
        for (i, want) in [0, 0, 429, 403].into_iter().enumerate() {
            let d = begin(
                &mut e,
                request("a", "/", "GET", 100.0 + i as f64, json!(null)),
            );
            assert_eq!(d["status"], want);
            finish(&mut e, &d, if want == 0 { 200 } else { want }, 104.0);
        }
        let mut other = Engine::new("{}").unwrap();
        assert_eq!(
            begin(&mut other, request("a", "/", "GET", 105.0, json!(null)))["status"],
            0
        );
        assert_eq!(
            begin(&mut e, request("a", "/", "GET", 100000.0, json!(null)))["status"],
            0
        );
    }
    #[test]
    fn honeypot_and_response_context() {
        let mut e = Engine::new("{}").unwrap();
        let mut other = Engine::new("{}").unwrap();
        let d = begin(&mut e, request("a", "/form", "GET", 100.0, json!(null)));
        assert!(
            other
                .finish(d["context"].as_str().unwrap(), 200, 1.0, 101.0)
                .is_err()
        );
        assert!(
            e.finish(d["context"].as_str().unwrap(), 0, 1.0, 101.0)
                .is_err()
        );
        let row = finish(&mut e, &d, 200, 99.0);
        assert!(row["log_csv"].as_str().unwrap().contains(",200,1,false,"));
        assert!(
            e.finish(d["context"].as_str().unwrap(), 200, 1.0, 101.0)
                .is_err()
        );
        let d = begin(&mut e, request("a", "/form", "POST", 100.1, json!({})));
        assert_eq!(d["status"], 403);
        let d = begin(&mut other, request("a", "/form", "POST", 100.1, json!({})));
        assert_eq!(d["status"], 0);
    }
    #[test]
    fn exemptions_caps_geo_uuid_and_logging() {
        let mut e = Engine::new(r#"{"geo_block":["XX"]}"#).unwrap();
        let mut r: Value =
            serde_json::from_str(&request("a", "/", "GET", 100.0, json!(null))).unwrap();
        r["country"] = json!("XX");
        let d = begin(&mut e, r.to_string());
        assert_eq!(d["status"], 403);
        r["path"] = json!("/health");
        assert_eq!(begin(&mut e, r.to_string())["status"], 0);
        r["ip"] = json!("b");
        r["country"] = json!("");
        r["path"] = json!("/user/not-a-uuid");
        assert_eq!(begin(&mut e, r.to_string())["status"], 403);
        r["ip"] = json!("c");
        r["path"] = json!("/docs");
        r["headers"] = json!({"HTTP_USER_AGENT":"x".repeat(501)});
        assert_eq!(begin(&mut e, r.to_string())["status"], 403);
        assert_eq!(
            csv_row(&["a,b".into(), "a\"b\nc".into()]),
            "\"a,b\",\"a\"\"b\nc\"\n"
        );
    }
    #[test]
    fn deferred_body_and_context_policy() {
        let mut e = Engine::new(r#"{"honeypot_field":"website"}"#).unwrap();
        let mut r: Value =
            serde_json::from_str(&request("a", "/api", "POST", 100.0, json!(null))).unwrap();
        r["defer_body"] = json!(true);
        let d = begin(&mut e, r.to_string());
        assert_eq!(d["status"], 0);
        let context = d["context"].as_str().unwrap();
        let finding: Value = serde_json::from_str(
            &e.inspect_body(
                context,
                r#"{"nested":{"q":"' OR 1=1--"}}"#,
                false,
                false,
                100.0,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(finding["status"], 403);
        assert!(e.inspect_body(context, "{}", false, false, 100.0).is_err());
        let effects = finish(&mut e, &d, 403, 100.0);
        assert!(
            effects["log_csv"]
                .as_str()
                .unwrap()
                .contains(",true,sql_boolean_tautology,")
        );
        r["ip"] = json!("b");
        r["path"] = json!("/health");
        let d = begin(&mut e, r.to_string());
        assert_eq!(
            e.inspect_body(
                d["context"].as_str().unwrap(),
                r#"{"website":"bot","q":"' OR 1=1--"}"#,
                false,
                false,
                100.0
            )
            .unwrap(),
            "null"
        );
        r["ip"] = json!("c");
        r["path"] = json!("/api");
        let d = begin(&mut e, r.to_string());
        let finding: Value = serde_json::from_str(
            &e.inspect_body(
                d["context"].as_str().unwrap(),
                r#"{"website":"bot"}"#,
                false,
                false,
                100.0,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(finding["rule"], "honeypot_field");
    }
    #[test]
    fn long_stream_survives_state_cleanup() {
        let mut e = Engine::new("{}").unwrap();
        let stream = begin(
            &mut e,
            request("stream", "/stream", "GET", 100.0, json!(null)),
        );
        let other = begin(&mut e, request("other", "/api", "GET", 1000.0, json!(null)));
        finish(&mut e, &other, 200, 1000.0);
        assert!(
            finish(&mut e, &stream, 200, 1001.0)["log_csv"]
                .as_str()
                .unwrap()
                .contains("/stream")
        );
    }
}
