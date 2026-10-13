use aiwaf_core::{
    BehaviorAnalysis, BuiltFeatureRecord, Contamination, FeatureBatchResult, FeatureRecordInput,
    FeatureRecordOutput, FeatureState, IsolationForest as CoreForest, IsolationForestState,
    KeywordMatcher as CoreKeywordMatcher, MaxFeatures, MaxSamples, ParsedFeatureRecord, RawFeatureRecord,
    RouteMatcher as CoreRouteMatcher,
    RecentEntryInput, analyze_recent_behavior as core_analyze_recent_behavior,
    build_records as core_build_records, extract_features as core_extract_features,
    extract_features_batch_with_state as core_extract_features_batch_with_state,
    extract_raw_features as core_extract_raw_features,
    extract_training_features as core_extract_training_features,
    finalize_feature_state as core_finalize_feature_state,
    rust_payload_from_records as core_rust_payload_from_records,
    validate_headers_with_config as core_validate_headers_with_config,
    validate_url as core_validate_url, validate_content as core_validate_content,
};
use js_sys::{Array, Function, Map};
use serde_wasm_bindgen::{from_value, to_value};
use std::collections::HashMap;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{Headers, Window};
mod request_pipeline;

/// Explicit stateful request engine. No JavaScript policy fallback.
#[wasm_bindgen]
pub struct NativeRequestPipeline {
    inner: request_pipeline::Engine,
}

#[wasm_bindgen]
impl NativeRequestPipeline {
    #[wasm_bindgen(constructor)]
    pub fn new(profile: &str) -> Result<NativeRequestPipeline, JsValue> {
        Ok(Self { inner: request_pipeline::Engine::new(profile).map_err(|e| JsValue::from_str(&e))? })
    }
    pub fn begin(&mut self, request: &str) -> Result<String, JsValue> {
        self.inner.begin(request).map_err(|e| JsValue::from_str(&e))
    }
    pub fn finish(&mut self, context: &str, status: u16, elapsed_ms: f64, now: f64) -> Result<String, JsValue> {
        self.inner.finish(context, status, elapsed_ms, now).map_err(|e| JsValue::from_str(&e))
    }
    pub fn inspect_payload(&self, payload: &str) -> Result<String, JsValue> {
        self.inner.inspect_payload(payload).map_err(|e| JsValue::from_str(&e))
    }
    pub fn inspect_body(&mut self, context:&str, payload:&str, exhausted:bool, authenticated:bool, now:f64)->Result<String,JsValue> {
        self.inner.inspect_body(context,payload,exhausted,authenticated,now).map_err(|e|JsValue::from_str(&e))
    }
    pub fn set_model(&mut self, model: &IsolationForest) -> Result<(), JsValue> {
        self.inner.set_model(model.inner.clone()).map_err(|e| JsValue::from_str(&e))
    }
    pub fn clear_model(&mut self) { self.inner.model = None; }
    pub fn diagnostics(&self) -> String { self.inner.diagnostics() }
}

#[wasm_bindgen]
pub struct KeywordMatcher {
    inner: CoreKeywordMatcher,
}

#[wasm_bindgen]
impl KeywordMatcher {
    #[wasm_bindgen(constructor)]
    pub fn new(keywords: JsValue) -> Result<KeywordMatcher, JsValue> {
        let keywords: Vec<String> = from_value(keywords)?;
        Ok(Self {
            inner: CoreKeywordMatcher::new(keywords)
                .map_err(|err| JsValue::from_str(&err.to_string()))?,
        })
    }

    pub fn first_match(&self, path: &str) -> Option<String> {
        self.inner.first_match(path).map(str::to_string)
    }
}

#[wasm_bindgen]
pub struct RouteMatcher {
    inner: CoreRouteMatcher,
}

#[wasm_bindgen]
impl RouteMatcher {
    #[wasm_bindgen(constructor)]
    pub fn new(prefixes: JsValue) -> Result<RouteMatcher, JsValue> {
        let prefixes: Vec<String> = from_value(prefixes)?;
        Ok(Self {
            inner: CoreRouteMatcher::new(prefixes),
        })
    }

    pub fn match_index(&self, path: &str) -> Option<u32> {
        self.inner.match_index(path).map(|index| index as u32)
    }
}

fn headers_js_to_map(headers: JsValue) -> Result<HashMap<String, String>, JsValue> {
    if let Ok(map) = from_value::<HashMap<String, String>>(headers.clone()) {
        return Ok(map);
    }

    // Try treating as a Headers object (e.g., fetch Request headers)
    if let Ok(h) = headers.clone().dyn_into::<Headers>() {
        let mut map = HashMap::new();
        let entries = h.entries();
        if let Some(mut iter) = js_sys::try_iter(&entries)? {
            while let Some(item) = iter.next() {
                let value = item?;
                let pair = Array::from(&value);
                if pair.length() >= 2 {
                    let key = pair.get(0).as_string().unwrap_or_default();
                    let value = pair.get(1).as_string().unwrap_or_default();
                    if !key.is_empty() {
                        map.insert(key, value);
                    }
                }
            }
            return Ok(map);
        }
    }

    // Try treating as a plain object with string values
    let obj = js_sys::Object::from(headers);
    let keys = js_sys::Object::keys(&obj);
    let mut map = HashMap::new();
    for key in keys.iter() {
        let k = key.as_string().unwrap_or_default();
        if k.is_empty() {
            continue;
        }
        let v = js_sys::Reflect::get(&obj, &key).unwrap_or(JsValue::UNDEFINED);
        let value = v.as_string().unwrap_or_else(|| format!("{v:?}"));
        map.insert(k, value);
    }
    Ok(map)
}

fn add_navigator_ua_if_missing(map: &mut HashMap<String, String>) {
    if map.contains_key("user-agent") {
        return;
    }
    let ua = web_sys::window()
        .and_then(|w: Window| w.navigator().user_agent().ok())
        .unwrap_or_default();
    if !ua.is_empty() {
        map.insert("user-agent".to_string(), ua);
    }
}

#[wasm_bindgen]
pub fn validate_headers(headers: JsValue) -> Result<JsValue, JsValue> {
    let mut map = headers_js_to_map(headers)?;
    add_navigator_ua_if_missing(&mut map);
    to_value(&core_validate_headers_with_config(
        &map,
        Some(vec![]),
        Some(0),
    ))
    .map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn validate_headers_with_config(
    headers: JsValue,
    required_headers: JsValue,
    min_score: JsValue,
) -> Result<JsValue, JsValue> {
    let mut map = headers_js_to_map(headers)?;
    add_navigator_ua_if_missing(&mut map);
    let required: Option<Vec<String>> =
        if required_headers.is_null() || required_headers.is_undefined() {
            None
        } else {
            Some(from_value(required_headers)?)
        };
    let min_score: Option<i32> = if min_score.is_null() || min_score.is_undefined() {
        None
    } else {
        Some(from_value(min_score)?)
    };
    to_value(&core_validate_headers_with_config(
        &map, required, min_score,
    ))
    .map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn validate_url(url: &str) -> Result<JsValue, JsValue> {
    to_value(&core_validate_url(url)).map_err(|error| error.into())
}

#[wasm_bindgen]
pub fn validate_content(content: &str) -> Result<JsValue, JsValue> {
    to_value(&core_validate_content(content)).map_err(|error| error.into())
}

#[wasm_bindgen]
pub fn build_records(
    parsed: JsValue,
    ip_404: JsValue,
    path_exists_fn: JsValue,
    path_exempt_fn: JsValue,
    status_idx_list: JsValue,
) -> Result<JsValue, JsValue> {
    let parsed = parse_parsed_records(parsed)?;
    let ip_404: HashMap<String, i32> = from_value(ip_404)?;
    let status_idx_list: Vec<i32> = from_value(status_idx_list)?;
    let path_exists_fn = path_exists_fn
        .dyn_into::<Function>()
        .map_err(|_| JsValue::from_str("path_exists_fn must be a function"))?;
    let path_exempt_fn = path_exempt_fn
        .dyn_into::<Function>()
        .map_err(|_| JsValue::from_str("path_exempt_fn must be a function"))?;

    let records = core_build_records(
        parsed,
        &ip_404,
        |path| {
            path_exists_fn
                .call1(&JsValue::NULL, &JsValue::from_str(path))
                .map(|value| value.as_bool().unwrap_or(false))
                .map_err(|_| ())
        },
        |path| {
            path_exempt_fn
                .call1(&JsValue::NULL, &JsValue::from_str(path))
                .map(|value| value.as_bool().unwrap_or(false))
                .map_err(|_| ())
        },
        &status_idx_list,
    );
    to_value(&records).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn rust_payload_from_records(records: JsValue) -> Result<JsValue, JsValue> {
    let records = parse_built_records(records)?;
    to_value(&core_rust_payload_from_records(&records)).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn python_feature_from_record(
    record: JsValue,
    ip_times: JsValue,
    static_keywords: JsValue,
) -> Result<JsValue, JsValue> {
    let record = parse_built_record(record)?;
    let ip_times = parse_ip_times(ip_times)?;
    let static_keywords: Vec<String> = from_value(static_keywords)?;
    to_value(&feature_from_built_record(
        &record,
        &ip_times,
        &static_keywords,
    ))
    .map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn python_features_batched(
    records: JsValue,
    ip_times: JsValue,
    static_keywords: JsValue,
    _iter_batches_fn: JsValue,
    batch_size: i32,
    _parallel_enabled: bool,
    _parallel_chunk_size: i32,
    _max_workers: i32,
) -> Result<JsValue, JsValue> {
    let records = parse_built_records(records)?;
    if records.is_empty() {
        return to_value(&Vec::<FeatureRecordOutput>::new()).map_err(|e| e.into());
    }

    let ip_times = parse_ip_times(ip_times)?;
    let static_keywords: Vec<String> = from_value(static_keywords)?;
    let batch_size = batch_size.max(1) as usize;
    let mut features = Vec::with_capacity(records.len());
    for batch in records.chunks(batch_size) {
        for record in batch {
            features.push(feature_from_built_record(
                record,
                &ip_times,
                &static_keywords,
            ));
        }
    }
    to_value(&features).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn extract_features(records: JsValue, static_keywords: JsValue) -> Result<JsValue, JsValue> {
    let records: Vec<FeatureRecordInput> = from_value(records)?;
    let keywords: Vec<String> = from_value(static_keywords)?;
    let out: Vec<FeatureRecordOutput> = core_extract_features(records, keywords);
    to_value(&out).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn extract_training_features(
    records: JsValue,
    static_keywords: JsValue,
) -> Result<JsValue, JsValue> {
    let records: Vec<FeatureRecordInput> = from_value(records)?;
    let keywords: Vec<String> = from_value(static_keywords)?;
    to_value(&core_extract_training_features(records, keywords)).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn extract_raw_training_features(
    records: JsValue,
    static_keywords: JsValue,
    status_indices: JsValue,
) -> Result<JsValue, JsValue> {
    let rows = Array::from(&records);
    let mut parsed = Vec::with_capacity(rows.length() as usize);
    for row in rows.iter() {
        let obj = row
            .dyn_into::<js_sys::Object>()
            .map_err(|_| JsValue::from_str("training records must be objects"))?;
        let timestamp = get_value(&obj, "timestamp")
            .ok_or_else(|| JsValue::from_str("timestamp is required"))?;
        let timestamp = js_sys::Date::new(&timestamp).get_time() / 1000.0;
        if !timestamp.is_finite() {
            return Err(JsValue::from_str("timestamp must be a valid date"));
        }
        let response_time = match get_value(&obj, "responseTime") {
            Some(value) => js_sys::Number::from(value).value_of(),
            None => get_f64_required(&obj, "response_time")?,
        };
        if !response_time.is_finite() {
            return Err(JsValue::from_str("responseTime must be finite"));
        }
        let status = get_value(&obj, "status")
            .ok_or_else(|| JsValue::from_str("status is required"))?;
        let status = status
            .as_string()
            .or_else(|| status.as_f64().map(|value| value.to_string()))
            .ok_or_else(|| JsValue::from_str("status must be a string or number"))?;
        parsed.push(RawFeatureRecord {
            ip: get_string_required(&obj, "ip")?,
            path: get_string_required(&obj, "path")?,
            timestamp,
            response_time,
            status,
        });
    }
    let keywords: Vec<String> = from_value(static_keywords)?;
    let statuses: Vec<String> = from_value(status_indices)?;
    to_value(&core_extract_raw_features(
        parsed,
        keywords,
        &statuses,
        &HashMap::new(),
        None,
        true,
    ))
    .map_err(|error| error.into())
}

#[wasm_bindgen]
pub fn extract_features_batch_with_state(
    records: JsValue,
    static_keywords: JsValue,
    state: JsValue,
) -> Result<JsValue, JsValue> {
    let records: Vec<FeatureRecordInput> = from_value(records)?;
    let keywords: Vec<String> = from_value(static_keywords)?;
    let state: Option<FeatureState> = if state.is_null() || state.is_undefined() {
        None
    } else {
        Some(from_value(state)?)
    };
    let result: FeatureBatchResult =
        core_extract_features_batch_with_state(records, keywords, state);
    to_value(&result).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn finalize_feature_state() -> Result<JsValue, JsValue> {
    let result: FeatureBatchResult = core_finalize_feature_state();
    to_value(&result).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn analyze_recent_behavior(
    entries: JsValue,
    static_keywords: JsValue,
) -> Result<JsValue, JsValue> {
    let entries: Vec<RecentEntryInput> = from_value(entries)?;
    let keywords: Vec<String> = from_value(static_keywords)?;
    let result: Option<BehaviorAnalysis> = core_analyze_recent_behavior(entries, keywords);
    to_value(&result).map_err(|e| e.into())
}

struct JsForestConfig {
    n_estimators: usize,
    max_samples: Option<JsValue>,
    contamination: Option<JsValue>,
    max_features: Option<JsValue>,
    bootstrap: bool,
    random_state: Option<u64>,
    verbose: usize,
    warm_start: bool,
}

impl JsForestConfig {
    fn default() -> Self {
        Self {
            n_estimators: 100,
            max_samples: None,
            contamination: None,
            max_features: None,
            bootstrap: false,
            random_state: None,
            verbose: 0,
            warm_start: false,
        }
    }
}

#[wasm_bindgen]
pub struct IsolationForest {
    inner: CoreForest,
}

#[wasm_bindgen]
impl IsolationForest {
    #[wasm_bindgen(constructor)]
    pub fn new(config: Option<JsValue>) -> Result<IsolationForest, JsValue> {
        let cfg = match config {
            None => JsForestConfig::default(),
            Some(v) if v.is_null() || v.is_undefined() => JsForestConfig::default(),
            Some(v) => parse_config_object(v)?,
        };

        let max_samples = parse_max_samples(cfg.max_samples)?;
        let contamination = parse_contamination(cfg.contamination)?;
        let max_features = parse_max_features(cfg.max_features)?;

        let inner = CoreForest::new(
            cfg.n_estimators,
            max_samples,
            contamination,
            max_features,
            cfg.bootstrap,
            cfg.random_state,
            cfg.verbose,
            cfg.warm_start,
        );
        Ok(IsolationForest { inner })
    }

    pub fn fit(&mut self, data: JsValue) -> Result<(), JsValue> {
        let data: Vec<Vec<f64>> = from_value(data)?;
        self.inner.fit(data);
        Ok(())
    }

    pub fn retrain(&mut self, data: JsValue) -> Result<(), JsValue> {
        let data: Vec<Vec<f64>> = from_value(data)?;
        self.inner.retrain(data);
        Ok(())
    }

    pub fn anomaly_score(&self, point: JsValue) -> Result<f64, JsValue> {
        let point: Vec<f64> = from_value(point)?;
        Ok(self.inner.anomaly_score(&point))
    }

    pub fn is_anomaly(&self, point: JsValue, thresh: Option<f64>) -> Result<bool, JsValue> {
        let point: Vec<f64> = from_value(point)?;
        let t = thresh.unwrap_or(0.5);
        Ok(self.inner.is_anomaly(&point, t))
    }

    pub fn score_samples(&self, data: JsValue) -> Result<JsValue, JsValue> {
        let data: Vec<Vec<f64>> = from_value(data)?;
        to_value(&self.inner.score_samples(&data)).map_err(|e| e.into())
    }

    pub fn decision_function(&self, data: JsValue) -> Result<JsValue, JsValue> {
        let data: Vec<Vec<f64>> = from_value(data)?;
        to_value(&self.inner.decision_function(&data)).map_err(|e| e.into())
    }

    pub fn predict(&self, data: JsValue) -> Result<JsValue, JsValue> {
        let data: Vec<Vec<f64>> = from_value(data)?;
        to_value(&self.inner.predict(&data)).map_err(|e| e.into())
    }

    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        let state: IsolationForestState = self.inner.to_state();
        to_value(&state).map_err(|e| e.into())
    }

    #[allow(unused_variables)]
    #[wasm_bindgen(static_method_of = IsolationForest)]
    pub fn from_json(state: JsValue) -> Result<IsolationForest, JsValue> {
        let state: IsolationForestState = from_value(state)?;
        Ok(IsolationForest {
            inner: CoreForest::from_state(state),
        })
    }
}

fn parse_max_samples(value: Option<JsValue>) -> Result<MaxSamples, JsValue> {
    match value {
        None => Ok(MaxSamples::Auto),
        Some(v) if v.is_null() || v.is_undefined() => Ok(MaxSamples::Auto),
        Some(v) => {
            if let Ok(s) = from_value::<String>(v.clone()) {
                if s == "auto" {
                    return Ok(MaxSamples::Auto);
                }
            }
            if let Ok(i) = from_value::<u32>(v.clone()) {
                return Ok(MaxSamples::Int(i as usize));
            }
            if let Ok(f) = from_value::<f64>(v) {
                return Ok(MaxSamples::Float(f));
            }
            Err(JsValue::from_str(
                "max_samples must be 'auto', int, or float",
            ))
        }
    }
}

fn parse_max_features(value: Option<JsValue>) -> Result<MaxFeatures, JsValue> {
    match value {
        None => Ok(MaxFeatures::Float(1.0)),
        Some(v) if v.is_null() || v.is_undefined() => Ok(MaxFeatures::Float(1.0)),
        Some(v) => {
            if let Ok(i) = from_value::<u32>(v.clone()) {
                return Ok(MaxFeatures::Int(i as usize));
            }
            if let Ok(f) = from_value::<f64>(v) {
                return Ok(MaxFeatures::Float(f));
            }
            Err(JsValue::from_str("max_features must be int or float"))
        }
    }
}

fn parse_contamination(value: Option<JsValue>) -> Result<Contamination, JsValue> {
    match value {
        None => Ok(Contamination::Auto),
        Some(v) if v.is_null() || v.is_undefined() => Ok(Contamination::Auto),
        Some(v) => {
            if let Ok(s) = from_value::<String>(v.clone()) {
                if s == "auto" {
                    return Ok(Contamination::Auto);
                }
            }
            if let Ok(f) = from_value::<f64>(v) {
                if f > 0.0 && f <= 0.5 {
                    return Ok(Contamination::Fixed(f));
                }
            }
            Err(JsValue::from_str(
                "contamination must be 'auto' or float in (0, 0.5]",
            ))
        }
    }
}

fn parse_config_object(value: JsValue) -> Result<JsForestConfig, JsValue> {
    let obj = value
        .dyn_into::<js_sys::Object>()
        .map_err(|_| JsValue::from_str("config must be an object"))?;
    let n_estimators = get_u64(&obj, "n_estimators")?.unwrap_or(100) as usize;
    let bootstrap = get_bool(&obj, "bootstrap")?.unwrap_or(false);
    let verbose = get_u64(&obj, "verbose")?.unwrap_or(0) as usize;
    let warm_start = get_bool(&obj, "warm_start")?.unwrap_or(false);
    let random_state = get_u64(&obj, "random_state")?;
    let max_samples = get_value(&obj, "max_samples");
    let contamination = get_value(&obj, "contamination");
    let max_features = get_value(&obj, "max_features");

    Ok(JsForestConfig {
        n_estimators,
        max_samples,
        contamination,
        max_features,
        bootstrap,
        random_state,
        verbose,
        warm_start,
    })
}

fn get_value(obj: &js_sys::Object, key: &str) -> Option<JsValue> {
    let key = JsValue::from_str(key);
    if let Ok(value) = js_sys::Reflect::get(obj, &key) {
        if !value.is_undefined() && !value.is_null() {
            return Some(value);
        }
    }

    let value = JsValue::from(obj.clone());
    let map = value.dyn_ref::<Map>()?;
    let value = map.get(&key);
    if value.is_undefined() || value.is_null() {
        None
    } else {
        Some(value)
    }
}

fn get_u64(obj: &js_sys::Object, key: &str) -> Result<Option<u64>, JsValue> {
    match get_value(obj, key) {
        None => Ok(None),
        Some(v) => {
            let n = js_sys::Number::from(v).value_of();
            if n.is_finite() && n >= 0.0 {
                Ok(Some(n as u64))
            } else {
                Err(JsValue::from_str(&format!(
                    "{} must be a non-negative number",
                    key
                )))
            }
        }
    }
}

fn get_bool(obj: &js_sys::Object, key: &str) -> Result<Option<bool>, JsValue> {
    match get_value(obj, key) {
        None => Ok(None),
        Some(v) => Ok(Some(v.as_bool().unwrap_or(false))),
    }
}

fn parse_parsed_records(value: JsValue) -> Result<Vec<ParsedFeatureRecord>, JsValue> {
    if let Ok(records) = from_value::<Vec<ParsedFeatureRecord>>(value.clone()) {
        return Ok(records);
    }

    let rows = Array::from(&value);
    let mut records = Vec::with_capacity(rows.length() as usize);
    for row in rows.iter() {
        let obj = row
            .dyn_into::<js_sys::Object>()
            .map_err(|_| JsValue::from_str("parsed records must be objects"))?;
        records.push(ParsedFeatureRecord {
            ip: get_string_required(&obj, "ip")?,
            path: get_string_required(&obj, "path")?,
            response_time: get_f64_required(&obj, "response_time")?,
            status: get_f64_required(&obj, "status")? as i32,
            timestamp: get_timestamp_required(&obj, "timestamp")?,
        });
    }
    Ok(records)
}

fn parse_built_records(value: JsValue) -> Result<Vec<BuiltFeatureRecord>, JsValue> {
    let rows = Array::from(&value);
    let mut records = Vec::with_capacity(rows.length() as usize);
    for row in rows.iter() {
        records.push(parse_built_record(row)?);
    }
    Ok(records)
}

fn parse_built_record(value: JsValue) -> Result<BuiltFeatureRecord, JsValue> {
    if let Ok(record) = from_value::<BuiltFeatureRecord>(value.clone()) {
        return Ok(record);
    }

    let obj = value
        .dyn_into::<js_sys::Object>()
        .map_err(|_| JsValue::from_str("record must be an object"))?;
    let timestamp_epoch = match get_value(&obj, "timestamp_epoch") {
        Some(value) => timestamp_epoch(value)?,
        None => get_timestamp_required(&obj, "timestamp")?,
    };
    Ok(BuiltFeatureRecord {
        ip: get_string_required(&obj, "ip")?,
        path_len: get_f64_required(&obj, "path_len")? as usize,
        path_lower: get_string_required(&obj, "path_lower")?,
        resp_time: get_f64_required(&obj, "resp_time")?,
        status_idx: get_f64_required(&obj, "status_idx")? as i32,
        timestamp: timestamp_epoch,
        timestamp_epoch,
        kw_check: get_bool_required(&obj, "kw_check")?,
        total_404: get_f64_required(&obj, "total_404")? as i32,
    })
}

fn parse_ip_times(value: JsValue) -> Result<HashMap<String, Vec<f64>>, JsValue> {
    if let Ok(map) = from_value::<HashMap<String, Vec<f64>>>(value.clone()) {
        return Ok(map);
    }

    if let Some(js_map) = value.dyn_ref::<Map>() {
        let entries = Array::from(&js_map.entries());
        let mut map = HashMap::new();
        for entry in entries.iter() {
            let pair = Array::from(&entry);
            if pair.length() < 2 {
                continue;
            }
            let key = pair.get(0).as_string().unwrap_or_default();
            if key.is_empty() {
                continue;
            }
            let values = Array::from(&pair.get(1));
            let mut timestamps = Vec::with_capacity(values.length() as usize);
            for value in values.iter() {
                timestamps.push(timestamp_epoch(value)?);
            }
            map.insert(key, timestamps);
        }
        return Ok(map);
    }

    let obj = value
        .dyn_into::<js_sys::Object>()
        .map_err(|_| JsValue::from_str("ip_times must be an object"))?;
    let keys = js_sys::Object::keys(&obj);
    let mut map = HashMap::new();
    for key_value in keys.iter() {
        let key = key_value.as_string().unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let values = Array::from(&js_sys::Reflect::get(&obj, &key_value)?);
        let mut timestamps = Vec::with_capacity(values.length() as usize);
        for value in values.iter() {
            timestamps.push(timestamp_epoch(value)?);
        }
        map.insert(key, timestamps);
    }
    Ok(map)
}

fn feature_from_built_record(
    record: &BuiltFeatureRecord,
    ip_times: &HashMap<String, Vec<f64>>,
    static_keywords: &[String],
) -> FeatureRecordOutput {
    let kw_hits = if record.kw_check {
        static_keywords
            .iter()
            .filter(|keyword| record.path_lower.contains(keyword.as_str()))
            .count() as i32
    } else {
        0
    };
    let burst_count = ip_times
        .get(&record.ip)
        .map(|timestamps| {
            timestamps
                .iter()
                .filter(|timestamp| record.timestamp - **timestamp <= 10.0)
                .count() as i32
        })
        .unwrap_or(0);

    FeatureRecordOutput {
        ip: record.ip.clone(),
        path_len: record.path_len,
        kw_hits,
        resp_time: record.resp_time,
        status_idx: record.status_idx,
        burst_count,
        total_404: record.total_404,
    }
}

fn get_string_required(obj: &js_sys::Object, key: &str) -> Result<String, JsValue> {
    get_value(obj, key)
        .and_then(|value| value.as_string())
        .ok_or_else(|| JsValue::from_str(&format!("{key} must be a string")))
}

fn get_f64_required(obj: &js_sys::Object, key: &str) -> Result<f64, JsValue> {
    match get_value(obj, key) {
        Some(value) => {
            let number = js_sys::Number::from(value).value_of();
            if number.is_finite() {
                Ok(number)
            } else {
                Err(JsValue::from_str(&format!("{key} must be a finite number")))
            }
        }
        None => Err(JsValue::from_str(&format!("{key} is required"))),
    }
}

fn get_bool_required(obj: &js_sys::Object, key: &str) -> Result<bool, JsValue> {
    get_value(obj, key)
        .and_then(|value| value.as_bool())
        .ok_or_else(|| JsValue::from_str(&format!("{key} must be a boolean")))
}

fn get_timestamp_required(obj: &js_sys::Object, key: &str) -> Result<f64, JsValue> {
    match get_value(obj, key) {
        Some(value) => timestamp_epoch(value),
        None => Err(JsValue::from_str(&format!("{key} is required"))),
    }
}

fn timestamp_epoch(value: JsValue) -> Result<f64, JsValue> {
    if let Some(number) = value.as_f64() {
        if number.is_finite() {
            return Ok(number);
        }
    }

    let get_time = js_sys::Reflect::get(&value, &JsValue::from_str("getTime"))?;
    if let Some(get_time) = get_time.dyn_ref::<Function>() {
        let millis = js_sys::Number::from(get_time.call0(&value)?).value_of();
        if millis.is_finite() {
            return Ok(millis / 1000.0);
        }
    }

    Err(JsValue::from_str(
        "timestamp must be an epoch number or Date",
    ))
}
