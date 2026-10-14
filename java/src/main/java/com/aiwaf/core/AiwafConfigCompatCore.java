package com.aiwaf.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class AiwafConfigCompatCore {
    private AiwafConfigCompatCore() {}

    public static AiwafConfig fromStructured(Map<String, Object> settings) {
        AiwafConfig cfg = new AiwafConfig();
        applyStructured(cfg, settings);
        return cfg;
    }

    public static AiwafConfig fromStructuredAndEnv(Map<String, Object> settings, Map<String, String> env) {
        AiwafConfig cfg = fromStructured(settings);
        applyEnv(cfg, env);
        return cfg;
    }

    public static void applyStructured(AiwafConfig cfg, Map<String, Object> settings) {
        if (cfg == null || settings == null) return;

        Map<String, Object> storage = map(settings.get("storage"));
        cfg.storageBackend = str(storage.get("backend"), cfg.storageBackend);
        cfg.storageFilePath = str(storage.get("file_path"), cfg.storageFilePath);
        cfg.storageRedisUrl = str(storage.get("redis_url"), cfg.storageRedisUrl);
        cfg.storageKeyPrefix = str(storage.get("key_prefix"), cfg.storageKeyPrefix);
        cfg.storageRedisMode = str(storage.get("redis_mode"), cfg.storageRedisMode);
        cfg.storageRedisFailureMode = str(storage.get("redis_failure_mode"), cfg.storageRedisFailureMode);
        cfg.storageRedisConnectionTimeoutMillis = intval(
                storage.get("redis_connection_timeout_millis"), cfg.storageRedisConnectionTimeoutMillis);
        cfg.storageRedisSocketTimeoutMillis = intval(
                storage.get("redis_socket_timeout_millis"), cfg.storageRedisSocketTimeoutMillis);
        cfg.storageRedisPoolMaxTotal = intval(
                storage.get("redis_pool_max_total"), cfg.storageRedisPoolMaxTotal);
        cfg.storageRedisPoolMaxIdle = intval(
                storage.get("redis_pool_max_idle"), cfg.storageRedisPoolMaxIdle);
        cfg.storageRedisPoolMinIdle = intval(
                storage.get("redis_pool_min_idle"), cfg.storageRedisPoolMinIdle);
        cfg.storageRedisPoolMaxWaitMillis = intval(
                storage.get("redis_pool_max_wait_millis"), cfg.storageRedisPoolMaxWaitMillis);

        Map<String, Object> hv = map(settings.get("header_validation"));
        cfg.headerValidationEnabled = bool(hv.get("enabled"), cfg.headerValidationEnabled);
        cfg.minHeaderQualityScore = intval(hv.get("quality_threshold"), cfg.minHeaderQualityScore);
        cfg.maxHeaderBytes = intval(hv.get("max_header_bytes"), cfg.maxHeaderBytes);
        cfg.maxHeaderCount = intval(hv.get("max_header_count"), cfg.maxHeaderCount);
        cfg.maxUserAgentLength = intval(hv.get("max_user_agent_length"), cfg.maxUserAgentLength);
        cfg.maxAcceptLength = intval(hv.get("max_accept_length"), cfg.maxAcceptLength);
        cfg.exemptPaths.addAll(strSet(hv.get("exempt_paths")));

        Map<String, Object> rl = map(settings.get("rate_limiting"));
        cfg.rateLimitEnabled = bool(rl.get("enabled"), cfg.rateLimitEnabled);
        cfg.rateLimitWindowSeconds = intval(rl.get("window_seconds"), cfg.rateLimitWindowSeconds);
        cfg.rateLimitMax = intval(rl.get("max_requests"), cfg.rateLimitMax);
        cfg.rateLimitFloodThreshold = intval(rl.get("flood_threshold"), cfg.rateLimitFloodThreshold);
        String keyMode = str(rl.get("key_mode"), "ip_path");
        cfg.rateLimitScope = Set.of("ip", "global_ip", "global-ip").contains(keyMode.toLowerCase(Locale.ROOT))
                ? AiwafConfig.RateLimitScope.GLOBAL_IP : AiwafConfig.RateLimitScope.PER_PATH;
        cfg.blockIpOnRateLimitBreach = bool(rl.get("soft_block_blocklist"), cfg.blockIpOnRateLimitBreach);
        cfg.blockIpOnFloodBreach = bool(rl.get("block_ip_on_flood"), cfg.blockIpOnFloodBreach);
        String cacheBackend = str(rl.get("cache_backend"), "memory");
        if ("redis".equalsIgnoreCase(cacheBackend)) cfg.storageBackend = "redis";
        cfg.storageRedisUrl = str(rl.get("redis_url"), cfg.storageRedisUrl);
        cfg.storageKeyPrefix = str(rl.get("cache_key_prefix"), cfg.storageKeyPrefix);
        cfg.exemptIps.addAll(strSet(rl.get("exempt_ips")));

        Map<String, Object> hp = map(settings.get("honeypot"));
        cfg.honeypotEnabled = bool(hp.get("enabled"), cfg.honeypotEnabled);
        cfg.minFormTimeSeconds = dbl(hp.get("min_form_time"), cfg.minFormTimeSeconds);
        cfg.maxFormPageTimeSeconds = dbl(hp.get("max_page_time"), cfg.maxFormPageTimeSeconds);
        cfg.loginMinFormTimeSeconds = dbl(hp.get("login_min_form_time"), cfg.loginMinFormTimeSeconds);
        Set<String> loginPrefixes = strSet(hp.get("login_path_prefixes"));
        if (!loginPrefixes.isEmpty()) cfg.loginPathPrefixes = loginPrefixes;

        Map<String, Object> ik = map(settings.get("ip_keyword_block"));
        cfg.ipKeywordBlockEnabled = bool(ik.get("enabled"), cfg.ipKeywordBlockEnabled);
        Set<String> mk = strSet(ik.get("malicious_keywords"));
        if (!mk.isEmpty()) cfg.blockedPathPatterns = new HashSet<>(mk);
        cfg.enableKeywordLearning = bool(ik.get("enable_learning"), cfg.enableKeywordLearning);
        cfg.dynamicTopN = intval(ik.get("dynamic_top_n"), cfg.dynamicTopN);

        Map<String, Object> geo = map(settings.get("geo_block"));
        cfg.geoBlockEnabled = bool(geo.get("enabled"), cfg.geoBlockEnabled);
        cfg.geoBlockedCountries.addAll(upperSet(geo.get("block_countries")));
        cfg.geoAllowedCountries.addAll(upperSet(geo.get("allow_countries")));
        cfg.geoIpDatabasePath = str(or(geo.get("database_path"), geo.get("mmdb_path")), cfg.geoIpDatabasePath);
        cfg.geoCacheSeconds = intval(geo.get("cache_seconds"), cfg.geoCacheSeconds);
        cfg.geoMaxCacheEntries = intval(geo.get("max_cache_entries"), cfg.geoMaxCacheEntries);
        cfg.geoExemptPaths.addAll(strSet(geo.get("exempt_paths")));

        Map<String, Object> manifest = map(settings.get("path_manifest"));
        cfg.pathManifestEnabled = bool(manifest.get("enabled"), cfg.pathManifestEnabled);
        cfg.pathManifestPath = str(manifest.get("path"), cfg.pathManifestPath);

        Map<String, Object> ai = map(settings.get("ai_anomaly"));
        cfg.aiEnabled = bool(ai.get("enabled"), cfg.aiEnabled);
        cfg.aiAnomalyScoreThreshold = dbl(ai.get("threshold"), cfg.aiAnomalyScoreThreshold);
        cfg.aiModelPath = str(ai.get("model_path"), cfg.aiModelPath);
        cfg.aiLazyLoadModel = bool(ai.get("lazy_load"), cfg.aiLazyLoadModel);
        cfg.aiBackgroundPreload = bool(ai.get("background_preload"), cfg.aiBackgroundPreload);
        cfg.aiRequireBehaviorConfirmation = bool(ai.get("require_behavior_confirmation"), cfg.aiRequireBehaviorConfirmation);
        cfg.aiRecentWindowSeconds = intval(ai.get("recent_window_seconds"), cfg.aiRecentWindowSeconds);
        cfg.aiMinRecentSamplesToBlock = intval(ai.get("min_recent_samples_to_block"), cfg.aiMinRecentSamplesToBlock);

        Map<String, Object> uuid = map(settings.get("uuid_tamper"));
        cfg.uuidTamperEnabled = bool(uuid.get("enabled"), cfg.uuidTamperEnabled);
        cfg.uuidScoreEnabled = bool(or(uuid.get("score_enabled"), uuid.get("scoring_enabled")), cfg.uuidScoreEnabled);
        cfg.uuidScoreWindowSeconds = intval(uuid.get("window_seconds"), cfg.uuidScoreWindowSeconds);
        cfg.uuidScoreBlockThreshold = intval(uuid.get("block_threshold"), cfg.uuidScoreBlockThreshold);
        cfg.uuidMalformedWeight = intval(uuid.get("malformed_weight"), cfg.uuidMalformedWeight);
        cfg.uuidNotFoundWeight = intval(uuid.get("not_found_weight"), cfg.uuidNotFoundWeight);
        cfg.uuidSuccessDecay = intval(uuid.get("success_decay"), cfg.uuidSuccessDecay);
        Set<String> uuidParameterNames = strSet(uuid.get("parameter_names"));
        if (!uuidParameterNames.isEmpty()) cfg.uuidParameterNames = uuidParameterNames;

        Map<String, Object> ex = map(settings.get("exemptions"));
        cfg.privateIpsExempted = bool(ex.get("private_ips_exempted"), cfg.privateIpsExempted);
        cfg.localhostExempted = bool(ex.get("localhost_exempted"), cfg.localhostExempted);
        cfg.exemptIps.addAll(strSet(ex.get("ips")));
        Set<String> autoExemptPatterns = strSet(ex.get("auto_exempt_patterns"));
        cfg.exemptIpPatterns.addAll(autoExemptPatterns);
        cfg.exemptIps.addAll(autoExemptPatterns);
        cfg.exemptPaths.addAll(strSet(ex.get("paths")));
        cfg.exemptAllowWildcards = bool(ex.get("allow_wildcards"), cfg.exemptAllowWildcards);
        cfg.exemptAllowPrefix = bool(ex.get("allow_prefix"), cfg.exemptAllowPrefix);

        Map<String, Object> logging = map(settings.get("logging_middleware"));
        cfg.loggingEnabled = bool(logging.get("enabled"), cfg.loggingEnabled);
        cfg.logDir = str(logging.get("log_dir"), cfg.logDir);
        cfg.logFormat = str(logging.get("log_format"), cfg.logFormat);
        cfg.logQueryParameters = bool(logging.get("log_query_parameters"), cfg.logQueryParameters);

        Map<String, Object> security = map(settings.get("security"));
        cfg.methodValidationEnabled = bool(security.get("method_validation_enabled"), cfg.methodValidationEnabled);
        Set<String> allowedMethods = upperSet(security.get("allowed_methods"));
        if (!allowedMethods.isEmpty()) cfg.allowedMethods = allowedMethods;
        cfg.maxRequestBodyBytes = intval(security.get("max_request_body_bytes"), cfg.maxRequestBodyBytes);
        cfg.requestBodyInspectionBytes = intval(security.get("request_body_inspection_bytes"), cfg.requestBodyInspectionBytes);
        cfg.requestBodyInspectionEnabled = bool(security.get("request_body_inspection_enabled"), cfg.requestBodyInspectionEnabled);
        cfg.sqlInjectionMode = str(security.get("sql_injection_mode"), cfg.sqlInjectionMode).toLowerCase(Locale.ROOT);
        cfg.allowCompressedRequestBodies = bool(security.get("allow_compressed_request_bodies"), cfg.allowCompressedRequestBodies);
        cfg.maxParameterCount = intval(security.get("max_parameter_count"), cfg.maxParameterCount);
        cfg.maxParameterBytes = intval(security.get("max_parameter_bytes"), cfg.maxParameterBytes);
        cfg.allowDuplicateParameters = bool(security.get("allow_duplicate_parameters"), cfg.allowDuplicateParameters);

        Map<String, Object> performance = map(settings.get("performance"));
        cfg.maxRuntimeStateEntries = intval(performance.get("max_runtime_state_entries"), cfg.maxRuntimeStateEntries);
        cfg.enabledMiddlewares.addAll(strSet(settings.get("enabled_middlewares")));
        cfg.disabledMiddlewares.addAll(strSet(settings.get("disabled_middlewares")));
        cfg.legitimateRouteHints.addAll(strSet(settings.get("legitimate_route_hints")));
        cfg.legitimatePathKeywords.addAll(LegitimateRouteKeywordsCore.fromRouteHints(cfg.legitimateRouteHints));

        List<?> rules = list(settings.get("path_rules"));
        if (rules != null) {
            for (Object ruleObj : rules) {
                Map<String, Object> r = map(ruleObj);
                String prefix = str(or(r.get("PREFIX"), r.get("prefix")), null);
                if (prefix == null || prefix.isBlank()) continue;
                Set<String> disable = strSet(or(r.get("DISABLE"), r.get("disable")));

                Integer max = null;
                Integer window = null;
                Integer flood = null;
                Map<String, Map<String, Integer>> overrides = new HashMap<>();
                Map<String, Object> rate = map(or(r.get("RATE_LIMIT"), r.get("rate_limit")));
                if (!rate.isEmpty()) {
                    max = intObj(or(rate.get("MAX"), rate.get("max")));
                    window = intObj(or(rate.get("WINDOW"), rate.get("window")));
                    flood = intObj(or(rate.get("FLOOD"), rate.get("flood")));
                    Map<String, Integer> normalized = new HashMap<>();
                    if (max != null) normalized.put("max", max);
                    if (window != null) normalized.put("window", window);
                    if (flood != null) normalized.put("flood", flood);
                    overrides.put("rate_limit", normalized);
                }

                cfg.pathRules.add(new AiwafConfig.PathRule(
                        prefix, false, max, window, flood, disable, overrides
                ));
            }
        }
    }

    public static void applyEnv(AiwafConfig cfg, Map<String, String> env) {
        if (cfg == null || env == null) return;
        get(env, "AIWAF_RATE_WINDOW").ifPresent(v -> cfg.rateLimitWindowSeconds = parseInt(v, cfg.rateLimitWindowSeconds));
        get(env, "AIWAF_RATE_MAX").ifPresent(v -> cfg.rateLimitMax = parseInt(v, cfg.rateLimitMax));
        get(env, "AIWAF_RATE_FLOOD").ifPresent(v -> cfg.rateLimitFloodThreshold = parseInt(v, cfg.rateLimitFloodThreshold));
        get(env, "AIWAF_HEADER_VALIDATION").ifPresent(v -> cfg.headerValidationEnabled = parseBool(v, cfg.headerValidationEnabled));
        get(env, "AIWAF_HEADER_VALIDATION_ENABLED").ifPresent(v -> cfg.headerValidationEnabled = parseBool(v, cfg.headerValidationEnabled));
        get(env, "AIWAF_HEADER_QUALITY_MIN_SCORE").ifPresent(v -> cfg.minHeaderQualityScore = parseInt(v, cfg.minHeaderQualityScore));
        get(env, "AIWAF_HEADER_QUALITY_THRESHOLD").ifPresent(v -> cfg.minHeaderQualityScore = parseInt(v, cfg.minHeaderQualityScore));
        get(env, "AIWAF_RATE_LIMITING_ENABLED").ifPresent(v -> cfg.rateLimitEnabled = parseBool(v, cfg.rateLimitEnabled));
        get(env, "AIWAF_RATE_MAX_REQUESTS").ifPresent(v -> cfg.rateLimitMax = parseInt(v, cfg.rateLimitMax));
        get(env, "AIWAF_RATE_WINDOW_SECONDS").ifPresent(v -> cfg.rateLimitWindowSeconds = parseInt(v, cfg.rateLimitWindowSeconds));
        get(env, "AIWAF_GEO_BLOCK_ENABLED").ifPresent(v -> cfg.geoBlockEnabled = parseBool(v, cfg.geoBlockEnabled));
        get(env, "AIWAF_GEO_BLOCK_COUNTRIES").ifPresent(v -> cfg.geoBlockedCountries.addAll(csvUpper(v)));
        get(env, "AIWAF_GEO_ALLOW_COUNTRIES").ifPresent(v -> cfg.geoAllowedCountries.addAll(csvUpper(v)));
        get(env, "AIWAF_GEOIP_DATABASE_PATH").ifPresent(v -> cfg.geoIpDatabasePath = v);
        get(env, "AIWAF_GEO_CACHE_SECONDS").ifPresent(v -> cfg.geoCacheSeconds = parseInt(v, cfg.geoCacheSeconds));
        get(env, "AIWAF_PATH_MANIFEST_ENABLED").ifPresent(v -> cfg.pathManifestEnabled = parseBool(v, cfg.pathManifestEnabled));
        get(env, "AIWAF_PATH_MANIFEST_PATH").ifPresent(v -> cfg.pathManifestPath = v);
        get(env, "AIWAF_AI_ENABLED").ifPresent(v -> cfg.aiEnabled = parseBool(v, cfg.aiEnabled));
        get(env, "AIWAF_AI_MODEL_PATH").ifPresent(v -> cfg.aiModelPath = v);
        get(env, "AIWAF_UUID_SCORE_ENABLED").ifPresent(v -> cfg.uuidScoreEnabled = parseBool(v, cfg.uuidScoreEnabled));
        get(env, "AIWAF_UUID_SCORE_WINDOW_SECONDS").ifPresent(v -> cfg.uuidScoreWindowSeconds = parseInt(v, cfg.uuidScoreWindowSeconds));
        get(env, "AIWAF_UUID_SCORE_BLOCK_THRESHOLD").ifPresent(v -> cfg.uuidScoreBlockThreshold = parseInt(v, cfg.uuidScoreBlockThreshold));
        get(env, "AIWAF_UUID_SCORE_MALFORMED_WEIGHT").ifPresent(v -> cfg.uuidMalformedWeight = parseInt(v, cfg.uuidMalformedWeight));
        get(env, "AIWAF_UUID_SCORE_NOT_FOUND_WEIGHT").ifPresent(v -> cfg.uuidNotFoundWeight = parseInt(v, cfg.uuidNotFoundWeight));
        get(env, "AIWAF_UUID_SCORE_SUCCESS_DECAY").ifPresent(v -> cfg.uuidSuccessDecay = parseInt(v, cfg.uuidSuccessDecay));
        get(env, "AIWAF_STORAGE_BACKEND").ifPresent(v -> cfg.storageBackend = v.toLowerCase(Locale.ROOT));
        get(env, "AIWAF_SQL_INJECTION_MODE").ifPresent(v -> cfg.sqlInjectionMode = v.toLowerCase(Locale.ROOT));
        get(env, "AIWAF_STORAGE_FILE_PATH").ifPresent(v -> cfg.storageFilePath = v);
        get(env, "AIWAF_REDIS_URL").ifPresent(v -> cfg.storageRedisUrl = v);
        get(env, "AIWAF_STORAGE_KEY_PREFIX").ifPresent(v -> cfg.storageKeyPrefix = v);
        get(env, "AIWAF_REDIS_MODE").ifPresent(v -> cfg.storageRedisMode = v);
        get(env, "AIWAF_REDIS_FAILURE_MODE").ifPresent(v -> cfg.storageRedisFailureMode = v);
        get(env, "AIWAF_REDIS_CONNECTION_TIMEOUT_MILLIS").ifPresent(v ->
                cfg.storageRedisConnectionTimeoutMillis = parseInt(v, cfg.storageRedisConnectionTimeoutMillis));
        get(env, "AIWAF_REDIS_SOCKET_TIMEOUT_MILLIS").ifPresent(v ->
                cfg.storageRedisSocketTimeoutMillis = parseInt(v, cfg.storageRedisSocketTimeoutMillis));
        get(env, "AIWAF_REDIS_POOL_MAX_TOTAL").ifPresent(v ->
                cfg.storageRedisPoolMaxTotal = parseInt(v, cfg.storageRedisPoolMaxTotal));
        get(env, "AIWAF_REDIS_POOL_MAX_IDLE").ifPresent(v ->
                cfg.storageRedisPoolMaxIdle = parseInt(v, cfg.storageRedisPoolMaxIdle));
        get(env, "AIWAF_REDIS_POOL_MIN_IDLE").ifPresent(v ->
                cfg.storageRedisPoolMinIdle = parseInt(v, cfg.storageRedisPoolMinIdle));
        get(env, "AIWAF_REDIS_POOL_MAX_WAIT_MILLIS").ifPresent(v ->
                cfg.storageRedisPoolMaxWaitMillis = parseInt(v, cfg.storageRedisPoolMaxWaitMillis));
        get(env, "AIWAF_RATE_CACHE_BACKEND").ifPresent(v -> {
            if ("redis".equalsIgnoreCase(v)) cfg.storageBackend = "redis";
        });
        get(env, "AIWAF_RATE_CACHE_KEY_PREFIX").ifPresent(v -> cfg.storageKeyPrefix = v);
        get(env, "AIWAF_RATE_KEY_MODE").ifPresent(v -> cfg.rateLimitScope =
                Set.of("ip", "global_ip", "global-ip").contains(v.trim().toLowerCase(Locale.ROOT))
                        ? AiwafConfig.RateLimitScope.GLOBAL_IP : AiwafConfig.RateLimitScope.PER_PATH);
        get(env, "AIWAF_RATE_SOFT_BLOCK_BLOCKLIST").ifPresent(v ->
                cfg.blockIpOnRateLimitBreach = parseBool(v, cfg.blockIpOnRateLimitBreach));
    }

    private static Object or(Object a, Object b) { return a != null ? a : b; }
    private static Map<String, Object> map(Object o) {
        if (!(o instanceof Map<?, ?> m)) return Map.of();
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<?, ?> e : m.entrySet()) if (e.getKey() != null) out.put(String.valueOf(e.getKey()), e.getValue());
        return out;
    }
    private static List<?> list(Object o) { return (o instanceof List<?> l) ? l : null; }
    private static String str(Object o, String d) { return o == null ? d : String.valueOf(o); }
    private static boolean bool(Object o, boolean d) {
        if (o == null) return d;
        if (o instanceof Boolean b) return b;
        return parseBool(String.valueOf(o), d);
    }
    private static int intval(Object o, int d) {
        Integer v = intObj(o);
        return v == null ? d : v;
    }
    private static Integer intObj(Object o) {
        if (o == null) return null;
        if (o instanceof Number n) return n.intValue();
        try { return Integer.parseInt(String.valueOf(o)); } catch (Exception ex) { return null; }
    }
    private static double dbl(Object o, double d) {
        if (o == null) return d;
        if (o instanceof Number n) return n.doubleValue();
        try { return Double.parseDouble(String.valueOf(o)); } catch (Exception ex) { return d; }
    }
    private static Set<String> strSet(Object o) {
        Set<String> out = new HashSet<>();
        if (o instanceof List<?> l) for (Object v : l) if (v != null) out.add(String.valueOf(v));
        return out;
    }
    private static Set<String> upperSet(Object o) {
        Set<String> out = new HashSet<>();
        for (String s : strSet(o)) out.add(s.toUpperCase(Locale.ROOT));
        return out;
    }
    private static java.util.Optional<String> get(Map<String, String> env, String key) {
        for (Map.Entry<String, String> e : env.entrySet()) {
            if (key.equalsIgnoreCase(e.getKey())) return java.util.Optional.ofNullable(e.getValue());
        }
        return java.util.Optional.empty();
    }
    private static int parseInt(String v, int d) {
        try { return Integer.parseInt(v); } catch (Exception ex) { return d; }
    }
    private static boolean parseBool(String v, boolean d) {
        if (v == null) return d;
        String x = v.trim().toLowerCase(Locale.ROOT);
        if (Set.of("1", "true", "yes", "on").contains(x)) return true;
        if (Set.of("0", "false", "no", "off").contains(x)) return false;
        return d;
    }
    private static Set<String> csvUpper(String v) {
        Set<String> out = new HashSet<>();
        if (v == null || v.isBlank()) return out;
        for (String p : v.split(",")) {
            String t = p.trim();
            if (!t.isBlank()) out.add(t.toUpperCase(Locale.ROOT));
        }
        return out;
    }
}
