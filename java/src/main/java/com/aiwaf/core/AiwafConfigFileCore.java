package com.aiwaf.core;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** JSON configuration loading, saving, deep merging, and validation. */
public final class AiwafConfigFileCore {
    private static final long MAX_CONFIG_BYTES = 2L * 1024L * 1024L;
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private AiwafConfigFileCore() {}

    public static AiwafConfig load(Path path) throws IOException {
        return load(path, System.getenv());
    }

    public static AiwafConfig load(Path path, Map<String, String> environment) throws IOException {
        AiwafConfig config = new AiwafConfig();
        if (path != null && Files.exists(path)) {
            AiwafConfigCompatCore.applyStructured(config, read(path));
        }
        AiwafConfigCompatCore.applyEnv(config, environment);
        List<String> errors = validate(config);
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException("Invalid AIWAF configuration: " + String.join("; ", errors));
        }
        return config;
    }

    public static Map<String, Object> read(Path path) throws IOException {
        if (path == null) throw new IllegalArgumentException("Configuration path cannot be null");
        long size = Files.size(path);
        if (size > MAX_CONFIG_BYTES) {
            throw new IOException("AIWAF configuration exceeds " + MAX_CONFIG_BYTES + " bytes");
        }
        Map<String, Object> value = JSON.readValue(path.toFile(), new TypeReference<>() {});
        return value == null ? new LinkedHashMap<>() : value;
    }

    public static void save(AiwafConfig config, Path path) throws IOException {
        if (config == null) throw new IllegalArgumentException("config cannot be null");
        if (path == null) throw new IllegalArgumentException("path cannot be null");
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        JSON.writeValue(path.toFile(), toStructured(config));
    }

    public static Map<String, Object> deepMerge(
            Map<String, Object> base,
            Map<String, Object> update
    ) {
        Map<String, Object> merged = deepCopy(base == null ? Map.of() : base);
        mergeInto(merged, update == null ? Map.of() : update);
        return merged;
    }

    public static List<String> validate(AiwafConfig config) {
        List<String> errors = new ArrayList<>();
        if (config == null) {
            errors.add("configuration is required");
            return errors;
        }
        String backend = config.storageBackend == null ? "" : config.storageBackend.trim().toLowerCase();
        if (config.sqlInjectionMode == null || !Set.of("block", "monitor", "off").contains(config.sqlInjectionMode)) {
            errors.add("security.sql_injection_mode must be block, monitor, or off");
        }
        if (!Set.of("memory", "file", "csv", "db", "redis").contains(backend)) {
            errors.add("storage.backend must be memory, file, csv, db, or redis");
        }
        if ("redis".equals(backend) && (config.storageRedisUrl == null || config.storageRedisUrl.isBlank())) {
            errors.add("storage.redis_url is required for the redis backend");
        }
        if (!"standalone".equalsIgnoreCase(config.storageRedisMode)) {
            errors.add("storage.redis_mode must be standalone; Sentinel and Cluster are not supported in Java 1.3");
        }
        String failureMode = config.storageRedisFailureMode == null
                ? "" : config.storageRedisFailureMode.trim().toLowerCase();
        if (!Set.of("fail_closed", "fail-closed", "closed", "fail_open", "fail-open", "open")
                .contains(failureMode)) {
            errors.add("storage.redis_failure_mode must be fail_closed or fail_open");
        }
        range(errors, "storage.redis_connection_timeout_millis",
                config.storageRedisConnectionTimeoutMillis, 1, 120_000);
        range(errors, "storage.redis_socket_timeout_millis",
                config.storageRedisSocketTimeoutMillis, 1, 120_000);
        range(errors, "storage.redis_pool_max_total", config.storageRedisPoolMaxTotal, 1, 10_000);
        range(errors, "storage.redis_pool_max_idle", config.storageRedisPoolMaxIdle, 0, 10_000);
        range(errors, "storage.redis_pool_min_idle", config.storageRedisPoolMinIdle, 0, 10_000);
        range(errors, "storage.redis_pool_max_wait_millis",
                config.storageRedisPoolMaxWaitMillis, 1, 120_000);
        if (config.storageRedisPoolMaxIdle > config.storageRedisPoolMaxTotal) {
            errors.add("storage.redis_pool_max_idle cannot exceed redis_pool_max_total");
        }
        if (config.storageRedisPoolMinIdle > config.storageRedisPoolMaxIdle) {
            errors.add("storage.redis_pool_min_idle cannot exceed redis_pool_max_idle");
        }
        range(errors, "header_validation.quality_threshold", config.minHeaderQualityScore, 0, 20);
        range(errors, "rate_limiting.max_requests", config.rateLimitMax, 1, 10_000);
        range(errors, "rate_limiting.window_seconds", config.rateLimitWindowSeconds, 1, 86_400);
        range(errors, "rate_limiting.flood_threshold", config.rateLimitFloodThreshold, 1, 100_000);
        if (config.rateLimitFloodThreshold < config.rateLimitMax) {
            errors.add("rate_limiting.flood_threshold must be at least max_requests");
        }
        range(errors, "security.max_header_bytes", config.maxHeaderBytes, 1_024, 65_536);
        range(errors, "security.max_user_agent_length", config.maxUserAgentLength, 16, 8_192);
        range(errors, "performance.max_runtime_state_entries", config.maxRuntimeStateEntries, 100, 10_000_000);
        if (config.minFormTimeSeconds < 0) errors.add("honeypot.min_form_time cannot be negative");
        if (config.maxFormPageTimeSeconds <= 0) errors.add("honeypot.max_page_time must be positive");
        if (config.aiAnomalyScoreThreshold < 0 || config.aiAnomalyScoreThreshold > 1) {
            errors.add("ai_anomaly.threshold must be between 0 and 1");
        }
        return errors;
    }

    public static Map<String, Object> toStructured(AiwafConfig config) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("storage", map(
                "backend", config.storageBackend,
                "file_path", config.storageFilePath,
                "redis_url", config.storageRedisUrl,
                "key_prefix", config.storageKeyPrefix,
                "redis_mode", config.storageRedisMode,
                "redis_failure_mode", config.storageRedisFailureMode,
                "redis_connection_timeout_millis", config.storageRedisConnectionTimeoutMillis,
                "redis_socket_timeout_millis", config.storageRedisSocketTimeoutMillis,
                "redis_pool_max_total", config.storageRedisPoolMaxTotal,
                "redis_pool_max_idle", config.storageRedisPoolMaxIdle,
                "redis_pool_min_idle", config.storageRedisPoolMinIdle,
                "redis_pool_max_wait_millis", config.storageRedisPoolMaxWaitMillis
        ));
        root.put("header_validation", map(
                "enabled", config.headerValidationEnabled,
                "quality_threshold", config.minHeaderQualityScore,
                "max_header_bytes", config.maxHeaderBytes,
                "max_header_count", config.maxHeaderCount,
                "max_user_agent_length", config.maxUserAgentLength,
                "max_accept_length", config.maxAcceptLength,
                "exempt_paths", config.exemptPaths
        ));
        root.put("rate_limiting", map(
                "enabled", config.rateLimitEnabled,
                "max_requests", config.rateLimitMax,
                "window_seconds", config.rateLimitWindowSeconds,
                "flood_threshold", config.rateLimitFloodThreshold,
                "key_mode", config.rateLimitScope == AiwafConfig.RateLimitScope.GLOBAL_IP ? "ip" : "ip_path",
                "soft_block_blocklist", config.blockIpOnRateLimitBreach,
                "block_ip_on_flood", config.blockIpOnFloodBreach
        ));
        root.put("honeypot", map(
                "enabled", config.honeypotEnabled,
                "min_form_time", config.minFormTimeSeconds,
                "max_page_time", config.maxFormPageTimeSeconds,
                "login_min_form_time", config.loginMinFormTimeSeconds,
                "login_path_prefixes", config.loginPathPrefixes
        ));
        root.put("ip_keyword_block", map(
                "enabled", config.ipKeywordBlockEnabled,
                "malicious_keywords", config.blockedPathPatterns,
                "enable_learning", config.enableKeywordLearning,
                "dynamic_top_n", config.dynamicTopN
        ));
        root.put("geo_block", map(
                "enabled", config.geoBlockEnabled,
                "allow_countries", config.geoAllowedCountries,
                "block_countries", config.geoBlockedCountries,
                "exempt_paths", config.geoExemptPaths,
                "database_path", config.geoIpDatabasePath,
                "cache_seconds", config.geoCacheSeconds,
                "max_cache_entries", config.geoMaxCacheEntries
        ));
        root.put("ai_anomaly", map(
                "enabled", config.aiEnabled,
                "model_path", config.aiModelPath,
                "threshold", config.aiAnomalyScoreThreshold,
                "lazy_load", config.aiLazyLoadModel,
                "background_preload", config.aiBackgroundPreload,
                "require_behavior_confirmation", config.aiRequireBehaviorConfirmation,
                "recent_window_seconds", config.aiRecentWindowSeconds,
                "min_recent_samples_to_block", config.aiMinRecentSamplesToBlock
        ));
        root.put("uuid_tamper", map(
                "enabled", config.uuidTamperEnabled,
                "score_enabled", config.uuidScoreEnabled,
                "window_seconds", config.uuidScoreWindowSeconds,
                "block_threshold", config.uuidScoreBlockThreshold,
                "malformed_weight", config.uuidMalformedWeight,
                "not_found_weight", config.uuidNotFoundWeight,
                "success_decay", config.uuidSuccessDecay,
                "parameter_names", config.uuidParameterNames
        ));
        root.put("logging_middleware", map(
                "enabled", config.loggingEnabled,
                "log_dir", config.logDir,
                "log_format", config.logFormat,
                "log_query_parameters", config.logQueryParameters
        ));
        root.put("exemptions", map(
                "private_ips_exempted", config.privateIpsExempted,
                "localhost_exempted", config.localhostExempted,
                "ips", config.exemptIps,
                "auto_exempt_patterns", config.exemptIpPatterns,
                "paths", config.exemptPaths,
                "allow_wildcards", config.exemptAllowWildcards,
                "allow_prefix", config.exemptAllowPrefix
        ));
        root.put("security", map(
                "method_validation_enabled", config.methodValidationEnabled,
                "allowed_methods", config.allowedMethods,
                "max_request_body_bytes", config.maxRequestBodyBytes,
                "request_body_inspection_bytes", config.requestBodyInspectionBytes,
                "request_body_inspection_enabled", config.requestBodyInspectionEnabled,
                "sql_injection_mode", config.sqlInjectionMode,
                "allow_compressed_request_bodies", config.allowCompressedRequestBodies,
                "max_parameter_count", config.maxParameterCount,
                "max_parameter_bytes", config.maxParameterBytes,
                "allow_duplicate_parameters", config.allowDuplicateParameters
        ));
        root.put("performance", map("max_runtime_state_entries", config.maxRuntimeStateEntries));
        root.put("path_manifest", map(
                "enabled", config.pathManifestEnabled,
                "path", config.pathManifestPath
        ));
        root.put("enabled_middlewares", config.enabledMiddlewares);
        root.put("disabled_middlewares", config.disabledMiddlewares);
        root.put("legitimate_route_hints", config.legitimateRouteHints);
        return root;
    }

    private static void range(List<String> errors, String name, int value, int min, int max) {
        if (value < min || value > max) errors.add(name + " must be between " + min + " and " + max);
    }

    @SuppressWarnings("unchecked")
    private static void mergeInto(Map<String, Object> base, Map<String, Object> update) {
        for (Map.Entry<String, Object> entry : update.entrySet()) {
            Object current = base.get(entry.getKey());
            Object value = entry.getValue();
            if (current instanceof Map<?, ?> currentMap && value instanceof Map<?, ?> valueMap) {
                mergeInto((Map<String, Object>) currentMap, stringMap(valueMap));
            } else {
                base.put(entry.getKey(), deepCopyValue(value));
            }
        }
    }

    private static Map<String, Object> deepCopy(Map<String, Object> source) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            out.put(entry.getKey(), deepCopyValue(entry.getValue()));
        }
        return out;
    }

    private static Object deepCopyValue(Object value) {
        if (value instanceof Map<?, ?> map) return deepCopy(stringMap(map));
        if (value instanceof List<?> list) return new ArrayList<>(list);
        if (value instanceof Set<?> set) return new ArrayList<>(set);
        return value;
    }

    private static Map<String, Object> stringMap(Map<?, ?> source) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() != null) out.put(String.valueOf(entry.getKey()), entry.getValue());
        }
        return out;
    }

    private static Map<String, Object> map(Object... values) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < values.length; i += 2) {
            out.put(String.valueOf(values[i]), values[i + 1]);
        }
        return out;
    }
}
