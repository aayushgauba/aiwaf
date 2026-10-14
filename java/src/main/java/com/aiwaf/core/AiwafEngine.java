package com.aiwaf.core;

import com.aiwaf.runtime.BlocklistManager;
import com.aiwaf.runtime.CidrUtil;
import com.aiwaf.runtime.RedisStorage;
import com.aiwaf.runtime.RuntimeState;
import com.aiwaf.runtime.RuntimeStorage;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class AiwafEngine {
    private final AiwafConfig config;
    private final RuntimeStorage.Context runtimeStorage;
    private final LazyModelProviderCore modelProvider;
    private final UuidPolicyCore.UUIDLookup uuidLookup;
    private final AiwafTelemetryCore telemetry = new AiwafTelemetryCore();
    private final Set<String> defaultMaliciousKeywords = new HashSet<>(Set.of(
            ".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "shell", "filemanager"
    ));
    private static final List<String> FLASK_ANOMALY_STATUS_CODES = List.of(
            "200", "201", "204", "301", "302", "400", "401", "403", "404", "405", "500", "502", "503"
    );

    public AiwafEngine(AiwafConfig config) {
        this(config, null);
    }

    public AiwafEngine(AiwafConfig config, UuidPolicyCore.UUIDLookup uuidLookup) {
        this(config, uuidLookup, RuntimeStorage.create(
                config.storageBackend,
                config.storageFilePath,
                config.storageRedisUrl,
                config.storageKeyPrefix,
                new RedisStorage.Options(
                        config.storageRedisMode,
                        RedisStorage.FailureMode.parse(config.storageRedisFailureMode),
                        config.storageRedisConnectionTimeoutMillis,
                        config.storageRedisSocketTimeoutMillis,
                        config.storageRedisPoolMaxTotal,
                        config.storageRedisPoolMaxIdle,
                        config.storageRedisPoolMinIdle,
                        config.storageRedisPoolMaxWaitMillis
                )
        ));
    }

    public AiwafEngine(
            AiwafConfig config,
            UuidPolicyCore.UUIDLookup uuidLookup,
            RuntimeStorage.Context runtimeStorage
    ) {
        this.config = config;
        PathManifestCore.applyManifest(config);
        this.uuidLookup = uuidLookup;
        this.modelProvider = new LazyModelProviderCore(config.aiModelPath);
        this.runtimeStorage = runtimeStorage;
        RuntimeStorage.installDefault(runtimeStorage);
        if (config.aiEnabled) {
            if (!config.aiLazyLoadModel) {
                modelProvider.get();
            } else if (config.aiBackgroundPreload) {
                Thread t = new Thread(modelProvider::get, "aiwaf-model-preload");
                t.setDaemon(true);
                t.start();
            }
        }
    }

    public void clearState() {
        runtimeStorage.state().clear();
        telemetry.reset();
    }

    public AiwafConfig config() {
        return config;
    }

    public AiwafTelemetryCore telemetry() {
        return telemetry;
    }

    public RuntimeStorage.Context runtimeStorage() {
        return runtimeStorage;
    }

    public AiwafDecision evaluate(AiwafRequest req) {
        return evaluateRequest(req, false);
    }

    /** Run request checks now; defer AI scoring until the handler response is available. */
    public AiwafDecision evaluateBeforeResponse(AiwafRequest req) {
        return evaluateRequest(req, true);
    }

    /** Complete an allowed request using the handler's actual response status and elapsed time. */
    public AiwafDecision evaluateAfterResponse(AiwafRequest req, int statusCode, long responseTimeMs) {
        long startedNs = System.nanoTime();
        long nowMillis = System.currentTimeMillis();
        String ip = blankToDefault(req.ip(), "127.0.0.1");
        AiwafConfig.PathRule rule = ExemptionsCore.getPathRuleForPath(req.path(), config.pathRules);
        boolean ipExempted = isIpExempted(ip);
        AiwafDecision aiDecision = evaluateUuidResponse(req, ip, statusCode, nowMillis);
        if (!isPathExempted(req) && !ipExempted
                && aiDecision == null
                && !isRuleDisabled(req, rule, config, "ai_anomaly") && config.aiEnabled) {
            aiDecision = evaluateAiAnomaly(req, ip, statusCode, responseTimeMs, nowMillis);
        }
        recordRecent(ip, req, statusCode, nowMillis);
        return finalizeDecision(aiDecision == null ? AiwafDecision.allow() : aiDecision,
                startedNs, aiDecision == null ? "allow" :
                        (aiDecision.reason().startsWith("UUID tampering") ? "uuid_tamper" : "ai_anomaly"));
    }

    /** Record a committed or streaming response without attempting to replace its body. */
    public void recordCommittedResponse(AiwafRequest req, int statusCode) {
        String ip = blankToDefault(req.ip(), "127.0.0.1");
        long nowMillis = System.currentTimeMillis();
        evaluateUuidResponse(req, ip, statusCode, nowMillis);
        recordRecent(ip, req, statusCode, nowMillis);
        finalizeDecision(AiwafDecision.allow(), System.nanoTime(), "allow");
    }

    private AiwafDecision evaluateRequest(AiwafRequest req, boolean deferAiAnomaly) {
        long startedNs = System.nanoTime();
        telemetryIncrement("requests.total");
        AiwafDecision requestShapeDecision = validateRequestShape(req);
        if (requestShapeDecision != null) {
            return finalizeDecision(requestShapeDecision, startedNs, "request_shape");
        }
        String contentEncoding = header(req.headers(), "content-encoding").trim();
        if (!config.allowCompressedRequestBodies && !contentEncoding.isEmpty()
                && !"identity".equalsIgnoreCase(contentEncoding)) {
            AiwafDecision d = AiwafDecision.deny(415, "Compressed request bodies are not accepted");
            return finalizeDecision(d, startedNs, "compressed_request_body");
        }
        if (containsJavaSerializationPayload(req)) {
            AiwafDecision d = AiwafDecision.deny(415, "Java serialization payloads are not accepted");
            return finalizeDecision(d, startedNs, "java_deserialization_payload");
        }
        AiwafConfig.PathRule rule = ExemptionsCore.getPathRuleForPath(req.path(), config.pathRules);
        boolean headerValidationEnabled = config.headerValidationEnabled && !isRuleDisabled(req, rule, config, "header_validation");
        int maxRequests = resolveRateLimitOverride(rule, "max", config.rateLimitMax, rule == null ? null : rule.rateLimitMaxOverride);
        int windowSeconds = resolveRateLimitOverride(rule, "window", config.rateLimitWindowSeconds, rule == null ? null : rule.rateLimitWindowOverride);
        int floodThreshold = resolveRateLimitOverride(rule, "flood", config.rateLimitFloodThreshold, rule == null ? null : rule.rateLimitFloodOverride);
        boolean pathExempted = isPathExempted(req);
        String ip = blankToDefault(req.ip(), "127.0.0.1");
        boolean ipExempted = isIpExempted(ip);
        if (!ipExempted && BlocklistManager.isBlocked(runtimeStorage, ip)) {
            AiwafDecision d = AiwafDecision.deny(403, "IP blocklisted");
            return finalizeDecision(d, startedNs, "ip_blocklisted");
        }

        if (config.methodValidationEnabled && !config.isMethodAllowed(req.method())) {
            AiwafDecision d = AiwafDecision.deny(405, "Method not allowed");
            return finalizeDecision(d, startedNs, "method_validation");
        }

        if (!pathExempted && !ipExempted && config.ipKeywordBlockEnabled
                && !isRuleDisabled(req, rule, config, "ip_keyword_block")
                && !"off".equals(config.sqlInjectionMode)) {
            String finding = SqlInjectionCore.inspect(req, config);
            if (finding != null) {
                telemetryIncrement("middleware.request_inspection." + finding);
                if (!"monitor".equals(config.sqlInjectionMode)) {
                    return finalizeDecision(AiwafDecision.deny(
                            "payload_inspection_limit".equals(finding) ? 413 : 403, finding),
                            startedNs, "request_inspection");
                }
            }
        }

        if (!pathExempted && !isRuleDisabled(req, rule, config, "ip_keyword_block")
                && config.ipKeywordBlockEnabled) {
            String matchedKeyword = detectMaliciousKeyword(req.path());
            if (matchedKeyword != null) {
                telemetryIncrement("middleware.ip_keyword_block.triggered");
                runtimeStorage.keywordStore().addKeyword(matchedKeyword, 1);
                blockWithContext(ip, req, "Keyword block: " + matchedKeyword);
                AiwafDecision d = AiwafDecision.deny(403, "Malicious keyword: " + matchedKeyword);
                return finalizeDecision(d, startedNs, "ip_keyword_block");
            }
            String learned = detectLearnedKeyword(req.path());
            if (learned != null) {
                telemetryIncrement("middleware.ip_keyword_block.learned_triggered");
                blockWithContext(ip, req, "Learned keyword block: " + learned);
                AiwafDecision d = AiwafDecision.deny(403, "Learned keyword: " + learned);
                return finalizeDecision(d, startedNs, "ip_keyword_learned_block");
            }
            maybeLearnKeywords(req);
        }

        if (!pathExempted && !ipExempted
                && !isRuleDisabled(req, rule, config, "uuid_tamper") && config.uuidTamperEnabled) {
            String uuidValue = uuidCandidate(req);
            if (uuidValue != null && !isValidUuid(uuidValue)) {
                telemetryIncrement("middleware.uuid_tamper.triggered");
                RuntimeState.UuidResult score = recordUuidSignal(
                        ip, UuidScoreCore.Signal.MALFORMED, req.nowEpochMillis());
                blockWithContext(ip, req, "UUID tampering score=" + score.score());
                AiwafDecision d = AiwafDecision.deny(403, "UUID tampering score=" + score.score());
                return finalizeDecision(d, startedNs, "uuid_tamper");
            }
        }

        if (!pathExempted && !isRuleDisabled(req, rule, config, "honeypot") && config.honeypotEnabled) {
            String key = ip + "|" + req.path();
            if ("GET".equalsIgnoreCase(req.method())) {
                runtimeStorage.state().recordFormGet(
                        key,
                        req.nowEpochMillis(),
                        Math.max(1, (int) Math.ceil(config.maxFormPageTimeSeconds)),
                        config.maxRuntimeStateEntries
                );
            } else if ("POST".equalsIgnoreCase(req.method())) {
                Long lastGet = runtimeStorage.state().getFormGet(key);
                if (lastGet != null) {
                    double elapsed = (req.nowEpochMillis() - lastGet) / 1000.0;
                    if (elapsed > config.maxFormPageTimeSeconds) {
                        telemetryIncrement("middleware.honeypot.page_expired");
                        AiwafDecision d = AiwafDecision.deny(409, "page_expired");
                        return finalizeDecision(d, startedNs, "honeypot_page_expired");
                    }
                    double minFormTime = config.minFormTimeSeconds;
                    String reqPathLower = req.path() == null ? "" : req.path().toLowerCase(Locale.ROOT);
                    for (String prefix : config.loginPathPrefixes) {
                        if (prefix != null && !prefix.isBlank() && reqPathLower.startsWith(prefix.toLowerCase(Locale.ROOT))) {
                            minFormTime = config.loginMinFormTimeSeconds;
                            break;
                        }
                    }
                    if (elapsed < minFormTime) {
                        telemetryIncrement("middleware.honeypot.timing_violation");
                        AiwafDecision d = AiwafDecision.deny(403, "Honeypot timing violation");
                        return finalizeDecision(d, startedNs, "honeypot_timing");
                    }
                }
            }
        }

        if (!pathExempted && headerValidationEnabled && !ipExempted) {
            int minHeaderQualityScore = resolveOverride(rule, "header_validation", "quality_threshold", config.minHeaderQualityScore);
            int maxHeaderBytes = resolveOverride(rule, "header_validation", "max_header_bytes", config.maxHeaderBytes);
            int maxHeaderCount = resolveOverride(rule, "header_validation", "max_header_count", config.maxHeaderCount);
            int maxUserAgentLength = resolveOverride(rule, "header_validation", "max_user_agent_length", config.maxUserAgentLength);
            int maxAcceptLength = resolveOverride(rule, "header_validation", "max_accept_length", config.maxAcceptLength);
            String headerIssue = HeaderValidationCore.validate(
                    req.headers(),
                    req.method(),
                    serverProtocolFrom(req),
                    config.resolveRequiredHeaders(req.method()),
                    minHeaderQualityScore,
                    maxHeaderBytes,
                    maxHeaderCount,
                    maxUserAgentLength,
                    maxAcceptLength
            );
            if (headerIssue != null) {
                telemetryIncrement("middleware.header_validation.triggered");
                AiwafDecision d = AiwafDecision.deny(403, headerIssue);
                return finalizeDecision(d, startedNs, "header_validation");
            }
        }

        if (!pathExempted && !isGeoPathExempted(req)
                && !isRuleDisabled(req, rule, config, "geo_block") && config.geoBlockEnabled && !ipExempted) {
            String country = safeUpper(req.country());
            if (!config.geoAllowedCountries.isEmpty() && !config.geoAllowedCountries.contains(country)) {
                telemetryIncrement("middleware.geo_block.allowlist_denied");
                AiwafDecision d = AiwafDecision.deny(403, "Geo allow list denied");
                return finalizeDecision(d, startedNs, "geo_allowlist");
            }
            boolean blockedByConfig = config.geoBlockedCountries.contains(country);
            boolean blockedByStore = runtimeStorage.geoBlockStore().getCountries().contains(country);
            if (blockedByConfig || blockedByStore) {
                telemetryIncrement("middleware.geo_block.blocked");
                AiwafDecision d = AiwafDecision.deny(403, "Geo blocked");
                return finalizeDecision(d, startedNs, "geo_block");
            }
        }

        if (!pathExempted && !isRuleDisabled(req, rule, config, "rate_limit") && config.rateLimitEnabled && !ipExempted) {
            String bucketKey = config.rateLimitScope == AiwafConfig.RateLimitScope.GLOBAL_IP
                    ? ip
                    : ip + "|" + req.path();
            RuntimeState.RateResult rate = runtimeStorage.state().recordRate(
                    bucketKey,
                    req.nowEpochMillis(),
                    windowSeconds,
                    maxRequests,
                    floodThreshold,
                    config.maxRuntimeStateEntries
            );
            if (rate.action() == RuntimeState.RateAction.CAPACITY) {
                telemetryIncrement("middleware.rate_limit.capacity");
                AiwafDecision d = AiwafDecision.deny(429, "Rate limiter capacity exceeded");
                return finalizeDecision(d, startedNs, "rate_limit_capacity");
            }
            if (rate.action() == RuntimeState.RateAction.FLOOD) {
                if (config.blockIpOnFloodBreach) blockWithContext(ip, req, "Flood pattern");
                telemetryIncrement("middleware.rate_limit.flood");
                AiwafDecision d = AiwafDecision.deny(403, "Flood pattern");
                return finalizeDecision(d, startedNs, "rate_limit_flood");
            }
            if (rate.action() == RuntimeState.RateAction.LIMIT) {
                if (config.blockIpOnRateLimitBreach) blockWithContext(ip, req, "Rate limit exceeded");
                telemetryIncrement("middleware.rate_limit.exceeded");
                AiwafDecision d = AiwafDecision.deny(429, "Rate limit exceeded");
                return finalizeDecision(d, startedNs, "rate_limit");
            }
        }

        if (!deferAiAnomaly && !pathExempted && !ipExempted
                && !isRuleDisabled(req, rule, config, "ai_anomaly") && config.aiEnabled) {
            AiwafDecision aiDecision = evaluateAiAnomaly(req, ip, 200, 0L, req.nowEpochMillis());
            if (aiDecision != null) {
                recordRecent(ip, req, aiDecision.statusCode());
                return finalizeDecision(aiDecision, startedNs, "ai_anomaly");
            }
        }

        AiwafDecision allow = AiwafDecision.allow();
        if (deferAiAnomaly) return allow;
        evaluateUuidResponse(req, ip, allow.statusCode(), req.nowEpochMillis());
        recordRecent(ip, req, allow.statusCode());
        return finalizeDecision(allow, startedNs, "allow");
    }

    public boolean isPathExempted(AiwafRequest req) {
        return config.isAutoExemptPath(req.path())
                || ExemptionsCore.isPathExempt(req.path(), config.exemptPaths, config.exemptAllowWildcards, config.exemptAllowPrefix)
                || runtimeStorage.pathExemptionStore().isExempted(req.path(), config.exemptAllowWildcards, config.exemptAllowPrefix);
    }

    public boolean shouldApplyMiddleware(AiwafRequest req, String middlewareName) {
        AiwafConfig.PathRule rule = ExemptionsCore.getPathRuleForPath(req.path(), config.pathRules);
        return !isPathExempted(req) && !isRuleDisabled(req, rule, config, middlewareName);
    }

    private boolean isGeoPathExempted(AiwafRequest req) {
        return ExemptionsCore.isPathExempt(
                req.path(), config.geoExemptPaths, config.exemptAllowWildcards, config.exemptAllowPrefix);
    }

    private AiwafDecision evaluateUuidResponse(AiwafRequest req, String ip, int statusCode, long nowMillis) {
        if (!config.uuidTamperEnabled || isPathExempted(req)) {
            return null;
        }
        AiwafConfig.PathRule rule = ExemptionsCore.getPathRuleForPath(req.path(), config.pathRules);
        if (isRuleDisabled(req, rule, config, "uuid_tamper")) {
            return null;
        }
        boolean ipExempted = isIpExempted(ip);
        if (ipExempted) {
            return null;
        }
        String candidate = uuidCandidate(req);
        if (!isValidUuid(candidate)) {
            return null;
        }

        UuidScoreCore.Signal signal;
        Boolean existsInModel = lookupUuid(candidate);
        if (statusCode == 404 || Boolean.FALSE.equals(existsInModel)) {
            signal = UuidScoreCore.Signal.NOT_FOUND;
        } else if (statusCode < 400) {
            signal = UuidScoreCore.Signal.SUCCESS;
        } else {
            return null;
        }
        RuntimeState.UuidResult score = recordUuidSignal(ip, signal, nowMillis);
        if (!score.blocked()) {
            return null;
        }
        telemetryIncrement("middleware.uuid_tamper.triggered");
        String reason = "UUID tampering score=" + score.score();
        blockWithContext(ip, req, reason);
        return AiwafDecision.deny(403, reason);
    }

    private Boolean lookupUuid(String candidate) {
        if (uuidLookup == null) return null;
        try {
            return uuidLookup.exists(candidate);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private UuidScoreCore.Config uuidScoreConfig() {
        return new UuidScoreCore.Config(
                config.uuidScoreEnabled,
                config.uuidScoreWindowSeconds,
                config.uuidScoreBlockThreshold,
                config.uuidMalformedWeight,
                config.uuidNotFoundWeight,
                config.uuidSuccessDecay
        );
    }

    private RuntimeState.UuidResult recordUuidSignal(
            String subject,
            UuidScoreCore.Signal signal,
            long nowMillis
    ) {
        UuidScoreCore.Config scoring = uuidScoreConfig();
        if (!scoring.enabled()) return new RuntimeState.UuidResult(0, false);
        int delta = switch (signal) {
            case MALFORMED -> scoring.malformedWeight();
            case NOT_FOUND -> scoring.notFoundWeight();
            case SUCCESS -> -scoring.successDecay();
        };
        return runtimeStorage.state().recordUuid(
                subject,
                delta,
                nowMillis,
                scoring.windowSeconds(),
                scoring.blockThreshold(),
                config.maxRuntimeStateEntries
        );
    }

    private String uuidCandidate(AiwafRequest req) {
        if (req.query() == null || req.query().isEmpty()) {
            return null;
        }
        for (String configuredName : config.uuidParameterNames) {
            if (configuredName == null) continue;
            for (Map.Entry<String, String> parameter : req.query().entrySet()) {
                if (configuredName.equalsIgnoreCase(parameter.getKey())) {
                    String value = parameter.getValue();
                    return value == null || value.isBlank() ? null : value.trim();
                }
            }
        }
        return null;
    }

    private static boolean containsJavaSerializationPayload(AiwafRequest req) {
        String contentType = header(req.headers(), "content-type").toLowerCase(Locale.ROOT);
        int separator = contentType.indexOf(';');
        String mediaType = (separator >= 0 ? contentType.substring(0, separator) : contentType).trim();
        if (Set.of(
                "application/x-java-serialized-object",
                "application/java-serialized-object",
                "application/x-java-object",
                "application/x-java-serialization"
        ).contains(mediaType)) {
            return true;
        }
        if (looksLikeSerializedValue(req.path())) {
            return true;
        }
        for (String value : req.query().values()) {
            if (looksLikeSerializedValue(value)) {
                return true;
            }
        }
        return looksLikeSerializedValue(req.bodyPreview());
    }

    private AiwafDecision validateRequestShape(AiwafRequest req) {
        Map<String, String> parameters = req.query() == null ? Map.of() : req.query();
        if (parameters.size() > Math.max(1, config.maxParameterCount)) {
            return AiwafDecision.deny(400, "Too many request parameters");
        }
        long bytes = 0;
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            bytes += utf8Length(entry.getKey()) + utf8Length(entry.getValue());
            if (bytes > Math.max(1, config.maxParameterBytes)) {
                return AiwafDecision.deny(400, "Request parameters too large");
            }
        }
        if (!config.allowDuplicateParameters
                && "true".equalsIgnoreCase(header(req.headers(), "aiwaf-internal-duplicate-parameters"))) {
            return AiwafDecision.deny(400, "Duplicate request parameters are not accepted");
        }

        Set<String> allowed = allowedContentTypes(req.path());
        if (!allowed.isEmpty() && hasRequestBody(req.method())) {
            String contentType = header(req.headers(), "content-type").toLowerCase(Locale.ROOT);
            int separator = contentType.indexOf(';');
            String mediaType = (separator < 0 ? contentType : contentType.substring(0, separator)).trim();
            if (mediaType.isEmpty() || allowed.stream().noneMatch(v -> v.equalsIgnoreCase(mediaType))) {
                return AiwafDecision.deny(415, "Content-Type is not allowed for this route");
            }
        }
        return null;
    }

    private Set<String> allowedContentTypes(String path) {
        String value = path == null ? "/" : path;
        String best = "";
        Set<String> result = Set.of();
        for (Map.Entry<String, Set<String>> entry : config.allowedContentTypesByPathPrefix.entrySet()) {
            String prefix = entry.getKey();
            if (prefix != null && value.startsWith(prefix) && prefix.length() > best.length()) {
                best = prefix;
                result = entry.getValue() == null ? Set.of() : entry.getValue();
            }
        }
        return result;
    }

    private static boolean hasRequestBody(String method) {
        return Set.of("POST", "PUT", "PATCH").contains(method == null ? "" : method.toUpperCase(Locale.ROOT));
    }

    private static int utf8Length(String value) {
        return value == null ? 0 : value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
    }

    private static boolean looksLikeSerializedValue(String value) {
        if (value == null) return false;
        String compact = value.strip().replaceAll("\\s+", "");
        String lower = compact.toLowerCase(Locale.ROOT);
        return compact.contains("rO0AB")
                || lower.contains("aced0005")
                || lower.contains("%ac%ed%00%05");
    }

    private static String header(Map<String, String> headers, String name) {
        if (headers == null) return "";
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (name.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue() == null ? "" : entry.getValue();
            }
        }
        return "";
    }

    private static boolean isRuleDisabled(AiwafRequest req, AiwafConfig.PathRule rule, AiwafConfig config, String middlewareName) {
        String normalized = ExemptionsCore.normalizeMiddlewareName(middlewareName);
        if (!config.isMiddlewareEnabled(normalized)) {
            return true;
        }
        if (req.disabledMiddlewares() != null && req.disabledMiddlewares().contains(normalized)) {
            return true;
        }
        return rule != null && rule.disables(normalized);
    }

    private static String safeUpper(String s) {
        return s == null ? "" : s.toUpperCase(Locale.ROOT);
    }

    private static String serverProtocolFrom(AiwafRequest req) {
        String protocol = HeaderValidationCore.getHeader(req.headers(), ":protocol");
        if (!protocol.isBlank()) {
            return protocol;
        }
        return "HTTP/1.1";
    }

    private static boolean isValidUuid(String value) {
        if (value == null || value.isBlank()) return false;
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private String detectMaliciousKeyword(String path) {
        String p = path == null ? "" : path.toLowerCase(Locale.ROOT);
        for (String pattern : config.blockedPathPatterns) {
            if (p.contains(pattern.toLowerCase(Locale.ROOT))) return pattern;
        }
        for (String keyword : defaultMaliciousKeywords) {
            if (p.contains(keyword.toLowerCase(Locale.ROOT))) return keyword;
        }
        return null;
    }

    private String detectLearnedKeyword(String path) {
        String p = path == null ? "" : path.toLowerCase(Locale.ROOT);
        String[] tokens = p.split("\\W+");
        Set<String> learned = new HashSet<>(runtimeStorage.keywordStore().getTopKeywords(100));
        for (String token : tokens) {
            if (config.legitimatePathKeywords.contains(token) || config.exemptKeywords.contains(token)) continue;
            // Older releases learned ordinary route words from malicious queries.
            // Retain stored evidence, but require attack evidence in the token itself.
            if (token.length() > 3 && learned.contains(token)
                    && isMaliciousContext(token, Map.of())) return token;
        }
        return null;
    }

    private static boolean isPrivateIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return false;
        }
        if (ip.equals("::1")) {
            return true;
        }
        if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")) {
            return true;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        int first;
        int second;
        try {
            first = Integer.parseInt(parts[0]);
            second = Integer.parseInt(parts[1]);
        } catch (NumberFormatException ex) {
            return false;
        }
        if (first != 172) {
            return false;
        }
        return second >= 16 && second <= 31;
    }

    private boolean isIpExempted(String ip) {
        if (runtimeStorage.exemptionStore().isExempted(ip) || config.exemptIps.contains(ip)) return true;
        if (config.localhostExempted && ("::1".equals(ip) || (ip != null && ip.startsWith("127.")))) return true;
        if (config.privateIpsExempted && isPrivateIp(ip)) return true;
        Set<String> patterns = new HashSet<>(config.exemptIpPatterns);
        for (String configured : config.exemptIps) {
            if (configured != null && (configured.contains("*") || configured.contains("/"))) patterns.add(configured);
        }
        for (String pattern : patterns) {
            if (pattern == null || pattern.isBlank()) continue;
            if (pattern.contains("/") && CidrUtil.contains(pattern, ip)) return true;
            String regex = pattern.replace(".", "\\.").replace("*", ".*");
            if (ip != null && ip.matches(regex)) return true;
        }
        return false;
    }

    private static String blankToDefault(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value;
    }

    private static int resolveOverride(AiwafConfig.PathRule rule, String middleware, String key, int fallback) {
        if (rule == null) {
            return fallback;
        }
        Integer override = rule.getOverride(middleware, key);
        return override == null ? fallback : override;
    }

    private static int resolveRateLimitOverride(AiwafConfig.PathRule rule, String key, int fallback, Integer explicitOverride) {
        if (explicitOverride != null) {
            return explicitOverride;
        }
        if (rule == null) {
            return fallback;
        }
        Integer generic = rule.getOverride("rate_limit", key);
        if (generic == null) {
            generic = rule.getOverride("RATE_LIMIT", key);
        }
        return generic == null ? fallback : generic;
    }

    private AiwafDecision evaluateAiAnomaly(AiwafRequest req, String ip, int statusCode, long responseTimeMs, long nowMillis) {
        TrainedModelCore trainedModel = modelProvider.get();
        if (trainedModel == null || trainedModel.payload() == null) {
            return null;
        }
        Object ifObj = trainedModel.payload().get("isolation_forest");
        if (!(ifObj instanceof Map<?, ?> ifMap)) {
            return null;
        }
        Object modelObj = ifMap.get("model");
        if (!(modelObj instanceof IsolationForestCore.Model model)) {
            return null;
        }
        Object namesObj = ifMap.get("feature_names");
        if (!(namesObj instanceof List<?> rawNames) || rawNames.isEmpty()) {
            return null;
        }

        Object metadataObj = trainedModel.payload().get("metadata");
        boolean pythonSixFeatures = metadataObj instanceof Map<?, ?> metadata
                && "python-six-v1".equals(metadata.get("feature_schema"));
        String matched = detectMaliciousKeyword(req.path());
        int kwHits = matched == null ? 0 : 1;
        if (pythonSixFeatures && ifMap.get("static_keywords") instanceof List<?> keywords) {
            String pathLower = req.path() == null ? "" : req.path().toLowerCase(Locale.ROOT);
            kwHits = 0;
            for (Object keyword : keywords) {
                if (keyword instanceof String value && !value.isEmpty() && pathLower.contains(value)) kwHits++;
            }
        }
        int burst = recentBurst(ip, nowMillis);
        int total404 = recent404(ip, nowMillis, config.aiRecentWindowSeconds);
        int statusIdx = pythonSixFeatures
                ? FLASK_ANOMALY_STATUS_CODES.indexOf(String.valueOf(statusCode))
                : switch (statusCode) {
                    case 200 -> 0;
                    case 403 -> 1;
                    case 404 -> 2;
                    case 500 -> 3;
                    default -> -1;
                };
        int pathDepth = 0;
        if (req.path() != null) {
            for (String p : req.path().split("/")) {
                if (!p.isBlank()) pathDepth++;
            }
        }

        double[] row = new double[rawNames.size()];
        for (int i = 0; i < rawNames.size(); i++) {
            String name = String.valueOf(rawNames.get(i));
            row[i] = switch (name) {
                case "path_len" -> req.path() == null ? 0.0 : (pythonSixFeatures
                        ? req.path().codePointCount(0, req.path().length()) : req.path().length());
                case "kw_hits" -> kwHits;
                case "status_code" -> statusCode;
                case "status_idx" -> statusIdx;
                case "response_time_ms" -> Math.max(0L, responseTimeMs);
                case "resp_time" -> Math.max(0L, responseTimeMs) / 1000.0;
                case "burst_count" -> burst;
                case "total_404" -> total404;
                case "path_depth" -> pathDepth;
                case "method_is_post" -> "POST".equalsIgnoreCase(req.method()) ? 1.0 : 0.0;
                default -> 0.0;
            };
        }

        double score = IsolationForestCore.score(model, row);
        double modelThreshold = ifMap.get("threshold") instanceof Number n ? n.doubleValue() : config.aiAnomalyScoreThreshold;
        double threshold = Math.min(modelThreshold, config.aiAnomalyScoreThreshold);
        if (score < threshold) {
            return null;
        }

        if (config.aiRequireBehaviorConfirmation) {
            int recent = recentCount(ip, nowMillis, config.aiRecentWindowSeconds);
            if (recent < config.aiMinRecentSamplesToBlock) {
                return null;
            }
        }

        blockWithContext(ip, req, String.format(Locale.ROOT, "AI anomaly score %.4f >= %.4f", score, threshold));
        return AiwafDecision.deny(403, String.format(Locale.ROOT, "AI anomaly score %.4f", score));
    }

    private void maybeLearnKeywords(AiwafRequest req) {
        if (!config.enableKeywordLearning || req.path() == null) {
            return;
        }
        String lower = req.path().toLowerCase(Locale.ROOT);
        if (!isMaliciousContext(lower, req.query())) {
            return;
        }
        String[] segments = lower.split("\\W+");
        int added = 0;
        for (String seg : segments) {
            if (seg == null || seg.length() <= 3) continue;
            if (config.exemptKeywords.contains(seg)) continue;
            if (config.legitimatePathKeywords.contains(seg)) continue;
            if (defaultMaliciousKeywords.contains(seg)) continue;
            // Query evidence must not label unrelated route segments as malicious.
            if (!isMaliciousContext(seg, Map.of())) continue;
            runtimeStorage.keywordStore().addKeyword(seg, 1);
            added++;
            if (added >= config.dynamicTopN) {
                break;
            }
        }
    }

    private boolean isMaliciousContext(String lowerPath, Map<String, String> query) {
        if (lowerPath.contains("../") || lowerPath.contains("..\\") || lowerPath.contains("%2e%2e")) {
            return true;
        }
        if (lowerPath.contains(".php") || lowerPath.contains(".env") || lowerPath.contains("wp-admin") || lowerPath.contains("phpmyadmin")) {
            return true;
        }
        if (query == null || query.isEmpty()) {
            return false;
        }
        String q = query.toString().toLowerCase(Locale.ROOT);
        return q.contains("cmd=") || q.contains("exec=") || q.contains("system=") || q.contains("union") || q.contains("<script");
    }

    private void blockWithContext(String ip, AiwafRequest req, String reason) {
        Map<String, Object> ext = config.storeExtendedBlockInfo ? extendedBlockInfo(req) : null;
        BlocklistManager.block(runtimeStorage, ip, reason, null, ext);
        telemetryIncrement("blocks.total");
    }

    private Map<String, Object> extendedBlockInfo(AiwafRequest req) {
        Map<String, Object> out = new HashMap<>();
        out.put("method", blankToDefault(req.method(), ""));
        out.put("path", blankToDefault(req.path(), ""));
        if (req.query() != null && !req.query().isEmpty()) {
            Map<String, String> safeQuery = new HashMap<>();
            for (Map.Entry<String, String> entry : req.query().entrySet()) {
                String key = entry.getKey() == null ? "" : entry.getKey();
                boolean sensitive = config.sensitiveParameterNames.stream()
                        .filter(java.util.Objects::nonNull)
                        .anyMatch(name -> name.equalsIgnoreCase(key));
                safeQuery.put(key, sensitive ? "[redacted]" : entry.getValue());
            }
            out.put("query", safeQuery);
        }
        out.put("headers", redactHeaders(req.headers()));
        return out;
    }

    private Map<String, String> redactHeaders(Map<String, String> headers) {
        Map<String, String> out = new HashMap<>();
        if (headers == null || headers.isEmpty()) return out;
        int max = Math.max(1, config.blockInfoMaxHeaders);
        int maxLen = Math.max(16, config.blockInfoMaxHeaderValueLength);
        Set<String> redact = new HashSet<>();
        for (String h : config.blockInfoRedactHeaders) {
            if (h != null) redact.add(h.toLowerCase(Locale.ROOT));
        }
        int count = 0;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (count >= max) break;
            String key = e.getKey() == null ? "" : e.getKey();
            String lower = key.toLowerCase(Locale.ROOT);
            String value = e.getValue() == null ? "" : e.getValue();
            if (redact.contains(lower)) {
                out.put(key, "[redacted]");
            } else {
                if (value.length() > maxLen) {
                    value = value.substring(0, maxLen) + "...(truncated)";
                }
                out.put(key, value);
            }
            count++;
        }
        return out;
    }

    private AiwafDecision finalizeDecision(AiwafDecision decision, long startedNs, String outcomeTag) {
        long elapsedMs = (System.nanoTime() - startedNs) / 1_000_000L;
        telemetryObserve("requests.evaluate.latency_ms", elapsedMs);
        if (decision.allowed()) {
            telemetryIncrement("requests.allowed");
        } else {
            telemetryIncrement("requests.blocked");
            telemetryIncrement("requests.blocked.status." + decision.statusCode());
            telemetryIncrement("requests.blocked.outcome." + outcomeTag);
        }
        return decision;
    }

    private void telemetryIncrement(String key) {
        if (!config.observabilityEnabled) return;
        telemetry.increment(key);
    }

    private void telemetryObserve(String key, long valueMs) {
        if (!config.observabilityEnabled) return;
        telemetry.observeMs(key, valueMs);
    }

    private void recordRecent(String ip, AiwafRequest req, int statusCode) {
        recordRecent(ip, req, statusCode, req.nowEpochMillis());
    }

    private void recordRecent(String ip, AiwafRequest req, int statusCode, long nowMillis) {
        runtimeStorage.state().recordRecent(
                ip,
                nowMillis,
                statusCode,
                config.aiRecentWindowSeconds,
                config.maxRuntimeStateEntries
        );
    }

    private int recentCount(String ip, long nowMillis, int windowSeconds) {
        return runtimeStorage.state().recentStats(ip, nowMillis, windowSeconds).count();
    }

    private int recent404(String ip, long nowMillis, int windowSeconds) {
        return runtimeStorage.state().recentStats(ip, nowMillis, windowSeconds).notFoundCount();
    }

    private int recentBurst(String ip, long nowMillis) {
        return runtimeStorage.state().recentStats(ip, nowMillis, config.aiRecentWindowSeconds).burstCount();
    }
}
