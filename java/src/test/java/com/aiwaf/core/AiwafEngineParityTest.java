package com.aiwaf.core;

import com.aiwaf.runtime.RuntimeStorage;
import com.aiwaf.runtime.BlocklistManager;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

class AiwafEngineParityTest {

    @Test
    void rejects_java_serialization_content_type_before_route_exemptions() {
        AiwafConfig config = new AiwafConfig();
        AiwafEngine engine = new AiwafEngine(config);
        AiwafDecision decision = engine.evaluate(req(
                "POST",
                "/health",
                "198.51.100.200",
                Map.of("Content-Type", "application/x-java-serialized-object; charset=binary"),
                Map.of(),
                "US"
        ));

        assertFalse(decision.allowed());
        assertEquals(415, decision.statusCode());
    }

    @Test
    void rejects_base64_java_serialization_in_query() {
        AiwafConfig config = new AiwafConfig();
        AiwafEngine engine = new AiwafEngine(config);
        AiwafDecision decision = engine.evaluate(req(
                "GET",
                "/decode",
                "198.51.100.201",
                browserHeaders(),
                Map.of("value", "rO0ABXNyABFqYXZhLmxhbmcuU3RyaW5n"),
                "US"
        ));

        assertFalse(decision.allowed());
        assertEquals(415, decision.statusCode());
    }

    @Test
    void global_disabled_middlewares_use_python_style_names() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.rateLimitEnabled = true;
        config.rateLimitMax = 1;
        config.headerValidationEnabled = false;
        config.disabledMiddlewares.add("RateLimitMiddleware");
        AiwafEngine engine = new AiwafEngine(config);

        AiwafDecision first = engine.evaluate(req("GET", "/p", "198.51.100.41", browserHeaders(), Map.of(), "US"));
        AiwafDecision second = engine.evaluate(req("GET", "/p", "198.51.100.41", browserHeaders(), Map.of(), "US"));

        assertTrue(first.allowed());
        assertTrue(second.allowed());
    }

    @Test
    void enabled_middlewares_allowlist_restricts_other_checks() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.rateLimitEnabled = true;
        config.rateLimitMax = 1;
        config.headerValidationEnabled = true;
        config.enabledMiddlewares.add("rate_limit");
        AiwafEngine engine = new AiwafEngine(config);

        Map<String, String> suspicious = new HashMap<>();
        suspicious.put("User-Agent", "curl/8.0.1");
        suspicious.put("Accept", "*/*");

        AiwafDecision first = engine.evaluate(req("GET", "/p", "198.51.100.42", suspicious, Map.of(), "US"));
        AiwafDecision second = engine.evaluate(req("GET", "/p", "198.51.100.42", suspicious, Map.of(), "US"));

        assertTrue(first.allowed());
        assertEquals(429, second.statusCode());
    }

    @Test
    void geo_block_reads_dynamic_runtime_store() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.geoBlockEnabled = true;
        config.headerValidationEnabled = false;
        config.rateLimitEnabled = false;
        AiwafEngine engine = new AiwafEngine(config);
        RuntimeStorage.getGeoBlockStore().addCountry("US");

        AiwafDecision decision = engine.evaluate(req(
                "GET",
                "/geo",
                "198.51.100.43",
                browserHeaders(),
                Map.of(),
                "US"
        ));
        assertEquals(403, decision.statusCode());
    }

    @Test
    void runtime_path_exemptions_bypass_header_and_rate_controls() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.rateLimitEnabled = true;
        config.rateLimitMax = 1;
        config.headerValidationEnabled = true;
        AiwafEngine engine = new AiwafEngine(config);
        RuntimeStorage.getPathExemptionStore().addPath("/health", "health check");

        Map<String, String> suspicious = new HashMap<>();
        suspicious.put("User-Agent", "curl/8.0.1");
        suspicious.put("Accept", "*/*");

        AiwafDecision first = engine.evaluate(req("GET", "/health", "198.51.100.44", suspicious, Map.of(), "US"));
        AiwafDecision second = engine.evaluate(req("GET", "/health", "198.51.100.44", suspicious, Map.of(), "US"));
        assertTrue(first.allowed());
        assertTrue(second.allowed());
    }

    @Test
    void required_headers_default_key_fallback_is_applied() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.rateLimitEnabled = false;
        config.requiredHeadersByMethod.clear();
        config.requiredHeadersByMethod.put("DEFAULT", List.of("user-agent"));
        AiwafEngine engine = new AiwafEngine(config);

        AiwafDecision blocked = engine.evaluate(req("POST", "/x", "198.51.100.45", Map.of(), Map.of(), "US"));
        assertEquals(403, blocked.statusCode());

        AiwafDecision allowed = engine.evaluate(req(
                "POST",
                "/x",
                "198.51.100.45",
                Map.of("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
                Map.of(),
                "US"
        ));
        assertTrue(allowed.allowed());
    }

    @Test
    void path_rule_header_validation_override_applies_quality_threshold() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.rateLimitEnabled = false;
        config.headerValidationEnabled = true;
        config.minHeaderQualityScore = 6;

        Map<String, Map<String, Integer>> overrides = new HashMap<>();
        overrides.put("HEADER_VALIDATION", Map.of("quality_threshold", 1));
        config.pathRules.add(new AiwafConfig.PathRule(
                "/api/",
                false,
                null,
                null,
                null,
                Set.of(),
                overrides
        ));
        AiwafEngine engine = new AiwafEngine(config);

        Map<String, String> minimal = Map.of(
                "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept", "text/html"
        );

        AiwafDecision blockedOutsideRule = engine.evaluate(req("GET", "/ui", "198.51.100.46", minimal, Map.of(), "US"));
        assertEquals(403, blockedOutsideRule.statusCode());

        AiwafDecision allowedInsideRule = engine.evaluate(req("GET", "/api/data", "198.51.100.46", minimal, Map.of(), "US"));
        assertTrue(allowedInsideRule.allowed());
    }

    @Test
    void path_rule_rate_limit_override_reads_generic_map_fields() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.headerValidationEnabled = false;
        config.rateLimitEnabled = true;
        config.rateLimitMax = 1;

        Map<String, Map<String, Integer>> overrides = new HashMap<>();
        overrides.put("RATE_LIMIT", Map.of("MAX", 3, "WINDOW", 60, "FLOOD", 10));
        config.pathRules.add(new AiwafConfig.PathRule(
                "/api/",
                false,
                null,
                null,
                null,
                Set.of(),
                overrides
        ));
        AiwafEngine engine = new AiwafEngine(config);

        AiwafDecision a1 = engine.evaluate(req("GET", "/api/data", "198.51.100.47", browserHeaders(), Map.of(), "US"));
        AiwafDecision a2 = engine.evaluate(req("GET", "/api/data", "198.51.100.47", browserHeaders(), Map.of(), "US"));
        AiwafDecision a3 = engine.evaluate(req("GET", "/api/data", "198.51.100.47", browserHeaders(), Map.of(), "US"));
        AiwafDecision a4 = engine.evaluate(req("GET", "/api/data", "198.51.100.47", browserHeaders(), Map.of(), "US"));
        assertTrue(a1.allowed());
        assertTrue(a2.allowed());
        assertTrue(a3.allowed());
        assertEquals(429, a4.statusCode());
    }

    @Test
    void honeypot_page_expired_returns_409() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.rateLimitEnabled = false;
        config.headerValidationEnabled = false;
        config.honeypotEnabled = true;
        config.maxFormPageTimeSeconds = 5.0;
        AiwafEngine engine = new AiwafEngine(config);

        long base = 10_000L;
        AiwafDecision first = engine.evaluate(new AiwafRequest(
                "GET", "/contact/submit/", "198.51.100.61", "US", browserHeaders(), Map.of(), base, Set.of()
        ));
        AiwafDecision second = engine.evaluate(new AiwafRequest(
                "POST", "/contact/submit/", "198.51.100.61", "US", browserHeaders(), Map.of(), base + 10_000L, Set.of()
        ));
        assertTrue(first.allowed());
        assertEquals(409, second.statusCode());
    }

    @Test
    void honeypot_login_paths_use_relaxed_min_time() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.rateLimitEnabled = false;
        config.headerValidationEnabled = false;
        config.honeypotEnabled = true;
        config.minFormTimeSeconds = 1.0;
        config.loginMinFormTimeSeconds = 0.1;
        AiwafEngine engine = new AiwafEngine(config);

        long base = 20_000L;
        AiwafDecision normalGet = engine.evaluate(new AiwafRequest(
                "GET", "/contact/submit/", "198.51.100.62", "US", browserHeaders(), Map.of(), base, Set.of()
        ));
        AiwafDecision normalPostFast = engine.evaluate(new AiwafRequest(
                "POST", "/contact/submit/", "198.51.100.62", "US", browserHeaders(), Map.of(), base + 200L, Set.of()
        ));

        AiwafDecision loginGet = engine.evaluate(new AiwafRequest(
                "GET", "/login/form/", "198.51.100.63", "US", browserHeaders(), Map.of(), base, Set.of()
        ));
        AiwafDecision loginPostFast = engine.evaluate(new AiwafRequest(
                "POST", "/login/form/", "198.51.100.63", "US", browserHeaders(), Map.of(), base + 200L, Set.of()
        ));

        assertTrue(normalGet.allowed());
        assertEquals(403, normalPostFast.statusCode());
        assertTrue(loginGet.allowed());
        assertTrue(loginPostFast.allowed());
    }

    @Test
    void ai_model_lazy_load_can_block_anomalous_request() throws Exception {
        List<NormalizedEvent> training = List.of(
                new NormalizedEvent("1.1.1.1", "GET", "/home", 200, 3, java.time.LocalDateTime.now(), "", "", "", true, false),
                new NormalizedEvent("1.1.1.1", "GET", "/about", 200, 3, java.time.LocalDateTime.now(), "", "", "", true, false),
                new NormalizedEvent("1.1.1.2", "GET", "/contact", 200, 3, java.time.LocalDateTime.now(), "", "", "", true, false),
                new NormalizedEvent("1.1.1.3", "GET", "/pricing", 200, 3, java.time.LocalDateTime.now(), "", "", "", true, false)
        );
        TrainedModelCore model = TrainingCore.trainModel(training, List.of(".php", ".env", "wp-admin"));
        String path = Files.createTempFile("aiwaf-model-", ".bin").toString();
        assertTrue(ModelArtifactIoCore.save(model, path));

        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.headerValidationEnabled = false;
        config.rateLimitEnabled = false;
        config.ipKeywordBlockEnabled = false;
        config.aiEnabled = true;
        config.aiModelPath = path;
        config.aiRequireBehaviorConfirmation = false;
        config.aiAnomalyScoreThreshold = 0.01;
        AiwafEngine engine = new AiwafEngine(config);

        AiwafDecision d = engine.evaluate(req(
                "GET",
                "/wp-admin/.env/shell",
                "198.51.100.88",
                browserHeaders(),
                Map.of(),
                "US"
        ));
        assertEquals(403, d.statusCode());

        AiwafConfig routed = new AiwafConfig();
        routed.privateIpsExempted = false;
        routed.headerValidationEnabled = false;
        routed.rateLimitEnabled = false;
        routed.ipKeywordBlockEnabled = false;
        routed.aiEnabled = true;
        routed.aiModelPath = path;
        routed.aiRequireBehaviorConfirmation = false;
        routed.aiAnomalyScoreThreshold = 0.01;
        routed.pathRules.add(new AiwafConfig.PathRule(
                "/wp-admin/", false, null, null, null, Set.of("AIAnomalyMiddleware")
        ));
        AiwafDecision routeDisabled = new AiwafEngine(routed).evaluate(req(
                "GET", "/wp-admin/.env/shell", "198.51.100.89", browserHeaders(), Map.of(), "US"
        ));
        assertTrue(routeDisabled.allowed());
    }

    @Test
    void blocked_requests_store_redacted_extended_context() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.headerValidationEnabled = false;
        config.rateLimitEnabled = false;
        config.storeExtendedBlockInfo = true;
        AiwafEngine engine = new AiwafEngine(config);

        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Mozilla/5.0");
        headers.put("Accept", "text/html");
        headers.put("Authorization", "Bearer secret-token");
        String ip = "198.51.100.91";

        AiwafDecision d = engine.evaluate(req("GET", "/wp-admin/.env", ip, headers, Map.of("cmd", "id"), "US"));
        assertEquals(403, d.statusCode());

        Map<String, Object> block = BlocklistManager.getBlockInfo(ip);
        @SuppressWarnings("unchecked")
        Map<String, Object> ext = (Map<String, Object>) block.get("extended_request_info");
        @SuppressWarnings("unchecked")
        Map<String, String> extHeaders = (Map<String, String>) ext.get("headers");
        assertEquals("[redacted]", extHeaders.get("Authorization"));
        assertEquals("/wp-admin/.env", ext.get("path"));
    }

    @Test
    void observability_counters_are_recorded_for_allow_and_block_paths() {
        AiwafConfig config = new AiwafConfig();
        config.privateIpsExempted = false;
        config.headerValidationEnabled = false;
        config.rateLimitEnabled = true;
        config.rateLimitMax = 1;
        config.observabilityEnabled = true;
        AiwafEngine engine = new AiwafEngine(config);

        engine.evaluate(req("GET", "/ok", "198.51.100.92", browserHeaders(), Map.of(), "US"));
        engine.evaluate(req("GET", "/ok", "198.51.100.92", browserHeaders(), Map.of(), "US"));

        var counters = engine.telemetry().counterSnapshot();
        var h = engine.telemetry().histogramSnapshot();
        assertTrue(counters.getOrDefault("requests.total", 0L) >= 2L);
        assertTrue(counters.getOrDefault("requests.allowed", 0L) >= 1L);
        assertTrue(counters.getOrDefault("requests.blocked", 0L) >= 1L);
        assertFalse(h.isEmpty());
    }

    private static AiwafRequest req(
            String method,
            String path,
            String ip,
            Map<String, String> headers,
            Map<String, String> query,
            String country
    ) {
        return new AiwafRequest(method, path, ip, country, headers, query, System.currentTimeMillis(), Set.of());
    }

    private static Map<String, String> browserHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        headers.put("Accept", "text/html,application/xhtml+xml");
        headers.put("Accept-Language", "en-US,en;q=0.9");
        headers.put("Accept-Encoding", "gzip, deflate, br");
        headers.put("Connection", "keep-alive");
        return headers;
    }
}
