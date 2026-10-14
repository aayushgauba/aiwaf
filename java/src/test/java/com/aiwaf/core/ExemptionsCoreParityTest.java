package com.aiwaf.core;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExemptionsCoreParityTest {

    @Test
    void normalize_path_behaves_like_python() {
        assertEquals("/", ExemptionsCore.normalizePath("", null));
        assertEquals("/a/b", ExemptionsCore.normalizePath("a//b", false));
        assertEquals("/a/b/", ExemptionsCore.normalizePath("a//b", true));
    }

    @Test
    void path_exempt_wildcard_and_prefix() {
        Set<String> exempt = Set.of("/health", "/static/", "*.css");
        assertTrue(ExemptionsCore.isPathExempt("/health", exempt, true, true));
        assertTrue(ExemptionsCore.isPathExempt("/static/js/app.js", exempt, true, true));
        assertTrue(ExemptionsCore.isPathExempt("/styles/main.css", exempt, true, true));
        assertFalse(ExemptionsCore.isPathExempt("/api/users", exempt, true, true));
    }

    @Test
    void best_matching_path_rule_is_selected() {
        AiwafConfig.PathRule broad = new AiwafConfig.PathRule("/api/", false, 10);
        AiwafConfig.PathRule narrow = new AiwafConfig.PathRule("/api/private/", false, 1);
        AiwafConfig.PathRule selected = ExemptionsCore.getPathRuleForPath("/api/private/data", List.of(broad, narrow));
        assertNotNull(selected);
        assertEquals(1, selected.rateLimitMaxOverride);
    }

    @Test
    void path_rule_disables_named_middleware() {
        AiwafConfig.PathRule rule = new AiwafConfig.PathRule(
                "/api/",
                false,
                null,
                null,
                null,
                Set.of("rate_limit", "HeaderValidationMiddleware")
        );
        assertTrue(rule.disables("rate_limit"));
        assertTrue(rule.disables("headervalidationmiddleware"));
        assertFalse(rule.disables("geo_block"));
        assertEquals("ai_anomaly", ExemptionsCore.normalizeMiddlewareName("AIAnomalyMiddleware"));
        assertEquals("logging", ExemptionsCore.normalizeMiddlewareName("AIWAFLoggingMiddleware"));
    }

    @Test
    void normalize_path_handles_edge_cases() {
        assertEquals("/", ExemptionsCore.normalizePath(null, null));
        assertEquals("/", ExemptionsCore.normalizePath("   ", null));

        assertEquals("/api/users",
                ExemptionsCore.normalizePath("API///Users", false));

        assertEquals("/api/users/",
                ExemptionsCore.normalizePath("  //API///Users//  ", true));

        assertEquals("/api/users",
                ExemptionsCore.normalizePath("/api/users/", false));

        assertEquals("/api/users/",
                ExemptionsCore.normalizePath("/api/users", true));

        assertEquals("/",
                ExemptionsCore.normalizePath("////", false));
    }

@Test
void optimized_normalization_matches_original() {
    String[] paths = {
        "",
        "/",
        "////",
        "api/users",
        "/api//users",
        "///API///Users///",
        "  /api/users  ",
        "/Admin/Login",
        "index.html",
        "/api/v1/users/123",
        "/a///b///c",
        " / ",
        "\t/api//test\n"
    };

    Boolean[] modes = {null, true, false};

    for (String path : paths) {
        for (Boolean mode : modes) {
            String expected = originalNormalizePath(path, mode);
            String actual = ExemptionsCore.normalizePath(path, mode);

            assertEquals(expected, actual,
                    "Mismatch for path: " + path + ", mode: " + mode);
        }
    }
}

private static String originalNormalizePath(
        String path, Boolean trailingSlash) {

    if (path == null || path.isBlank()) {
        return "/";
    }

    String cleaned = path.trim().replaceAll("/+", "/");

    if (!cleaned.startsWith("/")) {
        cleaned = "/" + cleaned;
    }

    if (Boolean.TRUE.equals(trailingSlash)
            && !cleaned.endsWith("/")) {
        cleaned = cleaned + "/";
    }

    if (Boolean.FALSE.equals(trailingSlash)
            && cleaned.length() > 1
            && cleaned.endsWith("/")) {
        cleaned = cleaned.substring(0, cleaned.length() - 1);
    }

    return cleaned.toLowerCase(java.util.Locale.ROOT);
}


}
