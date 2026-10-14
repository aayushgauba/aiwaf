package com.aiwaf.cli;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AiwafManagerLogicTest {

    @Test
    void manager_updates_runtime_stores_for_core_logic() {
        AiwafManager manager = new AiwafManager("aiwaf-manager-test.bin");

        assertTrue(manager.addToAllowlist("203.0.113.10"));
        assertTrue(manager.listAllowlistIps().contains("203.0.113.10"));

        assertTrue(manager.addGeoBlockedCountry("US"));
        assertTrue(manager.listGeoBlockedCountries().contains("US"));

        assertTrue(manager.addPathExemption("/health", "health"));
        assertTrue(manager.listPathExemptions().contains("/health"));

        assertTrue(manager.addToBlocklist("198.51.100.80", "manual"));
        assertTrue(manager.listBlocklist().containsKey("198.51.100.80"));
    }

    @Test
    void manager_blocklist_extended_info_export_import_and_reset() {
        String dataPath = "aiwaf-manager-test-2.bin";
        AiwafManager manager = new AiwafManager(dataPath);
        Map<String, Object> ext = Map.of("path", "/login", "method", "POST");
        assertTrue(manager.addToBlocklist("198.51.100.91", "extended", ext));

        Map<String, Map<String, Object>> bl = manager.listBlocklist();
        assertTrue(bl.containsKey("198.51.100.91"));
        assertEquals("/login", ((Map<?, ?>) bl.get("198.51.100.91").get("extended_request_info")).get("path"));

        String exportFile = "aiwaf-manager-export.bin";
        assertTrue(manager.exportConfig(exportFile));
        assertTrue(new File(exportFile).exists());

        assertTrue(manager.resetAll());
        assertTrue(manager.listBlocklistIps().isEmpty());

        assertTrue(manager.importConfig(exportFile));
        assertTrue(manager.listBlocklist().containsKey("198.51.100.91"));

        assertTrue(manager.reset(true, false));
        assertTrue(manager.listBlocklistIps().isEmpty());
    }

    @Test
    void manager_selective_reset_matches_python_style_flags() {
        AiwafManager manager = new AiwafManager("aiwaf-manager-reset-test.bin");
        assertTrue(manager.addToBlocklist("198.51.100.120", "test"));
        assertTrue(manager.addToAllowlist("203.0.113.120"));
        assertTrue(manager.addKeyword("login"));

        assertTrue(manager.resetSelective(true, false, false));
        assertTrue(manager.listBlocklistIps().isEmpty());
        assertTrue(manager.listAllowlistIps().contains("203.0.113.120"));
        assertTrue(manager.listKeywords().contains("login"));

        assertTrue(manager.resetSelective(false, true, false));
        assertTrue(manager.listAllowlistIps().isEmpty());
        assertTrue(manager.listKeywords().contains("login"));

        assertTrue(manager.resetSelective(false, false, true));
        assertTrue(manager.listKeywords().isEmpty());
    }

    @Test
    void manager_import_rejects_missing_or_malformed_payloads() throws Exception {
        AiwafManager manager = new AiwafManager("aiwaf-manager-invalid-import.bin");
        assertFalse(manager.importConfig("this-file-does-not-exist.bin"));

        Path malformed = Path.of("aiwaf-manager-malformed-import.bin");
        Files.writeString(malformed, "not-a-serialized-map", StandardCharsets.UTF_8);
        assertFalse(manager.importConfig(malformed.toString()));
    }

    @Test
    void manager_rejects_blank_inputs_and_blank_paths() {
        AiwafManager manager = new AiwafManager("aiwaf-manager-invalid-inputs.bin");

        assertFalse(manager.addAllowlistIp(" ", "x"));
        assertFalse(manager.removeAllowlistIp(""));
        assertFalse(manager.addBlocklistIp(" ", "x"));
        assertFalse(manager.removeBlocklistIp(""));
        assertFalse(manager.addKeyword(" "));
        assertFalse(manager.removeKeyword(""));
        assertFalse(manager.addGeoBlockedCountry(" "));
        assertFalse(manager.removeGeoBlockedCountry(""));
        assertFalse(manager.addPathExemption(" ", "x"));
        assertFalse(manager.removePathExemption(""));
        assertFalse(manager.exportConfig(" "));
        assertFalse(manager.importConfig(" "));
    }
}
