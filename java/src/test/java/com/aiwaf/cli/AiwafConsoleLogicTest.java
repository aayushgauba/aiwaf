package com.aiwaf.cli;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertTrue;

class AiwafConsoleLogicTest {

    @Test
    void geo_and_exempt_path_commands_are_supported() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream oldOut = System.out;
        System.setOut(new PrintStream(out));
        try {
            AiwafConsole.main(new String[]{"geo", "add", "US"});
            AiwafConsole.main(new String[]{"geo", "list"});
            AiwafConsole.main(new String[]{"exempt-path", "add", "/health", "--reason", "Health check"});
            AiwafConsole.main(new String[]{"exempt-path", "list"});
        } finally {
            System.setOut(oldOut);
        }
        String output = out.toString();
        assertTrue(output.contains("US"));
        assertTrue(output.contains("/health"));
    }

    @Test
    void export_import_and_reset_commands_are_supported() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream oldOut = System.out;
        System.setOut(new PrintStream(out));
        try {
            AiwafConsole.main(new String[]{"add", "blocklist", "198.51.100.99", "--reason", "test"});
            AiwafConsole.main(new String[]{"export", "aiwaf-console-export.bin"});
            AiwafConsole.main(new String[]{"reset"});
            AiwafConsole.main(new String[]{"import", "aiwaf-console-export.bin"});
            AiwafConsole.main(new String[]{"list", "blocklist"});
        } finally {
            System.setOut(oldOut);
        }
        String output = out.toString();
        assertTrue(output.contains("198.51.100.99"));
    }

    @Test
    void reset_flags_support_python_style_selective_behavior() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream oldOut = System.out;
        System.setOut(new PrintStream(out));
        try {
            AiwafConsole.main(new String[]{"add", "blocklist", "198.51.100.130", "--reason", "test"});
            AiwafConsole.main(new String[]{"add", "allowlist", "203.0.113.130"});
            AiwafConsole.main(new String[]{"add", "keyword", "login"});

            AiwafConsole.main(new String[]{"reset", "--blocklist"});
            AiwafConsole.main(new String[]{"list", "blocklist"});
            AiwafConsole.main(new String[]{"list", "allowlist"});
            AiwafConsole.main(new String[]{"list", "keywords"});

            AiwafConsole.main(new String[]{"reset", "--exemptions-only"});
            AiwafConsole.main(new String[]{"list", "allowlist"});
            AiwafConsole.main(new String[]{"list", "keywords"});

            AiwafConsole.main(new String[]{"reset", "--keywords"});
            AiwafConsole.main(new String[]{"list", "keywords"});
        } finally {
            System.setOut(oldOut);
        }
        String output = out.toString();
        assertTrue(output.contains("203.0.113.130"));
        assertTrue(output.contains("login"));
    }

    @Test
    void import_command_returns_noop_for_invalid_file() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream oldOut = System.out;
        System.setOut(new PrintStream(out));
        try {
            AiwafConsole.main(new String[]{"import", "missing-file.bin"});
        } finally {
            System.setOut(oldOut);
        }
        assertTrue(out.toString().contains("noop"));
    }

    @Test
    void list_all_and_path_exemptions_alias_are_supported() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream oldOut = System.out;
        System.setOut(new PrintStream(out));
        try {
            AiwafConsole.main(new String[]{"add", "geo", "FR"});
            AiwafConsole.main(new String[]{"add", "path-exemptions", "/status", "--reason", "Status endpoint"});
            AiwafConsole.main(new String[]{"list", "all"});
            AiwafConsole.main(new String[]{"list", "path-exemptions"});
        } finally {
            System.setOut(oldOut);
        }
        String output = out.toString();
        assertTrue(output.contains("geo="));
        assertTrue(output.contains("path_exemptions="));
        assertTrue(output.contains("FR"));
        assertTrue(output.contains("/status"));
    }

    @Test
    void invalid_console_commands_print_usage() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream oldOut = System.out;
        System.setOut(new PrintStream(out));
        try {
            AiwafConsole.main(new String[]{"list", "unknown-target"});
            AiwafConsole.main(new String[]{"geo", "unknown-action"});
        } finally {
            System.setOut(oldOut);
        }
        assertTrue(out.toString().contains("Usage:"));
    }

    @Test
    void invalid_add_remove_targets_return_noop() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream oldOut = System.out;
        System.setOut(new PrintStream(out));
        try {
            AiwafConsole.main(new String[]{"add", "unknown", "value"});
            AiwafConsole.main(new String[]{"remove", "unknown", "value"});
        } finally {
            System.setOut(oldOut);
        }
        String output = out.toString();
        assertTrue(output.contains("noop"));
    }
}
