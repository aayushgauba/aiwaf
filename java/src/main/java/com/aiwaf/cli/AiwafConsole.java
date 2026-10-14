package com.aiwaf.cli;

import com.aiwaf.core.WhoisLookup;
import com.aiwaf.core.CoreCli;
import com.aiwaf.core.ModelArtifactIoCore;
import com.aiwaf.core.TrainedModelCore;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Path;

public final class AiwafConsole {
    private AiwafConsole() {}

    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            printUsage();
            return;
        }
        String cmd = args[0].toLowerCase(Locale.ROOT);
        args = args.clone();
        if (args.length > 1 && java.util.Set.of("list", "add", "remove").contains(cmd)) {
            if (args[1].equals("blacklist")) args[1] = "blocklist";
            if (args[1].equals("whitelist")) args[1] = "allowlist";
        }
        if (cmd.equals("reset")) {
            for (int i = 1; i < args.length; i++) args[i] = args[i].replace("--blacklist", "--blocklist");
        }
        try {
            switch (cmd) {
                case "stats", "status" -> System.out.println(manager().stats());
                case "diagnose" -> handleDiagnose(manager(), args);
                case "list" -> handleList(manager(), args);
                case "blocked" -> System.out.println(manager().listBlocklist());
                case "unblock" -> handleUnblock(manager(), args);
                case "clear" -> System.out.println(manager().resetSelective(true, false, false) ? "ok" : "noop");
                case "add" -> handleAdd(manager(), args);
                case "remove" -> handleRemove(manager(), args);
                case "export" -> handleExport(manager(), args);
                case "import" -> handleImport(manager(), args);
                case "reset" -> handleReset(manager(), args);
                case "geo" -> handleGeo(manager(), args);
                case "exempt-path", "path-exemptions" -> handleExemptPath(manager(), args);
                case "whois" -> handleWhois(args);
                case "generate-manifest", "init" -> handleGenerateManifest(args);
                case "train", "train-model" -> handleCoreCommand("train-model", args);
                case "replay" -> handleCoreCommand("replay", args);
                case "model" -> handleModel(args);
                case "logs" -> handleLogs(args);
                default -> printUsage();
            }
        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            System.exit(1);
        }
    }

    private static AiwafManager manager() {
        return new AiwafManager();
    }

    private static void handleList(AiwafManager manager, String[] args) {
        String target = args.length > 1 ? args[1].toLowerCase(Locale.ROOT) : "all";
        switch (target) {
            case "allowlist" -> System.out.println(manager.listAllowlistIps());
            case "blocklist" -> System.out.println(manager.listBlocklistIps());
            case "keywords" -> System.out.println(manager.listKeywords(100));
            case "geo" -> System.out.println(manager.listGeoBlockedCountries());
            case "exempt-path", "path-exemptions" -> System.out.println(manager.listPathExemptions());
            case "all" -> {
                System.out.println("allowlist=" + manager.listAllowlistIps());
                System.out.println("blocklist=" + manager.listBlocklistIps());
                System.out.println("keywords=" + manager.listKeywords(100));
                System.out.println("geo=" + manager.listGeoBlockedCountries());
                System.out.println("path_exemptions=" + manager.listPathExemptions());
            }
            default -> printUsage();
        }
    }

    private static void handleAdd(AiwafManager manager, String[] args) {
        if (args.length < 3) {
            printUsage();
            return;
        }
        String target = args[1].toLowerCase(Locale.ROOT);
        String value = args[2];
        String reason = parseOption(args, "--reason");
        boolean result = switch (target) {
            case "allowlist" -> manager.addAllowlistIp(value, reason);
            case "blocklist" -> manager.addBlocklistIp(value, reason);
            case "keyword" -> manager.addKeyword(value);
            case "geo" -> manager.addGeoBlockedCountry(value);
            case "exempt-path", "path-exemptions" -> manager.addPathExemption(value, reason);
            default -> false;
        };
        System.out.println(result ? "ok" : "noop");
    }

    private static void handleRemove(AiwafManager manager, String[] args) {
        if (args.length < 3) {
            printUsage();
            return;
        }
        String target = args[1].toLowerCase(Locale.ROOT);
        String value = args[2];
        boolean result = switch (target) {
            case "allowlist" -> manager.removeAllowlistIp(value);
            case "blocklist" -> manager.removeBlocklistIp(value);
            case "keyword" -> manager.removeKeyword(value);
            case "geo" -> manager.removeGeoBlockedCountry(value);
            case "exempt-path", "path-exemptions" -> manager.removePathExemption(value);
            default -> false;
        };
        System.out.println(result ? "ok" : "noop");
    }

    private static String parseOption(String[] args, String option) {
        for (int i = 0; i < args.length; i++) {
            if (option.equals(args[i]) && i + 1 < args.length) {
                return args[i + 1];
            }
        }
        return null;
    }

    private static void printUsage() {
        List<String> lines = List.of(
                "Usage:",
                "  aiwaf-cli stats",
                "  aiwaf-cli diagnose [--model <model.json>]",
                "  aiwaf-cli blocked | unblock <ip> | clear",
                "  aiwaf-cli list [all|allowlist|blocklist|keywords|geo|exempt-path]",
                "  aiwaf-cli add <allowlist|blocklist|keyword|geo|exempt-path> <value> [--reason <text>]",
                "  aiwaf-cli remove <allowlist|blocklist|keyword|geo|exempt-path> <value>",
                "  aiwaf-cli export <file>",
                "  aiwaf-cli import <file>",
                "  aiwaf-cli reset [--blocklist|--exemptions|--keywords|--blocklist-only|--exemptions-only]",
                "  aiwaf-cli geo <list|add|remove> [country]",
                "  aiwaf-cli exempt-path <list|add|remove> [path] [--reason text]",
                "  aiwaf-cli whois <target>",
                "  aiwaf-cli train --events <events.json> --out <model.json> [--backend java|fastr]",
                "  aiwaf-cli replay --cases <cases.json>",
                "  aiwaf-cli model status [--path <model.json>]",
                "  aiwaf-cli logs [--dir aiwaf_logs]",
                "  aiwaf-cli init --app <SpringApplicationClass> [--output .aiwaf/paths.json]",
                "  aiwaf-cli generate-manifest [output.json] --class <ControllerClassName>"
        );
        for (String line : lines) {
            System.out.println(line);
        }
    }

    private static void handleGeo(AiwafManager manager, String[] args) {
        if (args.length < 2) {
            printUsage();
            return;
        }
        String action = args[1].toLowerCase(Locale.ROOT);
        switch (action) {
            case "list" -> System.out.println(manager.listGeoBlockedCountries());
            case "add" -> System.out.println((args.length > 2 && manager.addGeoBlockedCountry(args[2])) ? "ok" : "noop");
            case "remove" -> System.out.println((args.length > 2 && manager.removeGeoBlockedCountry(args[2])) ? "ok" : "noop");
            default -> printUsage();
        }
    }

    private static void handleExemptPath(AiwafManager manager, String[] args) {
        if (args.length < 2) {
            printUsage();
            return;
        }
        String action = args[1].toLowerCase(Locale.ROOT);
        String reason = parseOption(args, "--reason");
        switch (action) {
            case "list" -> System.out.println(manager.listPathExemptions());
            case "add" -> System.out.println((args.length > 2 && manager.addPathExemption(args[2], reason)) ? "ok" : "noop");
            case "remove" -> System.out.println((args.length > 2 && manager.removePathExemption(args[2])) ? "ok" : "noop");
            default -> printUsage();
        }
    }

    private static void handleWhois(String[] args) {
        if (args.length < 2) {
            printUsage();
            return;
        }
        String target = args[1];
        try {
            Map<String, String> result = WhoisLookup.runWhoisLookup(target);
            System.out.println("WHOIS result: " + result);
        } catch (IOException ex) {
            System.out.println("python-whois is not installed or whois command unavailable");
        }
    }

    private static void handleUnblock(AiwafManager manager, String[] args) {
        System.out.println(args.length > 1 && manager.removeBlocklistIp(args[1]) ? "ok" : "noop");
    }

    private static void handleCoreCommand(String command, String[] args) {
        String[] delegated = new String[args.length];
        delegated[0] = command;
        if (args.length > 1) System.arraycopy(args, 1, delegated, 1, args.length - 1);
        int status = CoreCli.main(delegated);
        System.out.println(status == 0 ? "ok" : "error (exit " + status + ")");
    }

    private static void handleDiagnose(AiwafManager manager, String[] args) {
        String modelPath = parseOption(args, "--model");
        if (modelPath == null) modelPath = "model.json";
        Package pkg = AiwafConsole.class.getPackage();
        String version = pkg == null || pkg.getImplementationVersion() == null
                ? "development" : pkg.getImplementationVersion();
        System.out.println("AIWAF Java diagnostics");
        System.out.println("version=" + version);
        System.out.println("java=" + System.getProperty("java.runtime.version", "unknown"));
        System.out.println("storage=" + manager.stats());
        System.out.println("model_path=" + Path.of(modelPath).toAbsolutePath().normalize());
        System.out.println("model=" + (ModelArtifactIoCore.load(modelPath) == null ? "unavailable" : "ready"));
    }

    private static void handleModel(String[] args) {
        String action = args.length > 1 ? args[1].toLowerCase(Locale.ROOT) : "status";
        if (!"status".equals(action)) {
            printUsage();
            return;
        }
        String path = parseOption(args, "--path");
        if (path == null) path = "model.json";
        TrainedModelCore model = ModelArtifactIoCore.load(path);
        if (model == null) {
            System.out.println("model=unavailable path=" + Path.of(path).toAbsolutePath().normalize());
            return;
        }
        System.out.println("model=ready type=" + model.modelType() + " version=" + model.version());
    }

    private static void handleLogs(String[] args) throws IOException {
        String configured = parseOption(args, "--dir");
        Path directory = Path.of(configured == null ? "aiwaf_logs" : configured);
        if (!Files.isDirectory(directory)) {
            System.out.println("logs=unavailable dir=" + directory.toAbsolutePath().normalize());
            return;
        }
        try (var files = Files.list(directory)) {
            files.filter(Files::isRegularFile)
                    .sorted((left, right) -> Long.compare(lastModified(right), lastModified(left)))
                    .forEach(path -> System.out.println(path + " bytes=" + size(path)));
        }
    }

    private static long lastModified(Path path) {
        try { return Files.getLastModifiedTime(path).toMillis(); } catch (IOException ignored) { return 0L; }
    }

    private static long size(Path path) {
        try { return Files.size(path); } catch (IOException ignored) { return 0L; }
    }

    private static void handleGenerateManifest(String[] args) {
        String outputOption = parseOption(args, "--output");
        String output = outputOption != null
                ? outputOption
                : (args.length > 1 && !args[1].startsWith("--")
                        ? args[1] : com.aiwaf.core.PathManifestCore.DEFAULT_MANIFEST_PATH);
        String appName = parseOption(args, "--app");
        if (appName != null) {
            Map<String, Object> manifest = com.aiwaf.spring.SpringPathManifest.launchAndGenerate(appName, output);
            printManifestSummary(output, manifest);
            return;
        }
        String clsName = parseOption(args, "--class");
        if (clsName == null) {
            System.out.println("Usage: aiwaf-cli init --app <SpringApplicationClass> [--output .aiwaf/paths.json]");
            return;
        }
        try {
            Class<?> cls = Class.forName(clsName);
            List<com.aiwaf.core.PathManifestCore.RouteInfo> routes =
                    com.aiwaf.core.PathManifestCore.discoverControllerRoutes(cls);
            com.aiwaf.core.PathManifestCore.generateManifest(routes, output);
            printManifestSummary(output, com.aiwaf.core.PathManifestCore.buildManifest("spring", routes));
        } catch (Exception e) {
            System.err.println("Error generating manifest: " + e.getMessage());
        }
    }

    private static void printManifestSummary(String output, Map<String, Object> manifest) {
        Object routes = manifest.get("routes");
        int count = routes instanceof Map<?, ?> map ? map.size() : 0;
        System.out.println("Generated " + output);
        System.out.println("Framework: " + manifest.getOrDefault("framework", "spring"));
        System.out.println("Routes: " + count);
        System.out.println("Context hash: " + manifest.getOrDefault("context_hash", ""));
    }

    private static void handleExport(AiwafManager manager, String[] args) {
        if (args.length < 2) {
            printUsage();
            return;
        }
        System.out.println(manager.exportConfig(args[1]) ? "ok" : "noop");
    }

    private static void handleImport(AiwafManager manager, String[] args) {
        if (args.length < 2) {
            printUsage();
            return;
        }
        System.out.println(manager.importConfig(args[1]) ? "ok" : "noop");
    }

    private static void handleReset(AiwafManager manager, String[] args) {
        boolean blocklistOnly = hasArg(args, "--blocklist-only");
        boolean exemptionsOnly = hasArg(args, "--exemptions-only");
        if (blocklistOnly) {
            System.out.println(manager.resetSelective(true, false, false) ? "ok" : "noop");
            return;
        }
        if (exemptionsOnly) {
            System.out.println(manager.resetSelective(false, true, false) ? "ok" : "noop");
            return;
        }

        boolean blocklist = hasArg(args, "--blocklist");
        boolean exemptions = hasArg(args, "--exemptions");
        boolean keywords = hasArg(args, "--keywords");
        if (blocklist || exemptions || keywords) {
            System.out.println(manager.resetSelective(blocklist, exemptions, keywords) ? "ok" : "noop");
            return;
        }
        System.out.println(manager.resetAll() ? "ok" : "noop");
    }

    private static boolean hasArg(String[] args, String value) {
        for (String arg : args) {
            if (value.equals(arg)) {
                return true;
            }
        }
        return false;
    }
}
