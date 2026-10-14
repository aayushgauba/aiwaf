package com.aiwaf.runtime;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.AtomicMoveNotSupportedException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CSV-backed key/value storage with TTL support.
 *
 * Parity target: Python runtime_storage.CSVStorage.
 * File schema: key,value,expires_at
 */
public final class CsvStorage implements StorageBackend {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String HEADER = "key,value,expires_at";

    private static final class Entry {
        Object value;
        Double expiresAtEpochSeconds;
    }

    private final Path filePath;
    private final Map<String, Entry> data = new HashMap<>();

    public CsvStorage(String filePath) {
        this.filePath = Path.of(filePath).toAbsolutePath().normalize();
        StorageFileLock.withLock(this.filePath, () -> { loadData(); return null; });
    }

    private synchronized void loadData() {
        data.clear();
        if (!Files.exists(filePath)) {
            return;
        }
        try (BufferedReader reader = Files.newBufferedReader(filePath, StandardCharsets.UTF_8)) {
            String header = reader.readLine();
            if (header == null) {
                return;
            }
            String line;
            while ((line = reader.readLine()) != null) {
                List<String> row = parseCsvLine(line);
                if (row.size() < 3) {
                    continue;
                }
                String key = row.get(0);
                if (key == null || key.isBlank()) {
                    continue;
                }
                String rawValue = row.get(1) == null ? "" : row.get(1);
                String rawExpires = row.get(2) == null ? "" : row.get(2).trim();

                Object value = deserializeValue(rawValue);
                Double expiresAt = null;
                if (!rawExpires.isBlank()) {
                    try {
                        expiresAt = Double.parseDouble(rawExpires);
                    } catch (NumberFormatException ignored) {
                        expiresAt = null;
                    }
                }

                Entry entry = new Entry();
                entry.value = value;
                entry.expiresAtEpochSeconds = expiresAt;
                data.put(key, entry);
            }
        } catch (IOException ex) {
            data.clear();
            throw new IllegalStateException("Unable to load CSV storage", ex);
        }
    }

    private synchronized void saveData() {
        try {
            if (filePath.getParent() != null) {
                Files.createDirectories(filePath.getParent());
            }
            Path temp = filePath.resolveSibling(filePath.getFileName() + ".tmp");
            try (BufferedWriter writer = Files.newBufferedWriter(temp, StandardCharsets.UTF_8)) {
                writer.write(HEADER);
                writer.newLine();
                for (Map.Entry<String, Entry> e : data.entrySet()) {
                    String key = e.getKey();
                    Entry entry = e.getValue();
                    String value = serializeValue(entry.value);
                    String expiresAt = entry.expiresAtEpochSeconds == null ? "" : String.valueOf(entry.expiresAtEpochSeconds);
                    writer.write(csvCell(key));
                    writer.write(',');
                    writer.write(csvCell(value));
                    writer.write(',');
                    writer.write(csvCell(expiresAt));
                    writer.newLine();
                }
            }
            try {
                Files.move(temp, filePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(temp, filePath, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to persist CSV storage", ex);
        }
    }

    private void cleanupExpired() {
        double nowSeconds = System.currentTimeMillis() / 1000.0;
        List<String> expiredKeys = new ArrayList<>();
        for (Map.Entry<String, Entry> e : data.entrySet()) {
            Double expiresAt = e.getValue().expiresAtEpochSeconds;
            if (expiresAt != null && nowSeconds >= expiresAt) {
                expiredKeys.add(e.getKey());
            }
        }
        if (!expiredKeys.isEmpty()) {
            for (String key : expiredKeys) {
                data.remove(key);
            }
        }
    }

    @Override
    public synchronized Object get(String key) {
        return StorageFileLock.withLock(filePath, () -> {
            loadData();
            cleanupExpired();
            Entry entry = data.get(key);
            return entry == null ? null : entry.value;
        });
    }

    @Override
    public synchronized boolean set(String key, Object value, Integer ttlSeconds) {
        return StorageFileLock.withLock(filePath, () -> {
            loadData();
            cleanupExpired();
            Entry entry = new Entry();
            entry.value = value;
            entry.expiresAtEpochSeconds = ttlSeconds == null ? null : (System.currentTimeMillis() / 1000.0) + ttlSeconds;
            data.put(key, entry);
            saveData();
            return true;
        });
    }

    @Override
    public synchronized boolean delete(String key) {
        return StorageFileLock.withLock(filePath, () -> {
            loadData();
            boolean removed = data.remove(key) != null;
            if (removed) {
                saveData();
            }
            return removed;
        });
    }

    @Override
    public synchronized boolean exists(String key) {
        return get(key) != null;
    }

    @Override
    public synchronized List<String> getAllKeys(String globPattern) {
        return StorageFileLock.withLock(filePath, () -> {
            loadData();
            cleanupExpired();
            String pattern = (globPattern == null || globPattern.isBlank()) ? "*" : globPattern;
            String regex = pattern.replace(".", "\\.").replace("*", ".*");
            List<String> keys = new ArrayList<>();
            for (String key : data.keySet()) {
                if (key.matches(regex)) {
                    keys.add(key);
                }
            }
            return keys;
        });
    }

    private Object deserializeValue(String rawValue) {
        try {
            return MAPPER.readValue(rawValue, Object.class);
        } catch (Exception ignored) {
            return rawValue;
        }
    }

    private String serializeValue(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException ignored) {
            return value == null ? "null" : String.valueOf(value);
        }
    }

    private static String csvCell(String value) {
        String text = value == null ? "" : value;
        if (text.contains(",") || text.contains("\"") || text.contains("\n") || text.contains("\r")) {
            return "\"" + text.replace("\"", "\"\"") + "\"";
        }
        return text;
    }

    private static List<String> parseCsvLine(String line) {
        List<String> out = new ArrayList<>();
        if (line == null) {
            return out;
        }
        StringBuilder cell = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    cell.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
                continue;
            }
            if (c == ',' && !inQuotes) {
                out.add(cell.toString());
                cell.setLength(0);
                continue;
            }
            cell.append(c);
        }
        out.add(cell.toString());
        return out;
    }
}
