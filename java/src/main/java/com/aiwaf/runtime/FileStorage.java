package com.aiwaf.runtime;

import com.aiwaf.core.SafeObjectInputStreams;
import com.aiwaf.core.SecureFiles;

import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class FileStorage implements StorageBackend {
    private static final class Entry implements java.io.Serializable {
        Object value;
        Long expiresAtMillis;
    }

    private final Path filePath;
    private final Map<String, Entry> data = new ConcurrentHashMap<>();

    public FileStorage(String filePath) {
        this.filePath = Path.of(filePath).toAbsolutePath().normalize();
        StorageFileLock.withLock(this.filePath, () -> { load(); return null; });
    }

    private synchronized void load() {
        data.clear();
        try {
            if (!Files.exists(filePath)) return;
            SecureFiles.rejectSymbolicLinks(filePath);
            if (!SecureFiles.verifySignature(filePath)) {
                throw new IllegalStateException("Unable to verify file storage signature");
            }
            try (var in = SafeObjectInputStreams.open(
                    new FileInputStream(filePath.toFile()), SafeObjectInputStreams.Profile.STORAGE)) {
                Object obj = in.readObject();
                if (obj instanceof Map<?, ?> map) {
                    data.clear();
                    for (Map.Entry<?, ?> e : map.entrySet()) {
                        if (e.getKey() instanceof String key && e.getValue() instanceof Entry entry) {
                            data.put(key, entry);
                        }
                    }
                } else {
                    throw new IllegalStateException("Invalid file storage payload");
                }
            }
        } catch (Exception ex) {
            data.clear();
            throw new IllegalStateException("Unable to load file storage", ex);
        }
    }

    private synchronized void save() {
        try {
            SecureFiles.writeAtomically(filePath, output -> {
                try (ObjectOutputStream out = new ObjectOutputStream(output)) {
                    out.writeObject(new java.util.HashMap<>(data));
                }
            });
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to persist file storage", ex);
        }
    }

    private void cleanupExpired() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, Entry> e : data.entrySet()) {
            Long expires = e.getValue().expiresAtMillis;
            if (expires != null && now >= expires) {
                data.remove(e.getKey());
            }
        }
    }

    @Override
    public synchronized Object get(String key) {
        return StorageFileLock.withLock(filePath, () -> {
            load();
            cleanupExpired();
            Entry entry = data.get(key);
            if (entry == null) return null;
            return entry.value;
        });
    }

    @Override
    public synchronized boolean set(String key, Object value, Integer ttlSeconds) {
        return StorageFileLock.withLock(filePath, () -> {
            load();
            cleanupExpired();
            Entry entry = new Entry();
            entry.value = value;
            entry.expiresAtMillis = ttlSeconds == null ? null : System.currentTimeMillis() + (ttlSeconds * 1000L);
            data.put(key, entry);
            save();
            return true;
        });
    }

    @Override
    public synchronized boolean delete(String key) {
        return StorageFileLock.withLock(filePath, () -> {
            load();
            boolean removed = data.remove(key) != null;
            if (removed) save();
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
            load();
            cleanupExpired();
            List<String> keys = new ArrayList<>();
            String pattern = globPattern == null || globPattern.isBlank() ? "*" : globPattern;
            String regex = pattern.replace(".", "\\.").replace("*", ".*");
            for (String key : data.keySet()) {
                if (key.matches(regex)) {
                    keys.add(key);
                }
            }
            return keys;
        });
    }
}
