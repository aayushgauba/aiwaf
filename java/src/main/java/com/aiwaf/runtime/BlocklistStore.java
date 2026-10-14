package com.aiwaf.runtime;

import com.aiwaf.core.ReputationCore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BlocklistStore {
    private final StorageBackend storage;

    public BlocklistStore(StorageBackend storage) {
        this.storage = storage;
    }

    public synchronized void blockIp(String ip, String reason, Integer durationSeconds) {
        blockIp(ip, reason, durationSeconds, null);
    }

    public synchronized void blockIp(
            String ip,
            String reason,
            Integer durationSeconds,
            Map<String, Object> extendedRequestInfo
    ) {
        double now = System.currentTimeMillis() / 1000.0;
        Map<String, Object> existing = getBlockInfo(ip);
        ReputationCore.Decision reputation = ReputationCore.evaluate(existing, reason, now);
        Integer effectiveDuration;
        if (durationSeconds == null) {
            effectiveDuration = reputation.durationSeconds() == null
                    ? ReputationCore.FIRST_BLOCK_SECONDS : reputation.durationSeconds();
        } else if (durationSeconds <= 0) {
            effectiveDuration = null;
        } else {
            effectiveDuration = durationSeconds;
        }
        Map<String, Object> block = new HashMap<>();
        block.put("ip", ip);
        block.put("reason", reason);
        block.put("reputation_reason", ReputationCore.formatBlockReason(reputation));
        block.put("reasons", reputation.reasons());
        block.put("score", reputation.score());
        block.put("offenses", reputation.offenses());
        block.put("blocked_at", now);
        block.put("added_date", now);
        block.put("duration", effectiveDuration);
        block.put("expires_at", effectiveDuration == null ? null : now + effectiveDuration);
        block.put("permanent", effectiveDuration == null);
        if (extendedRequestInfo != null && !extendedRequestInfo.isEmpty()) {
            block.put("extended_request_info", new HashMap<>(extendedRequestInfo));
        }
        storage.set("blocked:" + ip, block, effectiveDuration);

        List<Map<String, Object>> log = readBlockLog();
        log.add(block);
        if (log.size() > 1000) {
            log = new ArrayList<>(log.subList(log.size() - 1000, log.size()));
        }
        storage.set("block_log", log, null);
    }

    public synchronized boolean unblockIp(String ip) {
        return storage.delete("blocked:" + ip);
    }

    public synchronized boolean isBlocked(String ip) {
        return storage.exists("blocked:" + ip);
    }

    public synchronized Map<String, Object> getBlockInfo(String ip) {
        return coerceStringObjectMap(storage.get("blocked:" + ip));
    }

    public synchronized List<String> getBlockedIps() {
        List<String> keys = storage.getAllKeys("blocked:*");
        List<String> out = new ArrayList<>();
        for (String key : keys) out.add(key.replace("blocked:", ""));
        return out;
    }

    public synchronized Map<String, Object> getBlockStats() {
        List<String> blocked = getBlockedIps();
        List<Map<String, Object>> log = readBlockLog();
        Map<String, Integer> reasonCounts = new HashMap<>();
        int recent = 0;
        double now = System.currentTimeMillis() / 1000.0;
        for (Map<String, Object> row : log) {
            String reason = String.valueOf(row.getOrDefault("reason", "unknown"));
            reasonCounts.put(reason, reasonCounts.getOrDefault(reason, 0) + 1);
            Object ts = row.get("blocked_at");
            double blockedAt = ts instanceof Number ? ((Number) ts).doubleValue() : 0;
            if (now - blockedAt < 86400) recent++;
        }
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_blocked", blocked.size());
        stats.put("total_blocks_all_time", log.size());
        stats.put("recent_blocks_24h", recent);
        stats.put("reason_counts", reasonCounts);
        stats.put("blocked_ips", blocked.size() > 100 ? blocked.subList(0, 100) : blocked);
        return stats;
    }

    private List<Map<String, Object>> readBlockLog() {
        Object existing = storage.get("block_log");
        if (!(existing instanceof List<?> values)) {
            return new ArrayList<>();
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object value : values) {
            Map<String, Object> row = coerceStringObjectMap(value);
            if (row != null) {
                out.add(row);
            }
        }
        return out;
    }

    private Map<String, Object> coerceStringObjectMap(Object value) {
        if (!(value instanceof Map<?, ?> raw)) {
            return null;
        }
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<?, ?> e : raw.entrySet()) {
            if (e.getKey() != null) {
                out.put(String.valueOf(e.getKey()), e.getValue());
            }
        }
        return out;
    }
}
