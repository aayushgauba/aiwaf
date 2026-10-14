package com.aiwaf.runtime;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BlocklistManager {
    protected BlocklistManager() {}

    public static boolean block(String ip, String reason, Integer durationSeconds) {
        if (RuntimeStorage.getExemptionStore().isExempted(ip)) {
            return false;
        }
        RuntimeStorage.getBlocklistStore().blockIp(ip, reason, durationSeconds);
        return true;
    }

    public static boolean block(String ip, String reason, Integer durationSeconds, Map<String, Object> extendedRequestInfo) {
        return block(RuntimeStorage.getContext(), ip, reason, durationSeconds, extendedRequestInfo);
    }

    public static boolean block(
            RuntimeStorage.Context context,
            String ip,
            String reason,
            Integer durationSeconds,
            Map<String, Object> extendedRequestInfo
    ) {
        if (context.exemptionStore().isExempted(ip)) {
            return false;
        }
        context.blocklistStore().blockIp(ip, reason, durationSeconds, extendedRequestInfo);
        return true;
    }

    public static boolean block(String ip, String reason) {
        return block(ip, reason, null);
    }

    public static boolean blockTemporary(String ip, String reason, int minutes) {
        return block(ip, "Temporary: " + reason, Math.max(1, minutes) * 60);
    }

    public static boolean blockPermanent(String ip, String reason) {
        return block(ip, "Permanent: " + reason, 0);
    }

    public static boolean unblock(String ip) {
        return RuntimeStorage.getBlocklistStore().unblockIp(ip);
    }

    public static boolean isBlocked(String ip) {
        return isBlocked(RuntimeStorage.getContext(), ip);
    }

    public static boolean isBlocked(RuntimeStorage.Context context, String ip) {
        if (context.exemptionStore().isExempted(ip)) return false;
        return context.blocklistStore().isBlocked(ip);
    }

    public static Map<String, Object> getBlockInfo(String ip) {
        return RuntimeStorage.getBlocklistStore().getBlockInfo(ip);
    }

    public static List<String> getBlockedIps() {
        return RuntimeStorage.getBlocklistStore().getBlockedIps();
    }

    public static Map<String, Object> getStatistics() {
        return RuntimeStorage.getBlocklistStore().getBlockStats();
    }

    public static int cleanupExpired() {
        int cleaned = 0;
        double now = System.currentTimeMillis() / 1000.0;
        for (String ip : getBlockedIps()) {
            Map<String, Object> info = getBlockInfo(ip);
            if (info == null) continue;
            Object perm = info.get("permanent");
            if (perm instanceof Boolean b && b) continue;
            double blockedAt = info.get("blocked_at") instanceof Number n ? n.doubleValue() : 0;
            Integer duration = info.get("duration") instanceof Number n ? n.intValue() : null;
            if (duration != null && now - blockedAt > duration) {
                if (unblock(ip)) cleaned++;
            }
        }
        return cleaned;
    }

    public static void addToAllowlist(String ip, String reason) {
        RuntimeStorage.getExemptionStore().addIp(ip, reason);
        if (RuntimeStorage.getBlocklistStore().isBlocked(ip)) {
            RuntimeStorage.getBlocklistStore().unblockIp(ip);
        }
    }

    public static boolean removeFromAllowlist(String ip) {
        return RuntimeStorage.getExemptionStore().removeIp(ip);
    }

    public static boolean isAllowlisted(String ip) {
        return RuntimeStorage.getExemptionStore().isExempted(ip);
    }

    public static Map<String, Object> getAllowlist() {
        Map<String, Object> out = new HashMap<>();
        out.put("ips", RuntimeStorage.getExemptionStore().getExemptedIps());
        out.put("patterns", RuntimeStorage.getExemptionStore().getExemptedPatterns());
        return out;
    }

    public static List<Map<String, Object>> getRecentBlocks(int hours) {
        List<Map<String, Object>> log = coerceBlockLog(RuntimeStorage.getStorage().get("block_log"));
        double cutoff = (System.currentTimeMillis() / 1000.0) - (hours * 3600.0);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> row : log) {
            double ts = row.get("blocked_at") instanceof Number n ? n.doubleValue() : 0;
            if (ts >= cutoff) out.add(row);
        }
        out.sort(Comparator.comparingDouble((Map<String, Object> m) ->
                m.get("blocked_at") instanceof Number n ? n.doubleValue() : 0).reversed());
        return out;
    }

    public static List<Map<String, Object>> getTopBlockedReasons(int limit) {
        Map<String, Object> stats = getStatistics();
        Map<String, Integer> reasonCounts = coerceReasonCounts(stats.get("reason_counts"));
        List<Map.Entry<String, Integer>> entries = new ArrayList<>(reasonCounts.entrySet());
        entries.sort(Comparator.comparingInt((Map.Entry<String, Integer> e) -> e.getValue()).reversed());
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map.Entry<String, Integer> e : entries) {
            Map<String, Object> row = new HashMap<>();
            row.put("reason", e.getKey());
            row.put("count", e.getValue());
            out.add(row);
            if (out.size() >= limit) break;
        }
        return out;
    }

    private static List<Map<String, Object>> coerceBlockLog(Object value) {
        if (!(value instanceof List<?> rows)) {
            return new ArrayList<>();
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object row : rows) {
            if (row instanceof Map<?, ?> raw) {
                Map<String, Object> typed = new HashMap<>();
                for (Map.Entry<?, ?> e : raw.entrySet()) {
                    if (e.getKey() != null) {
                        typed.put(String.valueOf(e.getKey()), e.getValue());
                    }
                }
                out.add(typed);
            }
        }
        return out;
    }

    private static Map<String, Integer> coerceReasonCounts(Object value) {
        Map<String, Integer> out = new HashMap<>();
        if (!(value instanceof Map<?, ?> raw)) {
            return out;
        }
        for (Map.Entry<?, ?> e : raw.entrySet()) {
            if (e.getKey() == null) {
                continue;
            }
            Integer count = null;
            if (e.getValue() instanceof Number n) {
                count = n.intValue();
            } else if (e.getValue() != null) {
                try {
                    count = Integer.parseInt(String.valueOf(e.getValue()));
                } catch (NumberFormatException ignored) {
                    count = null;
                }
            }
            if (count != null) {
                out.put(String.valueOf(e.getKey()), count);
            }
        }
        return out;
    }

    // Compatibility aliases for the previous API names.
    @Deprecated
    public static void addToWhitelist(String ip, String reason) { addToAllowlist(ip, reason); }
    @Deprecated
    public static boolean removeFromWhitelist(String ip) { return removeFromAllowlist(ip); }
    @Deprecated
    public static boolean isWhitelisted(String ip) { return isAllowlisted(ip); }
    @Deprecated
    public static Map<String, Object> getWhitelist() { return getAllowlist(); }
}
