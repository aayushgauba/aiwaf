package com.aiwaf.core;

import com.aiwaf.runtime.RuntimeStorage;
import org.junit.jupiter.api.Test;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class TrainingBlocklistIsolationTest {
    @Test
    void retraining_does_not_extend_or_recreate_runtime_blocks() {
        RuntimeStorage.Context previous = RuntimeStorage.getContext();
        try {
            RuntimeStorage.initialize("memory", null);
            var blocklist = RuntimeStorage.getBlocklistStore();
            String ip = "203.0.113.1";
            List<NormalizedEvent> events = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                events.add(new NormalizedEvent(ip, "GET", "/wp-admin/shell.php", 404, 10,
                        LocalDateTime.of(2026, 10, 10, 0, 0).plusSeconds(i),
                        "", "", "", false, false));
            }
            blocklist.blockIp(ip, "scanner", 900);
            var before = blocklist.getBlockInfo(ip);
            TrainingCore.trainModel(events, List.of(".php", "wp-"));
            TrainingCore.trainModel(events, List.of(".php", "wp-"));
            assertEquals(before, blocklist.getBlockInfo(ip));
            blocklist.unblockIp(ip);
            TrainingCore.trainModel(events, List.of(".php", "wp-"));
            assertFalse(blocklist.isBlocked(ip));
        } finally {
            RuntimeStorage.installDefault(previous);
        }
    }
}
