package com.aiwaf.core;

import com.aiwaf.runtime.RuntimeStorage;
import org.junit.jupiter.api.Test;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class TrainingBlacklistIsolationTest {
    @Test
    void retraining_does_not_extend_or_recreate_runtime_blocks() {
        RuntimeStorage.Context previous = RuntimeStorage.getContext();
        try {
            RuntimeStorage.initialize("memory", null);
            var blacklist = RuntimeStorage.getBlacklistStore();
            String ip = "203.0.113.1";
            List<NormalizedEvent> events = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                events.add(new NormalizedEvent(ip, "GET", "/wp-admin/shell.php", 404, 10,
                        LocalDateTime.of(2026, 10, 10, 0, 0).plusSeconds(i),
                        "", "", "", false, false));
            }
            blacklist.blockIp(ip, "scanner", 900);
            var before = blacklist.getBlockInfo(ip);
            TrainingCore.trainModel(events, List.of(".php", "wp-"));
            TrainingCore.trainModel(events, List.of(".php", "wp-"));
            assertEquals(before, blacklist.getBlockInfo(ip));
            blacklist.unblockIp(ip);
            TrainingCore.trainModel(events, List.of(".php", "wp-"));
            assertFalse(blacklist.isBlocked(ip));
        } finally {
            RuntimeStorage.installDefault(previous);
        }
    }
}
