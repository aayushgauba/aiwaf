package com.aiwaf.runtime;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ListTerminologyCompatibilityTest {
    @Test
    void previousAccessorsAndManagerUseTheSameState() {
        RuntimeStorage.Context context = RuntimeStorage.create("memory", null, null, null);
        assertSame(context.blocklistStore(), context.blacklistStore());
        context.blacklistStore().blockIp("8.8.8.8", "existing block", 900);
        assertTrue(context.blocklistStore().isBlocked("8.8.8.8"));
    }
}
