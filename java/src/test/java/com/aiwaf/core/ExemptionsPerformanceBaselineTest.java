
package com.aiwaf.core;

import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;

public class ExemptionsPerformanceBaselineTest {

    @Test
    void measurePathRuleMatching() {
        List<AiwafConfig.PathRule> rules = new ArrayList<>();

        for (int i = 0; i < 500; i++) {
            rules.add(new AiwafConfig.PathRule(
                    "/api/service" + i,
                    false,
                    null
            ));
        }

        String path = "/api/service499/users/123";

        // JVM warmup
        for (int i = 0; i < 20_000; i++) {
            ExemptionsCore.getPathRuleForPath(path, rules);
        }

        int iterations = 100_000;
        long start = System.nanoTime();

        AiwafConfig.PathRule result = null;

        for (int i = 0; i < iterations; i++) {
            result = ExemptionsCore.getPathRuleForPath(path, rules);
        }

        long elapsed = System.nanoTime() - start;

        if (result == null) {
            throw new AssertionError("Expected matching path rule");
        }

        System.out.printf(
                "Average path rule lookup: %.2f ns%n",
                (double) elapsed / iterations
        );
    }
}

