package com.aiwaf.runtime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class StorageExpiryConcurrencyTest {
    @TempDir Path dir;

    private static StorageBackend storage(String type, String file) {
        return type.equals("csv") ? new CsvStorage(file) : new FileStorage(file);
    }

    @Test void staleInstancesPreserveRefreshedAndUnrelatedBlocks() throws Exception {
        for (String type : new String[]{"csv", "file"}) {
            String file = dir.resolve(type).toString();
            StorageBackend older = storage(type, file);
            older.set("blocked:expired", "expired", -1);
            StorageBackend writer = storage(type, file);
            writer.set("blocked:expired", "refreshed", 900);
            writer.set("blocked:new", "new", 900);
            byte[] beforeListing = Files.readAllBytes(Path.of(file));
            assertEquals(2, older.getAllKeys("blocked:*").size());
            assertArrayEquals(beforeListing, Files.readAllBytes(Path.of(file)));
            assertEquals("refreshed", older.get("blocked:expired"));
            older.set("unrelated", "value", null);
            assertTrue(writer.exists("blocked:new"));
            assertEquals("refreshed", storage(type, file).get("blocked:expired"));
            older.delete("unrelated");
            assertTrue(storage(type, file).exists("blocked:new"));
        }
    }

    @Test void expiredReadsDoNotRewriteFiles() throws Exception {
        for (String type : new String[]{"csv", "file"}) {
            String file = dir.resolve(type).toString();
            StorageBackend store = storage(type, file);
            store.set("blocked:expired", "expired", -1);
            store.set("blocked:active", "active", 900);
            // Add the expired row last: writes may prune already expired rows.
            store.set("blocked:expired", "expired", -1);
            byte[] before = Files.readAllBytes(Path.of(file));
            assertNull(store.get("blocked:expired"));
            assertEquals(1, store.getAllKeys("blocked:*").size());
            assertArrayEquals(before, Files.readAllBytes(Path.of(file)));
        }
    }

    @Test void concurrentInstancesKeepEveryWrite() throws Exception {
        for (String type : new String[]{"csv", "file"}) {
            String file = dir.resolve(type).toString();
            var pool = Executors.newFixedThreadPool(4);
            try {
                var tasks = new ArrayList<java.util.concurrent.Future<?>>();
                for (int worker = 0; worker < 4; worker++) {
                    int id = worker;
                    tasks.add(pool.submit(() -> {
                        StorageBackend store = storage(type, file);
                        for (int i = 0; i < 10; i++) store.set("blocked:" + id + ":" + i, "value", 900);
                    }));
                }
                for (var task : tasks) task.get(30, TimeUnit.SECONDS);
                assertEquals(40, storage(type, file).getAllKeys("blocked:*").size());
            } finally { pool.shutdownNow(); }
        }
    }

    public static class Writer {
        public static void main(String[] args) {
            StorageBackend store = storage(args[0], args[1]);
            for (int i = 0; i < 10; i++) store.set("blocked:" + args[2] + ":" + i, "value", 900);
        }
    }

    @Test void separateProcessesKeepEveryWrite() throws Exception {
        for (String type : new String[]{"csv", "file"}) {
            String file = dir.resolve(type).toString();
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
            var first = new ProcessBuilder(java, "-cp", classpath, Writer.class.getName(), type, file, "one")
                    .redirectErrorStream(true).redirectOutput(dir.resolve(type + "-one.log").toFile()).start();
            var second = new ProcessBuilder(java, "-cp", classpath, Writer.class.getName(), type, file, "two")
                    .redirectErrorStream(true).redirectOutput(dir.resolve(type + "-two.log").toFile()).start();
            try {
                assertTrue(first.waitFor(30, TimeUnit.SECONDS));
                assertTrue(second.waitFor(30, TimeUnit.SECONDS));
                assertEquals(0, first.exitValue());
                assertEquals(0, second.exitValue());
                assertEquals(20, storage(type, file).getAllKeys("blocked:*").size());
            } finally { first.destroyForcibly(); second.destroyForcibly(); }
        }
    }
}
