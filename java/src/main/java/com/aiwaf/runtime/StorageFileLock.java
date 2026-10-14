package com.aiwaf.runtime;

import com.aiwaf.core.SecureFiles;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.function.Supplier;

/** Stable sidecar locks survive atomic replacement of the storage data file. */
final class StorageFileLock {
    private static final Object[] STRIPES = new Object[64];
    static {
        for (int i = 0; i < STRIPES.length; i++) STRIPES[i] = new Object();
    }

    private StorageFileLock() {}

    static <T> T withLock(Path file, Supplier<T> action) {
        Path absolute = file.toAbsolutePath().normalize();
        Path lock = absolute.resolveSibling(absolute.getFileName() + ".lock");
        // Prevent overlapping OS locks from different instances in this JVM.
        synchronized (STRIPES[Math.floorMod(lock.hashCode(), STRIPES.length)]) {
            try {
                SecureFiles.rejectSymbolicLinks(absolute);
                SecureFiles.rejectSymbolicLinks(lock);
                Files.createDirectories(lock.getParent());
                try (FileChannel channel = FileChannel.open(lock,
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                     var held = channel.lock()) {
                    return action.get();
                }
            } catch (IOException ex) {
                throw new IllegalStateException("Unable to lock storage file " + absolute, ex);
            }
        }
    }
}
