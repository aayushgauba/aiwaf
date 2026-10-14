package com.aiwaf.runtime;
/** Compatibility name; use BlocklistStore. */
@Deprecated
public final class BlacklistStore extends BlocklistStore {
    public BlacklistStore(StorageBackend storage) { super(storage); }
}
