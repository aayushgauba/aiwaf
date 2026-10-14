package com.aiwaf.runtime;

public final class RuntimeStorage {
    public static final class Context {
        private final StorageBackend storage;
        private final RuntimeState state;
        private final ExemptionStore exemptionStore;
        private final PathExemptionStore pathExemptionStore;
        private final BlocklistStore blocklistStore;
        private final KeywordStore keywordStore;
        private final GeoBlockStore geoBlockStore;

        private Context(StorageBackend storage, RuntimeState state) {
            this.storage = storage;
            this.state = state;
            this.exemptionStore = new ExemptionStore(storage);
            this.pathExemptionStore = new PathExemptionStore(storage);
            this.blocklistStore = new BlacklistStore(storage);
            this.keywordStore = new KeywordStore(storage);
            this.geoBlockStore = new GeoBlockStore(storage);
        }

        public StorageBackend storage() { return storage; }
        public RuntimeState state() { return state; }
        public ExemptionStore exemptionStore() { return exemptionStore; }
        public PathExemptionStore pathExemptionStore() { return pathExemptionStore; }
        public BlocklistStore blocklistStore() { return blocklistStore; }
        @Deprecated
        public BlacklistStore blacklistStore() { return (BlacklistStore) blocklistStore; }
        public KeywordStore keywordStore() { return keywordStore; }
        public GeoBlockStore geoBlockStore() { return geoBlockStore; }
    }

    private static volatile Context defaultContext;

    private RuntimeStorage() {}

    public static synchronized StorageBackend initialize(String backendType, String filePath) {
        return initialize(backendType, filePath, null, null);
    }

    public static synchronized StorageBackend initialize(
            String backendType,
            String filePath,
            String redisUrl,
            String keyPrefix
    ) {
        defaultContext = create(backendType, filePath, redisUrl, keyPrefix);
        return defaultContext.storage();
    }

    public static Context create(String backendType, String filePath, String redisUrl, String keyPrefix) {
        return create(backendType, filePath, redisUrl, keyPrefix, RedisStorage.Options.defaults());
    }

    public static Context create(
            String backendType,
            String filePath,
            String redisUrl,
            String keyPrefix,
            RedisStorage.Options redisOptions
    ) {
        String kind = backendType == null ? "memory" : backendType.trim().toLowerCase();
        StorageBackend storage;
        switch (kind) {
            case "memory" -> storage = new MemoryStorage();
            case "file" -> storage = new FileStorage(filePath == null ? "aiwaf_data.bin" : filePath);
            case "csv" -> storage = new CsvStorage(filePath == null ? "aiwaf_data.csv" : filePath);
            case "db" -> storage = new DbStorage(filePath == null ? "aiwaf_data.db" : filePath);
            case "redis" -> storage = new RedisStorage(redisUrl, keyPrefix, redisOptions);
            default -> throw new IllegalArgumentException("Unknown storage backend: " + backendType);
        }
        RuntimeState state = storage instanceof RuntimeState shared ? shared : new LocalRuntimeState();
        return new Context(storage, state);
    }

    public static synchronized void installDefault(Context context) {
        if (context == null) throw new IllegalArgumentException("context cannot be null");
        defaultContext = context;
    }

    public static Context getContext() {
        Context current = defaultContext;
        if (current != null) return current;
        synchronized (RuntimeStorage.class) {
            if (defaultContext == null) defaultContext = create("memory", null, null, null);
            return defaultContext;
        }
    }

    public static synchronized StorageBackend getStorage() {
        return getContext().storage();
    }

    public static synchronized ExemptionStore getExemptionStore() {
        return getContext().exemptionStore();
    }

    public static synchronized BlocklistStore getBlocklistStore() {
        return getContext().blocklistStore();
    }

    public static synchronized PathExemptionStore getPathExemptionStore() {
        return getContext().pathExemptionStore();
    }

    public static synchronized KeywordStore getKeywordStore() {
        return getContext().keywordStore();
    }

    public static synchronized GeoBlockStore getGeoBlockStore() {
        return getContext().geoBlockStore();
    }

    // Compatibility aliases for the previous API names.
    @Deprecated
    public static synchronized BlacklistStore getBlacklistStore() { return (BlacklistStore) getBlocklistStore(); }
}
