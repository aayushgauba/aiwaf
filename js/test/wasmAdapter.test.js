const { IsolationForest } = require('../lib/isolationForest');

describe('wasmAdapter', () => {
  afterEach(() => {
    delete process.env.AIWAF_DISABLE_WASM;
    jest.resetModules();
    jest.clearAllMocks();
  });

  it('uses wasm validation helpers when available', async () => {
    const fitSpy = jest.fn();
    const retrainSpy = jest.fn();
    jest.doMock('aiwaf-wasm', () => ({
      default: jest.fn(async () => {}),
      validate_headers: jest.fn(() => null),
      validate_url: jest.fn(() => 'url_bad'),
      validate_content: jest.fn(() => ({ ok: false, reason: 'content_bad' })),
      validate_recent: jest.fn(() => false),
      extract_raw_training_features: jest.fn(() => [{ path_len: 6, kw_hits: 1 }]),
      RouteMatcher: class {
        constructor(prefixes) { this.prefixes = prefixes; }
        match_index(path) { return path.startsWith(this.prefixes[0]) ? 0 : undefined; }
      },
      AiwafIsolationForest: class {
        constructor() {}
        fit(data) { fitSpy(data); }
        retrain(data) { retrainSpy(data); }
        anomaly_score() { return 0.7; }
      }
    }));

    const {
      createIsolationForest,
      validateHeaders,
      validateUrl,
      validateContent,
      validateRecent,
      extractWasmRawTrainingFeatures,
      createRouteMatcher
    } = require('../lib/wasmAdapter');

    const model = await createIsolationForest({ nTrees: 10, sampleSize: 8, threshold: 0.5 });
    expect(model.__aiwafWasm).toBe(true);
    model.fit([[0.1, 0.2, 0.3]]);
    model.retrain([[0.2, 0.1, 0.4]]);
    expect(fitSpy).toHaveBeenCalledTimes(1);
    expect(retrainSpy).toHaveBeenCalledTimes(1);
    expect(model.isAnomaly([0.1, 0.2, 0.3])).toBe(true);

    expect(await validateHeaders({ accept: 'text/html' })).toBeNull();
    expect(await validateUrl('http://example.com')).toBe('url_bad');
    expect(await validateContent('payload')).toBe('content_bad');
    expect(await validateRecent([{ path: '/', status: 200 }])).toBe('wasm_recent_invalid');
    expect(await extractWasmRawTrainingFeatures(
      [{ ip: '203.0.113.1', path: '/a.php' }], ['.php'], ['200', '404']
    )).toEqual([{ path_len: 6, kw_hits: 1 }]);
    const routeMatcher = await createRouteMatcher(['/api/']);
    expect(routeMatcher.matchIndex('/api/items')).toBe(0);
    expect(routeMatcher.matchIndex('/other')).toBeNull();
  });

  it('falls back to JS isolation forest when wasm is unavailable', async () => {
    process.env.AIWAF_DISABLE_WASM = '1';
    jest.doMock('aiwaf-wasm', () => {
      throw new Error('not installed');
    });

    const { createIsolationForest, createTrainingEvidence } = require('../lib/wasmAdapter');
    const model = await createIsolationForest({ nTrees: 10, sampleSize: 8 });
    expect(model).not.toHaveProperty('__aiwafWasm', true);
    expect(typeof model.fit).toBe('function');
    expect(typeof model.anomalyScore).toBe('function');
    await expect(createTrainingEvidence('{"version":1,"ips":{}}')).rejects.toThrow('Training replay protection requires');
  });

  it('supports the current Rust wasm IsolationForest export shape', async () => {
    const scoreSamples = jest.fn(() => [0.1, 0.8]);
    const decisionFunction = jest.fn(() => [0.9, 0.2]);
    const predict = jest.fn(() => [1, -1]);
    const toJson = jest.fn(() => ({ trees: [] }));

    jest.doMock('aiwaf-wasm', () => ({
      default: jest.fn(async () => {}),
      IsolationForest: class {
        constructor(config) {
          this.config = config;
        }
        fit() {}
        retrain() {}
        anomaly_score() { return 0.8; }
        is_anomaly() { return true; }
        score_samples(data) { return scoreSamples(data); }
        decision_function(data) { return decisionFunction(data); }
        predict(data) { return predict(data); }
        to_json() { return toJson(); }
        static from_json() {
          return new this({ restored: true });
        }
      }
    }));

    const {
      createIsolationForest,
      createIsolationForestFromJSON
    } = require('../lib/wasmAdapter');

    const model = await createIsolationForest({ nTrees: 7, sampleSize: 3, seed: 11 });
    expect(model.__aiwafWasm).toBe(true);
    expect(model.anomalyScore([1, 2])).toBe(0.8);
    expect(model.isAnomaly([1, 2])).toBe(true);
    expect(model.scoreSamples([[1], [2]])).toEqual([0.1, 0.8]);
    expect(model.decisionFunction([[1], [2]])).toEqual([0.9, 0.2]);
    expect(model.predict([[1], [2]])).toEqual([1, -1]);
    expect(model.toJSON()).toEqual({ trees: [] });

    const restored = await createIsolationForestFromJSON({ trees: [] });
    expect(restored.__aiwafWasm).toBe(true);
    restored.fit([[1]]);
    restored.retrain([[2]]);
    expect(restored.anomalyScore([1, 2])).toBe(0.8);
    expect(restored.isAnomaly([1, 2])).toBe(true);
    expect(restored.scoreSamples([[1], [2]])).toEqual([0.1, 0.8]);
    expect(restored.decisionFunction([[1], [2]])).toEqual([0.9, 0.2]);
    expect(restored.predict([[1], [2]])).toEqual([1, -1]);
    expect(restored.toJSON()).toEqual({ trees: [] });
  });

  it('wraps Rust feature extraction and recent behavior helpers', async () => {
    const analyzeRecent = jest.fn(() => ({ should_block: true }));
    const extractFeatures = jest.fn(() => [{ features: [1, 2, 3] }]);
    const extractWithState = jest.fn(() => ({ records: [], state: { ok: true } }));
    const finalizeState = jest.fn(() => ({ records: [], state: null }));

    jest.doMock('aiwaf-wasm', () => ({
      default: jest.fn(async () => {}),
      analyze_recent_behavior: analyzeRecent,
      extract_features: extractFeatures,
      extract_features_batch_with_state: extractWithState,
      finalize_feature_state: finalizeState
    }));

    const {
      validateRecent,
      analyzeRecentBehavior,
      extractWasmFeatures,
      extractWasmFeaturesBatchWithState,
      finalizeWasmFeatureState
    } = require('../lib/wasmAdapter');

    expect(await validateRecent([{ path: '/x', status: 404, timestamp: 10000 }])).toBe('wasm_recent_invalid');
    expect(await analyzeRecentBehavior([{ path: '/x', timestamp: 20000 }], ['.php'])).toEqual({ should_block: true });
    expect(await extractWasmFeatures([{ path: '/x' }], ['.php'])).toEqual([{ features: [1, 2, 3] }]);
    expect(await extractWasmFeaturesBatchWithState([{ path: '/x' }], ['.php'], { previous: true })).toEqual({
      records: [],
      state: { ok: true }
    });
    expect(await finalizeWasmFeatureState()).toEqual({ records: [], state: null });

    expect(analyzeRecent).toHaveBeenNthCalledWith(1, [{ path_lower: '/x', timestamp: 10000, status: 404, kw_check: true }], []);
    expect(analyzeRecent).toHaveBeenNthCalledWith(2, [{ path_lower: '/x', timestamp: 20000, status: 0, kw_check: true }], ['.php']);
    await analyzeRecentBehavior([{ path: '/x', timestamp_ms: 20000 }], ['.php']);
    expect(analyzeRecent).toHaveBeenNthCalledWith(3, [{ path_lower: '/x', timestamp: 20, status: 0, kw_check: true }], ['.php']);
    expect(extractFeatures).toHaveBeenCalledWith([{ path: '/x' }], ['.php']);
    expect(extractWithState).toHaveBeenCalledWith([{ path: '/x' }], ['.php'], { previous: true });
  });

  it('wraps the Rust keyword matcher and preserves no-match results', async () => {
    const firstMatch = jest.fn(path => (path.includes('/.env') ? '.env' : null));
    jest.doMock('aiwaf-wasm', () => ({
      default: jest.fn(async () => {}),
      KeywordMatcher: class {
        constructor(keywords) {
          expect(keywords).toEqual(['.env', 'admin']);
        }
        first_match(path) { return firstMatch(path); }
      }
    }));

    const { createKeywordMatcher } = require('../lib/wasmAdapter');
    const matcher = await createKeywordMatcher(['.env', 'admin']);
    expect(matcher.firstMatch('/.env')).toBe('.env');
    expect(matcher.firstMatch('/safe')).toBeNull();
    expect(firstMatch).toHaveBeenCalledWith('/safe');
  });

  it('wraps optional Rust record conversion helpers when present', async () => {
    const buildRecords = jest.fn(() => [{ path: '/built' }]);
    const rustPayload = jest.fn(() => [{ path_len: 6 }]);
    const pythonFeature = jest.fn(() => ({ features: [6, 1] }));
    const pythonBatch = jest.fn(() => [{ features: [6, 1] }]);

    jest.doMock('aiwaf-wasm', () => ({
      default: jest.fn(async () => {}),
      build_records: buildRecords,
      rust_payload_from_records: rustPayload,
      python_feature_from_record: pythonFeature,
      python_features_batched: pythonBatch
    }));

    const {
      buildWasmRecords,
      rustPayloadFromRecords,
      pythonFeatureFromRecord,
      pythonFeaturesBatched
    } = require('../lib/wasmAdapter');

    const pathExists = jest.fn(() => true);
    const pathExempt = jest.fn(() => false);

    expect(await buildWasmRecords([{ path: '/x' }], { '203.0.113.1': 2 }, pathExists, pathExempt, [200, 404]))
      .toEqual([{ path: '/built' }]);
    expect(await rustPayloadFromRecords([{ path: '/built' }])).toEqual([{ path_len: 6 }]);
    expect(await pythonFeatureFromRecord({ path: '/built' }, { '203.0.113.1': [1, 2] }, ['.php']))
      .toEqual({ features: [6, 1] });
    expect(await pythonFeaturesBatched([{ path: '/built' }], {}, ['.php'], { batchSize: 2, maxWorkers: 1 }))
      .toEqual([{ features: [6, 1] }]);

    expect(buildRecords).toHaveBeenCalledWith([{ path: '/x' }], { '203.0.113.1': 2 }, pathExists, pathExempt, [200, 404]);
    expect(rustPayload).toHaveBeenCalledWith([{ path: '/built' }]);
    expect(pythonFeature).toHaveBeenCalledWith({ path: '/built' }, { '203.0.113.1': [1, 2] }, ['.php']);
    expect(pythonBatch).toHaveBeenCalledWith([{ path: '/built' }], {}, ['.php'], null, 2, true, 1000, 1);
  });
});
