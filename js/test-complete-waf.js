const express = require('express');
const request = require('supertest');
const wafMiddleware = require('./lib/wafMiddleware');
const blocklistManager = require('./lib/blocklistManager');
const rateLimiter = require('./lib/rateLimiter');
const { extractFeatures, init: initFeatures, markRequestStart } = require('./lib/featureUtils');
const anomalyDetector = require('./lib/anomalyDetector');

async function setupTestEnvironment() {
  console.log('Setting up test environment...');
  
  // Initialize all components
  await blocklistManager.initialize();
  
  initFeatures();
  
  await rateLimiter.init({
    WINDOW_SEC: 1,
    MAX_REQ: 3,
    FLOOD_REQ: 5
  });
  
  anomalyDetector.init();
  
  console.log('Test environment ready');
}

async function testCompleteWAF() {
  console.log('\nTesting Complete WAF Pipeline\n');
  
  await setupTestEnvironment();
  
  const app = express();
  
  // Add request timing middleware
  app.use((req, res, next) => {
    markRequestStart(req);
    next();
  });
  
  // Add WAF middleware
  app.use(wafMiddleware());
  
  // Test routes
  app.get('/', (req, res) => res.json({ message: 'Hello World' }));
  app.get('/admin', (req, res) => res.json({ message: 'Admin panel' }));
  app.get('/api/users', (req, res) => res.json({ users: [] }));
  
  console.log('1. Testing normal requests...');
  let response = await request(app)
    .get('/')
    .expect(200);
  console.log('   Normal request passed');
  
  response = await request(app)
    .get('/api/users')
    .expect(200);
  console.log('   API request passed');
  
  console.log('\n2. Testing suspicious requests...');
  
  try {
    response = await request(app)
      .get('/admin.php');
    console.log(`   PHP request: ${response.status} ${response.status === 403 ? '(Blocked by WAF)' : '(Allowed)'}`);
  } catch (err) {
    console.log(`   PHP request: Error - ${err.message}`);
  }
  
  try {
    response = await request(app)
      .get('/wp-admin/admin-ajax.php');
    console.log(`   WordPress request: ${response.status} ${response.status === 403 ? '(Blocked by WAF)' : '(Allowed)'}`);
  } catch (err) {
    console.log(`   WordPress request: Error - ${err.message}`);
  }
  
  console.log('\n3. Testing rate limiting...');
  const testIP = '192.168.1.100';
  
  // Make multiple requests quickly
  for (let i = 0; i < 4; i++) {
    try {
      response = await request(app)
        .get('/')
        .set('X-Forwarded-For', testIP);
      console.log(`   Request ${i + 1}: ${response.status}`);
    } catch (err) {
      console.log(`   Request ${i + 1}: Error - ${err.message}`);
    }
  }
  
  console.log('\n4. Testing feature extraction...');
  const mockReq = {
    path: '/test-path.php',
    ip: '192.168.1.200',
    headers: {},
    _startTime: Date.now() - 100
  };
  
  const features = await extractFeatures(mockReq);
  console.log(`   Features extracted: [${features.join(', ')}]`);
  console.log('   Feature breakdown:');
  console.log(`     - Path length: ${features[0]}`);
  console.log(`     - Keyword hits: ${features[1]}`);
  console.log(`     - Status index: ${features[2]}`);
  console.log(`     - Response time: ${features[3]}`);
  console.log(`     - Burst count: ${features[4]}`);
  console.log(`     - 404 count: ${features[5]}`);
  
  console.log('\n5. Testing anomaly detection...');
  const isAnomalous = anomalyDetector.isAnomalous(features);
  console.log(`   Anomaly detected: ${isAnomalous ? 'YES' : 'NO'}`);
  
  console.log('\n6. Testing blocklist management...');
  const testBlockIP = '192.168.1.999';
  await blocklistManager.block(testBlockIP, 'Test block');
  const isBlocked = await blocklistManager.isBlocked(testBlockIP);
  console.log(`   IP ${testBlockIP} blocked: ${isBlocked ? 'YES' : 'NO'}`);
  
  const blockedIPs = await blocklistManager.getBlockedIPs();
  console.log(`   Total blocked IPs: ${blockedIPs.length}`);
  
  await blocklistManager.unblock(testBlockIP);
  const stillBlocked = await blocklistManager.isBlocked(testBlockIP);
  console.log(`   IP ${testBlockIP} after unblock: ${stillBlocked ? 'Still blocked' : 'Unblocked'}`);
  
  console.log('\n7. Testing model info...');
  const modelInfo = anomalyDetector.getModelInfo();
  console.log(`   Model trained: ${modelInfo.trained ? 'YES' : 'NO'}`);
  if (modelInfo.metadata) {
    console.log(`   Samples trained on: ${modelInfo.metadata.samplesCount}`);
    console.log(`   Created at: ${modelInfo.metadata.createdAt}`);
  }
  
  console.log('\nWAF Pipeline Test Complete!');
  
  // Cleanup
  rateLimiter.cleanup();
}

// Run the test
if (require.main === module) {
  testCompleteWAF().catch(console.error);
}

module.exports = { testCompleteWAF, setupTestEnvironment };
