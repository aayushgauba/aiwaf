const { extractFeatures, init: initFeatures, markRequestStart } = require('./lib/featureUtils');
const anomalyDetector = require('./lib/anomalyDetector');
const blocklistManager = require('./lib/blocklistManager');
const rateLimiter = require('./lib/rateLimiter');

async function simpleTest() {
  console.log('Simple WAF Component Test\n');
  
  // Initialize components
  await blocklistManager.initialize();
  initFeatures();
  await rateLimiter.init({
    WINDOW_SEC: 1,
    MAX_REQ: 5,
    FLOOD_REQ: 10
  });
  anomalyDetector.init();
  
  console.log('1. Testing feature extraction...');
  
  // Test normal request
  const normalReq = {
    path: '/api/users',
    ip: '192.168.1.100',
    headers: {},
    _startTime: Date.now() - 50
  };
  
  const normalFeatures = await extractFeatures(normalReq);
  console.log(`   Normal request features: [${normalFeatures.join(', ')}]`);
  const normalAnomaly = anomalyDetector.isAnomalous(normalFeatures, 0.5);
  console.log(`   Normal request anomalous: ${normalAnomaly ? 'YES' : 'NO'}`);
  
  // Test suspicious request
  const suspiciousReq = {
    path: '/admin.php?shell=1&cmd=whoami',
    ip: '192.168.1.101',
    headers: {},
    _startTime: Date.now() - 1000
  };
  
  const suspiciousFeatures = await extractFeatures(suspiciousReq);
  console.log(`   Suspicious request features: [${suspiciousFeatures.join(', ')}]`);
  const suspiciousAnomaly = anomalyDetector.isAnomalous(suspiciousFeatures, 0.5);
  console.log(`   Suspicious request anomalous: ${suspiciousAnomaly ? 'YES' : 'NO'}`);
  
  console.log('\n2. Testing rate limiting...');
  
  const testIP = '192.168.1.200';
  
  // Record multiple requests
  for (let i = 0; i < 3; i++) {
    await rateLimiter.record(testIP);
    const blocked = await rateLimiter.isBlocked(testIP);
    console.log(`   Request ${i + 1}: ${blocked ? 'BLOCKED' : 'ALLOWED'}`);
  }
  
  console.log('\n3. Testing blocklist...');
  
  const blockIP = '192.168.1.300';
  await blocklistManager.block(blockIP, 'Test block');
  const isBlocked = await blocklistManager.isBlocked(blockIP);
  console.log(`   IP ${blockIP} blocked: ${isBlocked ? 'YES' : 'NO'}`);
  
  console.log('\n4. Model information...');
  const modelInfo = anomalyDetector.getModelInfo();
  console.log(`   Model trained: ${modelInfo.trained}`);
  if (modelInfo.metadata) {
    console.log(`   Training samples: ${modelInfo.metadata.samplesCount}`);
    console.log(`   Feature count: ${modelInfo.metadata.featureCount}`);
  }
  
  console.log('\nSimple test complete!');
  
  // Cleanup
  rateLimiter.cleanup();
}

simpleTest().catch(console.error);
