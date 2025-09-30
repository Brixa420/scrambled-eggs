import ScrambledEggs from './scrambled_eggs.js';

async function testDynamicLayers() {
  const crypto = new ScrambledEggs();
  
  console.log('Initial status:');
  console.log(crypto.getStats());
  
  // Test manual layer adjustment
  console.log('\n=== Testing manual layer adjustment ===');
  crypto.setLayers(1500, 'test_manual_adjustment');
  
  // Test security escalation
  console.log('\n=== Testing security escalation ===');
  crypto.config.failedAttempts = 4; // Above threshold
  
  // Show immediate effect
  console.log('Immediate status after setting failed attempts:');
  console.log(crypto.getStats());
  
  // Wait for security monitor to run
  console.log('\nWaiting for security monitor cycle...');
  await new Promise(resolve => setTimeout(resolve, 65000));
  
  console.log('\nFinal status:');
  console.log(crypto.getStats());
}

testDynamicLayers().catch(console.error);
