import { describe, it, before, after, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';
import ScrambledEggs from '../scrambled_eggs.js';
import KeyManager from '../key_derivation.js';
import { 
  generateTestData, 
  hashData, 
  runPerformanceTest,
  getMemoryUsage,
  randomString
} from './test_helpers.js';

// Test configuration
const TEST_CONFIG = {
  smallDataSize: 1024, // 1KB
  mediumDataSize: 1024 * 1024, // 1MB
  largeDataSize: 10 * 1024 * 1024, // 10MB
  password: 'super-secure-p@ssw0rd!',
  testIterations: 10
};

describe('Scrambled Eggs Encryption', function() {
  this.timeout(30000); // Increase timeout for performance tests
  
  let scrambledEggs;
  let testData = {
    small: null,
    medium: null,
    large: null,
    text: 'Hello, Scrambled Eggs! 🍳',
    json: { key: 'value', nested: { array: [1, 2, 3] } },
    binary: null
  };

  before(() => {
    console.log('\n🔍 Setting up test environment...');
    scrambledEggs = new ScrambledEggs();
    
    // Generate test data
    testData.small = generateTestData(TEST_CONFIG.smallDataSize);
    testData.medium = generateTestData(TEST_CONFIG.mediumDataSize);
    testData.large = generateTestData(TEST_CONFIG.largeDataSize);
    testData.binary = generateTestData(512); // Random binary data
    
    console.log('✅ Test data generated');
    console.log('📊 Memory Usage:', getMemoryUsage());
  });

  after(() => {
    console.log('\n🧹 Cleaning up test environment...');
    // Any cleanup code here
    console.log('✅ Cleanup complete');
  });

  describe('Basic Functionality', () => {
    it('should encrypt and decrypt small data correctly', async () => {
      const original = testData.small;
      const originalHash = hashData(original);
      
      const { encrypted, metadata } = await scrambledEggs.encrypt(original, TEST_CONFIG.password);
      const decrypted = await scrambledEggs.decrypt(encrypted, TEST_CONFIG.password);
      const decryptedHash = hashData(decrypted);
      
      expect(decrypted).to.be.an.instanceOf(Buffer);
      expect(decrypted).to.have.lengthOf(original.length);
      expect(decryptedHash).to.equal(originalHash);
      expect(metadata.layers).to.be.at.least(1000);
    });

    it('should handle different data types', async () => {
      // Test with string
      let encrypted = await scrambledEggs.encrypt(testData.text, TEST_CONFIG.password);
      let decrypted = await scrambledEggs.decrypt(encrypted.encrypted, TEST_CONFIG.password);
      expect(decrypted.toString()).to.equal(testData.text);
      
      // Test with JSON
      const jsonString = JSON.stringify(testData.json);
      encrypted = await scrambledEggs.encrypt(jsonString, TEST_CONFIG.password);
      decrypted = await scrambledEggs.decrypt(encrypted.encrypted, TEST_CONFIG.password);
      expect(JSON.parse(decrypted.toString())).to.deep.equal(testData.json);
      
      // Test with binary data
      encrypted = await scrambledEggs.encrypt(testData.binary, TEST_CONFIG.password);
      decrypted = await scrambledEggs.decrypt(encrypted.encrypted, TEST_CONFIG.password);
      expect(decrypted).to.deep.equal(testData.binary);
    });

    it('should fail with incorrect password', async () => {
      const { encrypted } = await scrambledEggs.encrypt(testData.small, TEST_CONFIG.password);
      
      try {
        await scrambledEggs.decrypt(encrypted, 'wrong-password');
        throw new Error('Decryption should have failed with wrong password');
      } catch (error) {
        expect(error).to.be.an('error');
        expect(error.message).to.include('Decryption failed');
      }
    });
  });

  describe('Security Features', () => {
    it('should detect tampered data', async () => {
      const { encrypted } = await scrambledEggs.encrypt(testData.small, TEST_CONFIG.password);
      
      // Tamper with the encrypted data
      const tampered = Buffer.from(encrypted);
      tampered[100] = (tampered[100] + 1) % 256; // Flip one bit
      
      try {
        await scrambledEggs.decrypt(tampered, TEST_CONFIG.password);
        throw new Error('Tampered data should be detected');
      } catch (error) {
        expect(error).to.be.an('error');
        expect(error.message).to.include('Decryption failed');
      }
    });

    it('should escalate security on breach detection', async () => {
      const originalLayers = scrambledEggs.layers;
      
      // Trigger a breach
      await scrambledEggs.encrypt(testData.small, TEST_CONFIG.password);
      const afterFirstEncryption = scrambledEggs.layers;
      
      // Trigger another breach
      await scrambledEggs.encrypt(testData.small, TEST_CONFIG.password);
      
      expect(scrambledEggs.layers).to.be.greaterThan(afterFirstEncryption);
      expect(scrambledEggs.breachDetected).to.be.true;
      console.log(`🔒 Security escalated from ${originalLayers} to ${scrambledEggs.layers} layers`);
    });
  });

  describe('Performance', () => {
    it('should handle large data efficiently', async () => {
      const sizes = [
        { name: 'Small (1KB)', data: testData.small },
        { name: 'Medium (1MB)', data: testData.medium },
        { name: 'Large (10MB)', data: testData.large }
      ];

      for (const { name, data } of sizes) {
        console.log(`\n📊 Testing with ${name} data`);
        
        const memBefore = getMemoryUsage();
        const start = process.hrtime.bigint();
        
        const { encrypted } = await scrambledEggs.encrypt(data, TEST_CONFIG.password);
        const decrypted = await scrambledEggs.decrypt(encrypted, TEST_CONFIG.password);
        
        const end = process.hrtime.bigint();
        const memAfter = getMemoryUsage();
        
        // Verify data integrity
        expect(decrypted).to.deep.equal(data);
        
        // Log performance
        const timeMs = Number(end - start) / 1_000_000;
        console.log(`  Time: ${timeMs.toFixed(2)}ms`);
        console.log('  Memory:', {
          rss: `+${(parseFloat(memAfter.rss) - parseFloat(memBefore.rss)).toFixed(2)} MB`,
          heapUsed: `+${(parseFloat(memAfter.heapUsed) - parseFloat(memBefore.heapUsed)).toFixed(2)} MB`
        });
      }
    });

    it('should scale with multiple encryptions', async () => {
      const results = [];
      
      for (let i = 0; i < 5; i++) {
        const size = 1024 * (i + 1); // 1KB to 5KB
        const data = generateTestData(size);
        
        const start = process.hrtime.bigint();
        await scrambledEggs.encrypt(data, `${TEST_CONFIG.password}-${i}`);
        const end = process.hrtime.bigint();
        
        results.push({
          size,
          timeMs: Number(end - start) / 1_000_000
        });
      }
      
      console.log('\n⏱️  Performance by data size:');
      results.forEach(({ size, timeMs }) => {
        console.log(`  ${(size / 1024).toFixed(1)}KB: ${timeMs.toFixed(2)}ms (${(size / 1024 / (timeMs / 1000)).toFixed(2)} KB/s)`);
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty data', async () => {
      const emptyData = Buffer.alloc(0);
      const { encrypted } = await scrambledEggs.encrypt(emptyData, TEST_CONFIG.password);
      const decrypted = await scrambledEggs.decrypt(encrypted, TEST_CONFIG.password);
      expect(decrypted).to.deep.equal(emptyData);
    });

    it('should handle very long passwords', async () => {
      const longPassword = randomString(10000); // 10KB password
      const { encrypted } = await scrambledEggs.encrypt(testData.small, longPassword);
      const decrypted = await scrambledEggs.decrypt(encrypted, longPassword);
      expect(decrypted).to.deep.equal(testData.small);
    });

    it('should handle concurrent operations', async () => {
      const concurrency = 10;
      const promises = [];
      
      for (let i = 0; i < concurrency; i++) {
        const data = generateTestData(1024); // 1KB per operation
        promises.push(
          scrambledEggs.encrypt(data, `${TEST_CONFIG.password}-${i}`)
            .then(({ encrypted }) => scrambledEggs.decrypt(encrypted, `${TEST_CONFIG.password}-${i}`))
            .then(decrypted => expect(decrypted).to.have.lengthOf(data.length))
        );
      }
      
      await Promise.all(promises);
    });
  });

  describe('Key Management', () => {
    it('should derive consistent keys', async () => {
      const salt = KeyManager.generateSalt();
      const key1 = await KeyManager.deriveKey('password', salt);
      const key2 = await KeyManager.deriveKey('password', salt);
      
      expect(key1).to.be.an.instanceOf(Buffer);
      expect(key1).to.have.length(32);
      expect(key1).to.deep.equal(key2);
    });

    it('should detect key derivation timing attacks', async () => {
      const salt = KeyManager.generateSalt();
      const start = process.hrtime.bigint();
      
      // First call (warm-up)
      await KeyManager.deriveKey('password', salt);
      
      // Test with different passwords
      const results = [];
      const passwords = ['password', 'passw0rd', 'password123', 'p@ssw0rd'];
      
      for (const pwd of passwords) {
        const startTime = process.hrtime.bigint();
        await KeyManager.deriveKey(pwd, salt);
        const endTime = process.hrtime.bigint();
        results.push({
          password: pwd,
          time: Number(endTime - startTime)
        });
      }
      
      // Check that timing differences are minimal
      const times = results.map(r => r.time);
      const maxDiff = Math.max(...times) - Math.min(...times);
      const maxAllowedDiff = 1000000; // 1ms in nanoseconds
      
      console.log('\n⏱️  Key derivation timing test:');
      results.forEach(({ password, time }) => {
        console.log(`  ${password}: ${(time / 1_000_000).toFixed(4)}ms`);
      });
      
      expect(maxDiff).to.be.lessThan(maxAllowedDiff);
    });
  });
});
