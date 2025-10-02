import { randomBytes, createHash } from 'crypto';

/**
 * Generate random test data of specified size
 * @param {number} size - Size in bytes
 * @returns {Buffer}
 */
export function generateTestData(size) {
  return randomBytes(size);
}

/**
 * Calculate SHA-256 hash of data
 * @param {Buffer|string} data
 * @returns {string}
 */
export function hashData(data) {
  return createHash('sha256')
    .update(data)
    .digest('hex');
}

/**
 * Run a performance test
 * @param {Function} fn - Function to test
 * @param {string} name - Test name
 * @param {number} iterations - Number of iterations
 */
export async function runPerformanceTest(fn, name, iterations = 100) {
  const start = process.hrtime.bigint();
  
  for (let i = 0; i < iterations; i++) {
    await fn();
  }
  
  const end = process.hrtime.bigint();
  const totalNs = Number(end - start);
  const avgMs = (totalNs / 1_000_000) / iterations;
  
  console.log(`\n⏱️  ${name} Performance:`);
  console.log(`  Iterations: ${iterations}`);
  console.log(`  Total Time: ${(totalNs / 1_000_000).toFixed(2)}ms`);
  console.log(`  Average Time: ${avgMs.toFixed(4)}ms per operation`);
  
  return {
    totalTime: totalNs / 1_000_000, // ms
    averageTime: avgMs, // ms
    iterations,
    name
  };
}

/**
 * Measure memory usage
 * @returns {Object} Memory usage in MB
 */
export function getMemoryUsage() {
  const used = process.memoryUsage();
  const format = (bytes) => (bytes / 1024 / 1024).toFixed(2) + ' MB';
  
  return {
    rss: format(used.rss),
    heapTotal: format(used.heapTotal),
    heapUsed: format(used.heapUsed),
    external: format(used.external || 0),
    arrayBuffers: format(used.arrayBuffers || 0)
  };
}

/**
 * Generate a random string of specified length
 * @param {number} length
 * @returns {string}
 */
export function randomString(length) {
  return randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
}
