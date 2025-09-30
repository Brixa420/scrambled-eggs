import ScrambledEggs from './scrambled_eggs.js';

async function runTest() {
  const scrambledEggs = new ScrambledEggs();
  const testData = 'Hello, Scrambled Eggs!';
  const password = 'test-password';

  console.log('Testing encryption...');
  
  try {
    // Test encryption
    const { encrypted, metadata } = await scrambledEggs.encrypt(testData, password);
    console.log('✅ Encryption successful!');
    console.log(`Layers used: ${metadata.layers}`);

    // Test decryption
    const decrypted = await scrambledEggs.decrypt(encrypted, password);
    const decryptedText = decrypted.toString();
    
    console.log('✅ Decryption successful!');
    console.log('Original:', testData);
    console.log('Decrypted:', decryptedText);
    
    if (testData === decryptedText) {
      console.log('✅ Test passed! The decrypted text matches the original.');
    } else {
      console.error('❌ Test failed! The decrypted text does not match the original.');
    }
  } catch (error) {
    console.error('❌ Test failed with error:', error);
  }
}

runTest().catch(console.error);
