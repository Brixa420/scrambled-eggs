import ScrambledEggs from './scrambled_eggs.js';

async function testEncryption() {
  try {
    console.log('Testing Scrambled Eggs Encryption...');
    const scrambledEggs = new ScrambledEggs();
    const testData = 'Hello, Scrambled Eggs!';
    const password = 'test-password';

    console.log('Encrypting data...');
    const { encrypted, metadata } = await scrambledEggs.encrypt(testData, password);
    console.log('Encryption successful!');
    console.log(`Layers used: ${metadata.layers}`);

    console.log('Decrypting data...');
    const decrypted = await scrambledEggs.decrypt(encrypted, password);
    console.log('Decryption successful!');
    
    const decryptedText = decrypted.toString();
    console.log('Original:', testData);
    console.log('Decrypted:', decryptedText);
    
    if (testData === decryptedText) {
      console.log('✅ Test passed! The decrypted text matches the original.');
    } else {
      console.error('❌ Test failed! The decrypted text does not match the original.');
    }
  } catch (error) {
    console.error('❌ Error during test:', error);
  }
}

testEncryption();
