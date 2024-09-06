import CryptoJS from 'crypto-js';

export function encryptAES256ECB(block, key) {
    // Check input lengths
    if (block.length !== 16 || key.length !== 32) {
        throw new Error('Invalid input lengths. Block must be 16 bytes and key must be 32 bytes.');
    }

    // Convert Uint8Array to WordArray
    const blockWords = CryptoJS.lib.WordArray.create(block);
    const keyWords = CryptoJS.lib.WordArray.create(key);

    // Encrypt
    const encrypted = CryptoJS.AES.encrypt(blockWords, keyWords, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.NoPadding
    });

    // Convert the result back to Uint8Array
    const encryptedArray = new Uint8Array(encrypted.ciphertext.words.length * 4);
    for (let i = 0; i < encrypted.ciphertext.words.length; i++) {
        const word = encrypted.ciphertext.words[i];
        encryptedArray[i*4] = (word >> 24) & 0xff;
        encryptedArray[i*4 + 1] = (word >> 16) & 0xff;
        encryptedArray[i*4 + 2] = (word >> 8) & 0xff;
        encryptedArray[i*4 + 3] = word & 0xff;
    }

    return encryptedArray;
}

export function decryptAES256ECB(block, key) {
    // Check input lengths
    if (block.length !== 16 || key.length !== 32) {
        throw new Error('Invalid input lengths. Block must be 16 bytes and key must be 32 bytes.');
    }

    // Convert Uint8Array to WordArray
    const blockWords = CryptoJS.lib.WordArray.create(block);
    const keyWords = CryptoJS.lib.WordArray.create(key);

    // Decrypt
    const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: blockWords },
        keyWords,
        {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.NoPadding
        }
    );

    // Convert the result back to Uint8Array
    const decryptedArray = new Uint8Array(decrypted.words.length * 4);
    for (let i = 0; i < decrypted.words.length; i++) {
        const word = decrypted.words[i];
        decryptedArray[i*4] = (word >> 24) & 0xff;
        decryptedArray[i*4 + 1] = (word >> 16) & 0xff;
        decryptedArray[i*4 + 2] = (word >> 8) & 0xff;
        decryptedArray[i*4 + 3] = word & 0xff;
    }

    return decryptedArray;
}