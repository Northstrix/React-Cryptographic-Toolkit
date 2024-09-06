import React, { useState, useCallback} from 'react';
import CryptoJS from 'crypto-js';
import './midbar-compatible-aes-256-cbc.css';
import { encryptAES256ECB, decryptAES256ECB } from '../cryptographicPrimitives/aes';
import { encryptTwofish256ECB, decryptTwofish256ECB } from '../cryptographicPrimitives/twofish';
import { encryptSerpent256ECB, decryptSerpent256ECB } from '../cryptographicPrimitives/serpent';
import { showDisappearingSpanNotification } from '../Notifications/spanNotification';
import '../Notifications/spanNotification.css';
import { pbkdf2, createSHA512, createHMAC, whirlpool } from 'hash-wasm';
import { ChaCha20 } from 'mipher';

const MidbarCompatibleAES256CBC = ({ encryptionType }) => {
    const [input, setInput] = useState('');
    const [key, setKey] = useState('');
    const [output, setOutput] = useState('');
    const [showKey, setShowKey] = useState(false);
    const [isKeyHidden, setIsKeyHidden] = useState(false);

    const deriveKey = useCallback(async (password, salt, iterations) => {
      const derivedKey = await pbkdf2({
        password,
        salt,
        iterations,
        hashLength: 96, // 96 bytes (768 bits)
        hashFunction: createSHA512(),
        outputType: 'binary',
      });
      return new Uint8Array(derivedKey);
    }, []);
    
    const setOKOutput = (message) => {
        const textarea = document.getElementById('output');
        
        if (textarea) {
            textarea.value = message;
            textarea.style.color = '#4d4d4d';
        }
    };

    const setErrorOutput = (errorMessage) => {
        const textarea = document.getElementById('output');
        
        if (textarea) {
            textarea.value = errorMessage;
            textarea.style.color = '#DF3C5F';
        }
    };

    const incrAesKey = (aesKey) => {
        let newAesKey = new Uint8Array(aesKey);
        let i = 15; // Start from the last byte

        while (i >= 0) {
            if (newAesKey[i] === 255) {
                newAesKey[i] = 0; // Reset to 0 if it is 255
                i -= 1; // Move to the next byte
            } else {
                newAesKey[i] += 1; // Increment the current byte
                break; // Exit the loop after incrementing
            }
        }

        return newAesKey; // Return the new array
    };

    const hexStringToArray = (hexString) => {
        // Check if the input is a valid hex string
        if (!/^[0-9A-Fa-f]+$/.test(hexString)) {
            throw new Error("Invalid hex string");
        }
    
        if (hexString.length % 2 !== 0) {
            throw new Error("Invalid hex string");
        }
    
        const resultArray = [];
        for (let i = 0; i < hexString.length; i += 2) {
            const hexPair = hexString.substring(i, i + 2);
            resultArray.push(parseInt(hexPair, 16)); // Convert hex pair to integer
        }
    
        return resultArray;
    };

    const encryptSwitch = () => {
      switch (encryptionType) {
          case 'Midbar-Compatible AES-256 CBC':
          case 'Serpent CBC + Key Incrementation':
          case 'Twofish CBC + Key Incrementation':
              encryptStringWithMidbarAES256CBC();
              break;
          case 'ChaCha20 for strings':
              encryptStringWithChaCha20();
              break;
          case 'ChaCha20 (Chunked) + AES-256 CBC for strings':
          case 'ChaCha20 (Chunked) + Serpent-256 CBC for strings':
          case 'ChaCha20 (Chunked) + Twofish-256 CBC for strings':
              encryptStringWithTwoCiphers();
              break;
          default:
              console.log('Unsupported encryption type');
              break;
      }
  };

  const encryptStringWithChaCha20 = async () => {
    //console.log('Starting encryption process');
  
    // Step 1: Convert input to byte array
    const inputArray = new TextEncoder().encode(input);
    //console.log('Input converted to byte array:', inputArray);
  
    // Step 2: Initialize encrypted data array and generate salt
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    //console.log('Salt generated:', salt);
  
    // Step 3: Derive key
    const iterations = 100;
    //console.log('Deriving key with iterations:', iterations);
    const derivedKey = await deriveKey(key, salt, iterations);
    //console.log('Derived key:', derivedKey);
  
    // Step 4: Split derived key into chacha20key, nonce, and hmacKey
    const chacha20key = derivedKey.slice(0, 32);
    const nonce = derivedKey.slice(32, 40);
    const hmacKey = derivedKey.slice(40);
    //console.log('ChaCha20 key:', chacha20key);
    //console.log('Nonce:', nonce);
    //console.log('HMAC key:', hmacKey);
  
    // Step 5: Compute tag
    //console.log('Computing tag');
    const tag = await computeTagForStringUsingHMACSHA512(hmacKey, inputArray);
    //console.log('Computed tag:', tag);
  
    // Step 6: Combine tag and data
    const tag_and_data = [...tag, ...inputArray];
    //console.log('Combined tag and data:', tag_and_data);
  
    // Step 7: Encrypt using ChaCha20
    //console.log('Initializing ChaCha20');
    const chacha20 = new ChaCha20();
    //console.log('Encrypting data');
    const encryptedBytes = chacha20.encrypt(chacha20key, tag_and_data, nonce);
    //console.log('Encrypted bytes:', encryptedBytes);
  
    // Step 8: Combine salt and encrypted bytes
    const encryptedChunks = new Uint8Array([...salt, ...encryptedBytes]);
    //console.log('Combined encrypted chunks:', encryptedChunks);
  
    // Step 9: Convert to hexadecimal string
    const ciphertext = Array.from(encryptedChunks).map(byte => byte.toString(16).padStart(2, '0')).join('');
    //console.log("Ciphertext:", ciphertext);
    //console.log("Ciphertext length:", ciphertext.length);
  
    // Step 10: Set output
    setOKOutput(ciphertext);
    //console.log('Encryption process completed');
  }

  const derive224BytesUsingHMACSHA512 = useCallback(async (password, salt, iterations) => {
    const derivedKey = await pbkdf2({
      password,
      salt,
      iterations,
      hashLength: 224,
      hashFunction: createSHA512(),
      outputType: 'binary',
    });
    return new Uint8Array(derivedKey);
  }, []);

  const encryptStringWithTwoCiphers = async () => {
    const bytes = new TextEncoder().encode(input);
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    const iterations = 100;
    const chunkSize = 256 * 1024;
    let offset = 0;

    const encryptedChunks = [];
    salt.forEach(byte => encryptedChunks.push(byte));
    const derivedKey = await derive224BytesUsingHMACSHA512(key, salt, iterations);
    let chacha20key = new Uint8Array(derivedKey.slice(0, 64));
    const blockCipherKey = derivedKey.slice(64, 96);
    const hmacKey = derivedKey.slice(96);
    const tag = await computeTagForStringUsingHMACSHA512(hmacKey, bytes);
    const tag_and_data = new Uint8Array([...tag, ...bytes]);
    const encryptedData = new Uint8Array(tag_and_data.length);
    const totalSize = tag_and_data.length;

    while (offset < totalSize) {
      const input = Array.from(chacha20key).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const sha512_output = CryptoJS.SHA512(input).toString();
      const sha512Array = hexStringToArray(sha512_output);
      const byteArray = new Uint8Array(sha512Array);
      const generatedHash = await whirlpool(byteArray);
      chacha20key = new Uint8Array(hexStringToArray(generatedHash));
    
      const chunk = tag_and_data.slice(offset, Math.min(offset + chunkSize, totalSize));
      const nonce = chacha20key.slice(32, 40);
      const chacha20 = new ChaCha20();
      const encryptedChunk = chacha20.encrypt(chacha20key.slice(0, 32), chunk, nonce);
      
      // Push encrypted chunk element by element
      for (let i = 0; i < encryptedChunk.length; i++) {
        encryptedData[offset + i] = encryptedChunk[i];
      }
      
      offset += chunk.length;
    }

    const blockcipher_chunk_size = 16;
    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    //console.log(encryptionType);
    
    let encryptFunction;
    switch (encryptionType) {
      case 'ChaCha20 (Chunked) + AES-256 CBC for strings':
        encryptFunction = encryptAES256ECB;
        break;
      case 'ChaCha20 (Chunked) + Serpent-256 CBC for strings':
        encryptFunction = encryptTwofish256ECB;
        break;
      case 'ChaCha20 (Chunked) + Twofish-256 CBC for strings':
        encryptFunction = encryptSerpent256ECB;
        break;
      default:
        throw new Error('Unsupported encryption type');
    }
    
    const encryptedIV = await encryptFunction(iv, blockCipherKey);
    encryptedIV.forEach(byte => encryptedChunks.push(byte));
    
    let previousCiphertext = iv;
    
    for (let i = 0; i < encryptedData.length; i += blockcipher_chunk_size) {
      let chunk = encryptedData.slice(i, i + blockcipher_chunk_size);
      if (chunk.length < blockcipher_chunk_size) {
        const padding = blockcipher_chunk_size - chunk.length;
        const paddedChunk = new Uint8Array(blockcipher_chunk_size);
        paddedChunk.set(chunk);
        paddedChunk.fill(padding, chunk.length);
        chunk = paddedChunk;
      }
      let xorChunk = chunk.map((byte, index) => byte ^ previousCiphertext[index]);
      let encryptedChunk = await encryptFunction(xorChunk, blockCipherKey);
      encryptedChunk.forEach(byte => encryptedChunks.push(byte));
      previousCiphertext = encryptedChunk;
    }

    const ciphertext = Array.from(encryptedChunks).map(byte => byte.toString(16).padStart(2, '0')).join('');
    setOKOutput(ciphertext);
  }

  const computeTagForStringUsingHMACSHA512 = useCallback(async (key, data) => {
    const hmac = await createHMAC(createSHA512(), key);
    hmac.init();
    hmac.update(data);
    const signature = hmac.digest('binary');
    return new Uint8Array(signature);
  }, []);

  const decryptStringWithChaCha20 = async () => {
      const bytes = new Uint8Array(input.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
      const salt = bytes.slice(0, 32);

      const iterations = 100;
      const derivedKey = await deriveKey(key, salt, iterations);
      const chacha20key = derivedKey.slice(0, 32);
      const nonce = derivedKey.slice(32, 40);
      const hmacKey = derivedKey.slice(40);

      const chacha20 = new ChaCha20();
      const ciphertext = bytes.slice(32);
      const decryptedBytes = chacha20.decrypt(chacha20key, ciphertext, nonce);

      const decryptedTag = decryptedBytes.slice(0, 64);
      const decryptedData = decryptedBytes.slice(64);

      const newTag = await computeTagForStringUsingHMACSHA512(hmacKey, decryptedData);
      
      let integrityFailed = false;
      for (let i = 0; i < 64; i++) {
          if (decryptedTag[i] !== newTag[i]) {
              integrityFailed = true;
              break;
          }
      }

      if (integrityFailed) {
        setErrorOutput(`Error: Failed to verify the integrity/authenticity of the decrypted data.\nDecrypted Data:\n${bytesToAscii(decryptedData)}`);
        showDisappearingSpanNotification('Failed to verify the integrity/authenticity of the decrypted data.', 10000, true);
      } else {
        setOKOutput(bytesToAscii(decryptedData));
        showDisappearingSpanNotification('Data decrypted successfully!', 4000, false);
      }

  };

  function pkcs7PaddingConsumed(data) {
    let allTen = true;
    for (let i = 0; i < 16; i++) {
      if (data[i] !== 0x10) {
        allTen = false;
        break;
      }
    }
    if (allTen) {
      return 16;
    }
    const paddingValue = data[15];
    if (paddingValue < 1 || paddingValue > 16) {
      return 0;
    }
    for (let i = 1; i <= paddingValue; i++) {
      if (data[16 - i] !== paddingValue) {
        return 0;
      }
    }
    return paddingValue;
  }

  const decryptStringWithTwoCiphers = async () => {
    const bytes = new Uint8Array(input.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const salt = bytes.slice(0, 32);
    const iterations = 100;
    const chunkSize = 16;
    const derivedKey = await derive224BytesUsingHMACSHA512(key, salt, iterations);
    let chacha20key = new Uint8Array(derivedKey.slice(0, 64));
    const blockCipherKey = derivedKey.slice(64, 96);
    const hmacKey = derivedKey.slice(96);
  
    let decryptFunction;
    switch (encryptionType) {
      case 'ChaCha20 (Chunked) + AES-256 CBC for strings':
        decryptFunction = decryptAES256ECB;
        break;
      case 'ChaCha20 (Chunked) + Serpent-256 CBC for strings':
        decryptFunction = decryptTwofish256ECB;
        break;
      case 'ChaCha20 (Chunked) + Twofish-256 CBC for strings':
        decryptFunction = decryptSerpent256ECB;
        break;
      default:
        throw new Error('Unsupported encryption type');
    }
  
    const extractedIV = bytes.slice(32, 48);
    const decryptedIV = await decryptFunction(extractedIV, blockCipherKey);
    let previousCiphertext = decryptedIV;
    const decryptedData = [];
    const decryptedDataForWrite = [];
    let dataLengthNoLC = bytes.length - chunkSize;
    for (let i = 48; i < dataLengthNoLC; i += chunkSize) {
      let chunk = bytes.slice(i, i + chunkSize);
      let decryptedChunk = await decryptFunction(chunk, blockCipherKey);
      let xorChunk = decryptedChunk.map((byte, index) => byte ^ previousCiphertext[index]);
      xorChunk.forEach(byte => decryptedData.push(byte));
      previousCiphertext = chunk;
    }
  
    // Handle padding in the last block
    let encryptedLastBlock = bytes.slice(bytes.length - chunkSize);
    let decryptedLastBlock = await decryptFunction(encryptedLastBlock, blockCipherKey);
    let decryptedLastBlockXORed = decryptedLastBlock.map((byte, index) => byte ^ previousCiphertext[index]);
    let paddingLength = pkcs7PaddingConsumed(decryptedLastBlockXORed);
    let invalidPadding = false;
    if (paddingLength === 0) {
      invalidPadding = true;
    } else if (paddingLength === 16) {
      // Do nothing
    } else {
      let unpaddedLastBlock = decryptedLastBlockXORed.slice(0, 16 - paddingLength);
      unpaddedLastBlock.forEach(byte => decryptedData.push(byte));
    }

    const decryptedDataUint8Array = new Uint8Array(decryptedData);

    const chunkSizeForStreamCipher = 256 * 1024; // 256 KB chunks
    let streamCipherOffset = 0;
    const decryptedTag = new Uint8Array(64);
    const decryptedChunks = new Uint8Array(decryptedDataUint8Array.length - 64);
    let decryptedOffset = 0;
    
    let isFirstChunk = true;
    
    while (streamCipherOffset < decryptedDataUint8Array.length) {
      const input = Array.from(chacha20key).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const sha512_output = CryptoJS.SHA512(input).toString();
      const sha512Array = hexStringToArray(sha512_output);
      const byteArray = new Uint8Array(sha512Array);
      const generatedHash = await whirlpool(byteArray);
      chacha20key = new Uint8Array(hexStringToArray(generatedHash));
    
      const chunk = decryptedDataUint8Array.slice(streamCipherOffset, Math.min(streamCipherOffset + chunkSizeForStreamCipher, decryptedDataUint8Array.length));
      const nonce = chacha20key.slice(32, 40);
      const chacha20 = new ChaCha20();
      const decryptedChunk = chacha20.decrypt(chacha20key.slice(0, 32), chunk, nonce);
    
      if (isFirstChunk) {
        decryptedTag.set(decryptedChunk.slice(0, 64));
        decryptedChunks.set(decryptedChunk.slice(64), 0);
        decryptedOffset = decryptedChunk.length - 64;
        isFirstChunk = false;
      } else {
        decryptedChunks.set(decryptedChunk, decryptedOffset);
        decryptedOffset += decryptedChunk.length;
      }
    
      streamCipherOffset += chunk.length;
    }
    
    const decryptedWithStreamCipher = decryptedChunks.slice(0, decryptedOffset);
    const newTag = await computeTagForStringUsingHMACSHA512(hmacKey, decryptedWithStreamCipher);
    let integrityFailed = false;
    for (let i = 0; i < 64; i++) {
      if (decryptedTag[i] !== newTag[i]) {
        integrityFailed = true;
        break;
      }
    }

    if (integrityFailed) {
      setErrorOutput(`Error: Failed to verify the integrity/authenticity of the decrypted data.\nDecrypted Data:\n${bytesToAscii(decryptedWithStreamCipher)}`);
      showDisappearingSpanNotification('Failed to verify the integrity/authenticity of the decrypted data.', 10000, true);
    } else {
      setOKOutput(bytesToAscii(decryptedWithStreamCipher));
      showDisappearingSpanNotification('Data decrypted successfully!', 4000, false);
    }

};
  
  function bytesToAscii(bytes) {
    return Array.from(bytes).map(byte => {
      if (byte >= 32 && byte <= 126) {
        return String.fromCharCode(byte);
      } else {
        return '.';
      }
    }).join('');
  };


  const decryptSwitch = () => {
      switch (encryptionType) {
          case 'Midbar-Compatible AES-256 CBC':
          case 'Serpent CBC + Key Incrementation':
          case 'Twofish CBC + Key Incrementation':
              decryptStringWithMidbarAES256CBC();
              break;
          case 'ChaCha20 for strings':
              decryptStringWithChaCha20();
              break;
          case 'ChaCha20 (Chunked) + AES-256 CBC for strings':
          case 'ChaCha20 (Chunked) + Serpent-256 CBC for strings':
          case 'ChaCha20 (Chunked) + Twofish-256 CBC for strings':
              decryptStringWithTwoCiphers();
              break;
          default:
              console.log('Unsupported decryption type');
              break;
      }
  };

    const encryptStringWithMidbarAES256CBC = () => {
        const chunkSize = 16;
        const encryptedChunks = [];
        const sha512HashString = CryptoJS.SHA512(key).toString();
        const sha512Array = hexStringToArray(sha512HashString);
        //console.log("SHA-512 Array length:", sha512Array.length);
        
        let rightHalf = sha512Array.slice(sha512Array.length / 2);
        //console.log("AES key:", Array.from(rightHalf).map(b => b.toString(16).padStart(2, '0')).join(''));
        
        const leftHalfForHMAC = sha512HashString.slice(0, sha512HashString.length / 2);
        const leftHalfWordArray = CryptoJS.enc.Hex.parse(leftHalfForHMAC);
        const hmacString = CryptoJS.HmacSHA256(input, leftHalfWordArray).toString();
        
        const iv = new Uint8Array(16);
        window.crypto.getRandomValues(iv);
        //console.log("IV:", Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''));
        let aesKeyForIV = new Uint8Array(32);
        aesKeyForIV.set(rightHalf);

        let encryptFunction;
        switch (encryptionType) {
          case 'Midbar-Compatible AES-256 CBC':
            encryptFunction = encryptAES256ECB;
            break;
          case 'Serpent CBC + Key Incrementation':
            encryptFunction = encryptSerpent256ECB;
            break;
          case 'Twofish CBC + Key Incrementation':
            encryptFunction = encryptTwofish256ECB;
            break;
          default:
            throw new Error('Unsupported encryption type');
        }
    
        // Encrypt IV
        const encryptedIV = encryptFunction(iv, aesKeyForIV);
        encryptedIV.forEach(byte => encryptedChunks.push(byte));
        rightHalf = incrAesKey(rightHalf);
        //console.log("Encrypted IV:", Array.from(encryptedChunks).map(b => b.toString(16).padStart(2, '0')).join(' '));
    
        let previousCiphertext = iv;
    
        // Prepare data for encryption (HMAC + input)
        const hmacArray = hexStringToArray(hmacString);
        const inputArray = new TextEncoder().encode(input);
        const dataToEncrypt = new Uint8Array([...hmacArray, ...inputArray]);
    
        for (let i = 0; i < dataToEncrypt.length; i += chunkSize) {
            let chunk = dataToEncrypt.slice(i, i + chunkSize);    
            // Pad the last chunk if necessary
            if (chunk.length < chunkSize) {
                const padding = chunkSize - chunk.length;
                chunk = new Uint8Array([...chunk, ...new Array(padding).fill(0x00)]);
            }
            
            //console.log(`Chunk ${i/chunkSize}:`, Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' '));
    
            let xorChunk = chunk.map((byte, index) => byte ^ previousCiphertext[index]);
            //console.log("After XOR with previousCiphertext:", Array.from(xorChunk).map(b => b.toString(16).padStart(2, '0')).join(' '));
    
            let encryptedChunk = encryptFunction(xorChunk, rightHalf);
            //console.log("After AES-256-ECB encryption:", Array.from(encryptedChunk).map(b => b.toString(16).padStart(2, '0')).join(' '));
    
            encryptedChunk.forEach(byte => encryptedChunks.push(byte));
    
            previousCiphertext = encryptedChunk;
            rightHalf = incrAesKey(rightHalf);
        }
    
        const ciphertext = Array.from(encryptedChunks).map(byte => byte.toString(16).padStart(2, '0')).join('');
        //console.log("Ciphertext length:", ciphertext.length);
        
        setOKOutput(ciphertext);
    };

    const decryptStringWithMidbarAES256CBC = () => {
        
        const chunkSize = 16;
        const encryptedChunks = [];
        const sha512HashString = CryptoJS.SHA512(key).toString();
        const sha512Array = hexStringToArray(sha512HashString);
        //console.log("SHA-512 Array length:", sha512Array.length);
        if (input.length < 96){
            setErrorOutput("Error: Insufficient ciphertext length");
        }
        else{
            try {
                const ciphertextArray = new Uint8Array(hexStringToArray(input));
                
                let rightHalf = sha512Array.slice(sha512Array.length / 2);
                let aesKeyForIV = new Uint8Array(32);
                aesKeyForIV.set(rightHalf);

                let decryptFunction;
                switch (encryptionType) {
                  case 'Midbar-Compatible AES-256 CBC':
                    decryptFunction = decryptAES256ECB;
                    break;
                  case 'Serpent CBC + Key Incrementation':
                    decryptFunction = decryptSerpent256ECB;
                    break;
                  case 'Twofish CBC + Key Incrementation':
                    decryptFunction = decryptTwofish256ECB;
                    break;
                  default:
                    throw new Error('Unsupported encryption type');
                }
            
                const decryptedIV = decryptFunction(ciphertextArray.slice(0, 16), aesKeyForIV);
                const decryptedTag = [];
                const decryptedData = [];
                //console.log("Decrypted IV:", Array.from(decryptedIV).map(b => b.toString(16).padStart(2, '0')).join(' '));
                rightHalf = incrAesKey(rightHalf);

                let previousCiphertext = decryptedIV;

                for (let i = chunkSize; i < ciphertextArray.length; i += chunkSize) {
                    let chunk = new Uint8Array(ciphertextArray.slice(i, i + chunkSize));    
                    // Pad the last chunk if necessary
                    
                    //console.log(`Chunk ${i/chunkSize}:`, Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' '));
            
                    let decryptedChunk = decryptFunction(chunk, rightHalf);
                    //console.log("After AES-256-ECB decryption:", Array.from(decryptedChunk).map(b => b.toString(16).padStart(2, '0')).join(' '));
        
                    let xorChunk = decryptedChunk.map((byte, index) => byte ^ previousCiphertext[index]);

                    if (i === chunkSize || i === chunkSize * 2) {
                        xorChunk.forEach(byte => decryptedTag.push(byte));
                    }
                    else{
                        xorChunk.forEach(byte => decryptedData.push(byte));
                    }
            
                    previousCiphertext = chunk;
                    rightHalf = incrAesKey(rightHalf);
                }

                let decrDataStr = '';
  
                for (let i = 0; i < decryptedData.length; i++) {
                  if (decryptedData[i] > 0) {
                    decrDataStr += String.fromCharCode(decryptedData[i]);
                  }
                }

                const leftHalfForHMAC = sha512HashString.slice(0, sha512HashString.length / 2);
                const leftHalfWordArray = CryptoJS.enc.Hex.parse(leftHalfForHMAC);
                const hmacString = CryptoJS.HmacSHA256(decrDataStr, leftHalfWordArray).toString();
                const hmacArray = hexStringToArray(hmacString);

                let isMatch = true;
                for (let i = 0; i < decryptedTag.length; i++) {
                    if (decryptedTag[i] !== hmacArray[i]) {
                        isMatch = false;
                        break;
                    }
                }

                if (isMatch) {
                    setOKOutput(decrDataStr);
                    showDisappearingSpanNotification('Data decrypted successfully!', 4000, false);
                } else {
                    setErrorOutput(`Error: Failed to verify the integrity/authenticity of the decrypted data.\nDecrypted Data:\n${decrDataStr}`);
                    showDisappearingSpanNotification('Failed to verify the integrity/authenticity of the decrypted data.', 10000, true);
                }

            } catch (error) {
                setErrorOutput(error);
            }
        }
    };

    const getTitle = () => {
      switch (encryptionType) {
        case 'Midbar-Compatible AES-256 CBC':
          return (
            <>
              <h2>Midbar-Compatible</h2>
              <h2>AES-256 CBC</h2>
            </>
          );
        case 'Serpent CBC + Key Incrementation':
          return (
            <>
              <h2>Serpent CBC with</h2>
              <h2>Key Incrementation</h2>
            </>
          );
        case 'Twofish CBC + Key Incrementation':
          return (
            <>
              <h2>Twofish CBC with</h2>
              <h2>Key Incrementation</h2>
            </>
          );
        case 'ChaCha20 for strings':
          return (
            <>
              <h2>ChaCha20</h2>
              <h2>with HMAC-SHA512</h2>
            </>
          );
        case 'ChaCha20 (Chunked) + AES-256 CBC for strings':
          return (
            <>
              <h2>ChaCha20 (Chunked)</h2>
              <h2>with AES-256 CBC</h2>
            </>
          );
        case 'ChaCha20 (Chunked) + Serpent-256 CBC for strings':
          return (
            <>
              <h2>ChaCha20 (Chunked)</h2>
              <h2>with Serpent-256 CBC</h2>
            </>
          );
        case 'ChaCha20 (Chunked) + Twofish-256 CBC for strings':
          return (
            <>
              <h2>ChaCha20 (Chunked)</h2>
              <h2>with Twofish-256 CBC</h2>
            </>
          );
        default:
          return <h2>Unknown Encryption Type</h2>;
      }
    };

      const getPhotoCredit = () => {
        switch (encryptionType) {
          case 'Midbar-Compatible AES-256 CBC':
            return (
              <div className="photo-credit">
                Photo by <a href="https://unsplash.com/@morganpetroskiphoto?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Morgan Petroski</a> on <a href="https://unsplash.com/photos/castle-amusement-park-Ju_epyz921s?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Unsplash</a>
              </div>
            );
          case 'Serpent CBC + Key Incrementation':
            return (
                <div className="photo-credit">
                  Photo by <a href="https://unsplash.com/@slavasfotos?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Slava Keyzman</a> on <a href="https://unsplash.com/photos/cars-on-road-near-high-rise-buildings-during-daytime-AxpiddAYfg8?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Unsplash</a>
                </div>
              );
          case 'Twofish CBC + Key Incrementation':
            return (
              <div className="photo-credit">
                Photo by <a href="https://unsplash.com/@farmtrue?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">R K</a> on <a href="https://unsplash.com/photos/aerial-view-of-city-buildings-during-daytime-lFtdsMzJlGk?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Unsplash</a>
              </div>
            );
          case 'ChaCha20 for strings':
            return (
              <div className="photo-credit">
                Photo by <a href="https://www.pexels.com/@v-h-1454055/" target="_blank" rel="noopener noreferrer">V H</a> on <a href="https://www.pexels.com/photo/marina-bay-sans-singapore-2804038/" target="_blank" rel="noopener noreferrer">Pexels</a>
              </div>
            );
          case 'ChaCha20 (Chunked) + AES-256 CBC for strings':
            return (
              <div className="photo-credit">
                Photo by <a href="https://unsplash.com/@shaipal?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Shai Pal</a> on <a href="https://unsplash.com/photos/a-city-with-tall-buildings-tNklhdD_D9o?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Unsplash</a>
              </div>
            );
          case 'ChaCha20 (Chunked) + Serpent-256 CBC for strings':
            return (
              <div className="photo-credit">
                Photo by <a href="https://unsplash.com/@jakobnoahrosen?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Jakob Rosen</a> on <a href="https://unsplash.com/photos/city-skyline-during-night-time-7C00d3z3ssU?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Unsplash</a>
              </div>
            );
          case 'ChaCha20 (Chunked) + Twofish-256 CBC for strings':
            return (
              <div className="photo-credit">
                Photo by <a href="https://unsplash.com/@m_camper?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Micah Camper</a> on <a href="https://unsplash.com/photos/a-city-with-tall-buildings--9PsvIEPZP4?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash" target="_blank" rel="noopener noreferrer">Unsplash</a>
              </div>
            );
          default:
            return null;
          }
      };
    
      const getBackgroundClass = () => {
        switch (encryptionType) {
          case 'Midbar-Compatible AES-256 CBC':
            return 'midbar-compatible-aes-256-cbc';
          case 'Serpent CBC + Key Incrementation':
            return 'serpent-cbc-key-incrementation';
          case 'Twofish CBC + Key Incrementation':
            return 'twofish-cbc-key-incrementation';
          case 'ChaCha20 for strings':
            return 'chacha20-for-strings';
          case 'ChaCha20 (Chunked) + AES-256 CBC for strings':
            return 'chacha20-chunked-aes-256-cbc-strings';
          case 'ChaCha20 (Chunked) + Serpent-256 CBC for strings':
            return 'chacha20-chunked-serpent-256-cbc-strings';
          case 'ChaCha20 (Chunked) + Twofish-256 CBC for strings':
            return 'chacha20-chunked-twofish-256-cbc-strings';
          default:
            return '';
        }
      };

    const handleClear = () => {
        setInput('');
        setKey('');
        setOKOutput('');
    };

    return (
        <div className="container">
            <div className="session">
            <div className={`left ${getBackgroundClass()}`}>
                {getPhotoCredit()}
            </div>
                <div className="right">
                    <div className="right-inner">
                        {getTitle()}
                        <div className="form-group">
                            <label htmlFor="input">Input</label>
                            <input
                                type="text"
                                id="input"
                                name="input"
                                placeholder="Input goes here"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                            />
                        </div>
                        <div className="form-group">
                            <label htmlFor="key">Key</label>
                            <div className="input-container">
                                <input
                                type={showKey ? "text" : "password"}
                                id="key"
                                name="key"
                                placeholder="Enter the key here"
                                value={key}
                                onChange={(e) => setKey(e.target.value)}
                                />
                                <button 
                                type="button" 
                                className="eye-button" 
                                onClick={() => setShowKey(!showKey)}
                                >
                                {showKey ? '🌕' : '🌑'}
                                </button>
                            </div>
                        </div>
                        <div className="form-group">
                            <label htmlFor="output">Output</label>
                            <textarea
                                id="output"
                                name="output"
                                readOnly
                                placeholder="Output will appear here"
                                value={output}
                            />
                        </div>
                        <div className="button-container">
                            <button type="button" className="encrypt" onClick={encryptSwitch}>Encrypt</button>
                            <button type="button" className="decrypt" onClick={decryptSwitch}>Decrypt</button>
                            <button type="button" className="clear" onClick={handleClear}>Clear</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default MidbarCompatibleAES256CBC;