import React, { useState, useCallback, useEffect, useRef  } from 'react';
import './FileEncryptionForm.css';
import { encryptAES256ECB, decryptAES256ECB } from '../cryptographicPrimitives/aes';
import { encryptTwofish256ECB, decryptTwofish256ECB } from '../cryptographicPrimitives/twofish';
import { encryptSerpent256ECB, decryptSerpent256ECB } from '../cryptographicPrimitives/serpent';
import { showDisappearingSpanNotification } from '../Notifications/spanNotification';
import '../Notifications/spanNotification.css';
import { pbkdf2, createSHA512, createHMAC, whirlpool } from 'hash-wasm';
import { ChaCha20 } from 'mipher';
import CryptoJS from 'crypto-js';

const FileEncryptionForm = ({ encryptionType }) => {
  const [key, setKey] = useState('');
  const [iterations, setIterations] = useState('');
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [showKey, setShowKey] = useState(false);
  const [showIterations, setShowIterations] = useState(false);
  const [isKeyHidden, setIsKeyHidden] = useState(false);
  const [isIterationsHidden, setIsIterationsHidden] = useState(false);
  const [showPopup, setShowPopup] = useState(false);
  const [showProcessingPopup, setShowProcessingPopup] = useState(false);
  const [processingStep, setProcessingStep] = useState('');
  const [processingProgress, setProcessingProgress] = useState(0);
  const [currentFileName, setCurrentFileName] = useState('');
  const [downloadUrl, setDownloadUrl] = useState('');
  const [downloadFileName, setDownloadFileName] = useState('');
  const [showNextButton, setShowNextButton] = useState(false);
  const [showDownloadPopup, setShowDownloadPopup] = useState(false);

  const handleFileSelect = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    input.onchange = (event) => {
      const files = Array.from(event.target.files);
      const selectedFiles = files
        .filter(file => file.size > 0)
        .map(file => ({
          name: file.name,
          size: (file.size / (1024 * 1024)).toFixed(2),
          file: file
        }));
      setSelectedFiles(selectedFiles);
    };
    input.click();
  };

  const derive96BytesUsingHMACSHA512 = useCallback(async (password, salt, iterations) => {
    setProcessingStep('Deriving key using PBKDF2-SHA512. The page might freeze or become unresponsive during the process.');
    await new Promise(resolve => setTimeout(resolve, 50));
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

  const derive192BytesUsingHMACSHA512 = useCallback(async (password, salt, iterations) => {
    setProcessingStep('Deriving key using PBKDF2-SHA512. The page might freeze or become unresponsive during the process.');
    await new Promise(resolve => setTimeout(resolve, 50));
    const derivedKey = await pbkdf2({
      password,
      salt,
      iterations,
      hashLength: 192,
      hashFunction: createSHA512(),
      outputType: 'binary',
    });
    return new Uint8Array(derivedKey);
  }, []);

  const derive224BytesUsingHMACSHA512 = useCallback(async (password, salt, iterations) => {
    setProcessingStep('Deriving key using PBKDF2-SHA512. The page might freeze or become unresponsive during the process.');
    await new Promise(resolve => setTimeout(resolve, 50));
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
  
  const computeTagForFileUsingHMACSHA512 = useCallback(async (key, data) => {
    toggleProgressAnimation(false);
    setProcessingStep('Computing tag for file using HMAC-SHA512');
    const chunkSize = 256 * 1024; // 256 KB chunks
    let offset = 0;
    const hmac = await createHMAC(createSHA512(), key);
    hmac.init();
  
    async function updateProgressWithDelay(progress) {
      setProcessingProgress(progress);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  
    while (offset < data.length) {
      const chunk = data.slice(offset, Math.min(offset + chunkSize, data.length));
      hmac.update(chunk);
      offset += chunk.length;
  
      const progress = (offset / data.length) * 100;
      await updateProgressWithDelay(progress);
    }
    setProcessingProgress(100);
    setProcessingStep('Finalizing tag computation');
    await new Promise(resolve => setTimeout(resolve, 50));
    toggleProgressAnimation(true);
  
    const signature = hmac.digest('binary');
    return new Uint8Array(signature);
  }, []);

  const generateRandomKey = () => {
    const length = Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / (2**32) * (64 - 40 + 1)) + 40;
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    const randomValues = new Uint32Array(length);
    crypto.getRandomValues(randomValues);
    let newKey = "";
    for (let i = 0; i < length; i++) {
      const randomIndex = randomValues[i] % charset.length;
      newKey += charset[randomIndex];
    }
    const newIterations = Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / (2**32) * (2500000 - 500000 + 1)) + 500000;
    setKey(newKey);
    setIterations(newIterations.toString());
    setShowKey(true);
    setShowIterations(true);
    setTimeout(() => {
      setIsKeyHidden(true);
      setIsIterationsHidden(true);
    }, 4500);
    setTimeout(() => {
      setShowKey(false);
      setShowIterations(false);
      setIsKeyHidden(false);
      setIsIterationsHidden(false);
    }, 5000);
  };

  const removeFile = (fileToRemove) => {
    setSelectedFiles(selectedFiles.filter(file => file.name !== fileToRemove.name));
  };

  const viewSelectedFiles = () => {
    setShowPopup(true);
  };

  const processFiles = async (isEncryption) => {
    setShowDownloadPopup(false);
    setShowNextButton(false);
    if (selectedFiles.length === 0) {
      showDisappearingSpanNotification('No files selected', 4000, true);
      return;
    }
    if (!key) {
      showDisappearingSpanNotification('Key is empty', 4000, true);
      return;
    }
    const iterationsValue = parseInt(iterations);
    if (isNaN(iterationsValue) || iterationsValue <= 0) {
      showDisappearingSpanNotification('Invalid iterations', 4000, true);
      return;
    }
  
    setShowProcessingPopup(true);
  
    for (const fileInfo of selectedFiles) {
      setCurrentFileName(fileInfo.name);
      setProcessingProgress(0);
      setProcessingStep('Reading file');
      setShowDownloadPopup(false);
  
      try {
        const fileBytes = await readFileByChunks(fileInfo.file);
        switch (encryptionType) {
          case 'AES-256 CBC':
          case 'Serpent-256 CBC':
          case 'Twofish-256 CBC':
            if (isEncryption) {
              await encryptReadFileWithSingleBlockCipher(fileBytes, key, iterationsValue, fileInfo.name);
            } else {
              await decryptReadFileWithSingleBlockCipher(fileBytes, key, iterationsValue, fileInfo.name);
            }
            break;
          
          case 'ChaCha20':
            if (isEncryption) {
              await encryptFileWithChaCha20(fileBytes, key, iterationsValue, fileInfo.name);
            } else {
              await decryptFileWithChaCha20(fileBytes, key, iterationsValue, fileInfo.name);
            }
            break;

          case 'ChaCha20 (Chunked)':
            if (isEncryption) {
              await encryptFileWithChaCha20Chunked(fileBytes, key, iterationsValue, fileInfo.name);
            } else {
              await decryptFileWithChaCha20Chunked(fileBytes, key, iterationsValue, fileInfo.name);
            }
            break;
          
          case 'ChaCha20 (Chunked) + AES-256 CBC':
          case 'ChaCha20 (Chunked) + Serpent-256 CBC':
          case 'ChaCha20 (Chunked) + Twofish-256 CBC':
            if (isEncryption) {
              await encryptFileWithTwoCiphersCBC(fileBytes, key, iterationsValue, fileInfo.name);
            } else {
              await decryptFileWithTwoCiphersCBC(fileBytes, key, iterationsValue, fileInfo.name);
            }
            break;

          default:
            throw new Error('Unsupported encryption type');
        }
        await waitForNextFile();
      } catch (error) {
        console.error(`Error processing file ${fileInfo.name}:`, error);
        showDisappearingSpanNotification(`Error processing ${fileInfo.name}`, 4000, true);
      }
    }
  
    setShowProcessingPopup(false);
  };
  
  const readFileByChunks = async (file) => {
    const chunkSize = 1024 * 1024;
    const reader = new FileReader();
    let offset = 0;
    const totalSize = file.size;
    const fileBytes = new Uint8Array(totalSize);
    let isFirstUpdate = true;
  
    function readChunk(blob) {
      return new Promise((resolve, reject) => {
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = (e) => reject(e.target.error);
        reader.readAsArrayBuffer(blob);
      });
    }
  
    async function updateProgressWithDelay(progress) {
      if (isFirstUpdate) {
        toggleProgressAnimation(false);
        isFirstUpdate = false;
      }
      setProcessingProgress(progress);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  
    while (offset < totalSize) {
      const chunk = file.slice(offset, offset + chunkSize);
      const arrayBuffer = await readChunk(chunk);
      const uint8Array = new Uint8Array(arrayBuffer);
      fileBytes.set(uint8Array, offset);
      offset += uint8Array.length;
      const progress = ((offset / totalSize) * 100).toFixed(2);
      await updateProgressWithDelay(parseFloat(progress));
    }
  
    return fileBytes;
  };
  
  const encryptFiles = () => processFiles(true);
  const decryptFiles = () => processFiles(false);

  const waitForNextFile = () => {
    return new Promise(resolve => {
      const nextButton = document.getElementById('file-processing-popup-next-button');
      const downloadButton = document.getElementById('file-processing-popup-download-button');
      nextButton.style.display = 'block';
      downloadButton.style.display = 'block';
      nextButton.onclick = () => {
        nextButton.style.display = 'none';
        downloadButton.style.display = 'none';
        resolve();
      };
    });
  };

  const encryptDataWithCBC = async (bytes, blockCipherKey, cipherName) => {
    const chunkSize = 16;
    const encryptedChunks = [];
    const iv = window.crypto.getRandomValues(new Uint8Array(chunkSize));
  
    let encryptFunction;
    switch (cipherName) {
      case 'AES-256':
        encryptFunction = encryptAES256ECB;
        break;
      case 'Twofish-256':
        encryptFunction = encryptTwofish256ECB;
        break;
      case 'Serpent-256':
        encryptFunction = encryptSerpent256ECB;
        break;
      default:
        throw new Error('Unsupported encryption type');
    }
  
    const encryptedIV = await encryptFunction(iv, blockCipherKey);
    encryptedChunks.push(encryptedIV);
  
    let previousCiphertext = iv;
  
    async function updateProgressWithDelay(progress) {
      setProcessingProgress(progress);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  
    for (let i = 0; i < bytes.length; i += chunkSize) {
      let chunk = bytes.slice(i, i + chunkSize);
      if (chunk.length < chunkSize) {
        const padding = chunkSize - chunk.length;
        const paddedChunk = new Uint8Array(chunkSize);
        paddedChunk.set(chunk);
        paddedChunk.fill(padding, chunk.length);
        chunk = paddedChunk;
      }
      let xorChunk = chunk.map((byte, index) => byte ^ previousCiphertext[index]);
      let encryptedChunk = await encryptFunction(xorChunk, blockCipherKey);
      encryptedChunks.push(encryptedChunk);
      previousCiphertext = encryptedChunk;
  
      if (i % 16000 === 0) {
        await updateProgressWithDelay((i / bytes.length) * 100);
      }
    }
    await updateProgressWithDelay(100);
  
    return encryptedChunks;
  };

  const decryptDataWithCBC = async (bytes, blockCipherKey, cipherName) => {
    const chunkSize = 16;
    const decryptedData = [];
  
    let decryptFunction;
    switch (cipherName) {
      case 'AES-256':
        decryptFunction = decryptAES256ECB;
        break;
      case 'Twofish-256':
        decryptFunction = decryptTwofish256ECB;
        break;
      case 'Serpent-256':
        decryptFunction = decryptSerpent256ECB;
        break;
      default:
        throw new Error('Unsupported encryption type');
    }
  
    const extractedIV = bytes.slice(0, chunkSize);
    const decryptedIV = await decryptFunction(extractedIV, blockCipherKey);
    let previousCiphertext = decryptedIV;
  
    async function updateProgressWithDelay(progress) {
      setProcessingProgress(progress);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  
    const dataLengthNoLC = bytes.length - chunkSize;
    for (let i = chunkSize; i < dataLengthNoLC; i += chunkSize) {
      let chunk = bytes.slice(i, i + chunkSize);
      let decryptedChunk = await decryptFunction(chunk, blockCipherKey);
      let xorChunk = decryptedChunk.map((byte, index) => byte ^ previousCiphertext[index]);
      decryptedData.push(...xorChunk);
      previousCiphertext = chunk;
  
      if ((i - chunkSize) % 16000 === 0) {
        await updateProgressWithDelay(((i - chunkSize) / (dataLengthNoLC - chunkSize)) * 100);
      }
    }
  
    // Handle padding in the last block
    let encryptedLastBlock = bytes.slice(bytes.length - chunkSize);
    let decryptedLastBlock = await decryptFunction(encryptedLastBlock, blockCipherKey);
    let decryptedLastBlockXORed = decryptedLastBlock.map((byte, index) => byte ^ previousCiphertext[index]);
    let paddingLength = pkcs7PaddingConsumed(decryptedLastBlockXORed);
    await updateProgressWithDelay(100);
  
    if (paddingLength === 0) {
      throw new Error('Invalid padding');
    } else if (paddingLength < 16) {
      let unpaddedLastBlock = decryptedLastBlockXORed.slice(0, chunkSize - paddingLength);
      decryptedData.push(...unpaddedLastBlock);
    }
  
    return new Uint8Array(decryptedData);
  };

  const encryptReadFileWithSingleBlockCipher = async (bytes, password, iterations, fileName) => {
    const chunkSize = 16;
    const encryptedChunks = [];
  
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    encryptedChunks.push(salt);
    toggleProgressAnimation(true);
    const derivedKey = await derive96BytesUsingHMACSHA512(password, salt, iterations);
    const blockCipherKey = derivedKey.slice(0, 32);
    const hmacKey = derivedKey.slice(32);
  
    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    //console.log(encryptionType);
  
    let encryptFunction;
    switch (encryptionType) {
      case 'AES-256 CBC':
        encryptFunction = encryptAES256ECB;
        break;
      case 'Twofish-256 CBC':
        encryptFunction = encryptTwofish256ECB;
        break;
      case 'Serpent-256 CBC':
        encryptFunction = encryptSerpent256ECB;
        break;
      default:
        throw new Error('Unsupported encryption type');
    }
  
    const encryptedIV = await encryptFunction(iv, blockCipherKey);
    encryptedChunks.push(encryptedIV);
  
    const hmac = await computeTagForFileUsingHMACSHA512(hmacKey, bytes);
    toggleProgressAnimation(false);
  
    setProcessingStep('Encrypting file');
    let previousCiphertext = iv;
    for (let i = 0; i < hmac.length; i += chunkSize) {
      let chunk = hmac.slice(i, i + chunkSize);
      let xorChunk = chunk.map((byte, index) => byte ^ previousCiphertext[index]);
      let encryptedChunk = await encryptFunction(xorChunk, blockCipherKey);
      encryptedChunks.push(encryptedChunk);
      previousCiphertext = encryptedChunk;
    }
  
    async function updateProgressWithDelay(progress) {
      setProcessingProgress(progress);
      // Introduce a small delay to allow the browser to update the UI
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  
    for (let i = 0; i < bytes.length; i += chunkSize) {
      let chunk = bytes.slice(i, i + chunkSize);
      if (chunk.length < chunkSize) {
        const padding = chunkSize - chunk.length;
        const paddedChunk = new Uint8Array(chunkSize);
        paddedChunk.set(chunk);
        paddedChunk.fill(padding, chunk.length);
        chunk = paddedChunk;
      }
      let xorChunk = chunk.map((byte, index) => byte ^ previousCiphertext[index]);
      let encryptedChunk = await encryptFunction(xorChunk, blockCipherKey);
      encryptedChunks.push(encryptedChunk);
      previousCiphertext = encryptedChunk;
  
      if (i % 16000 === 0) {
        await updateProgressWithDelay((i / bytes.length) * 100);
      }
    }
    await updateProgressWithDelay(100);
    setProcessingStep('Encryption done!');
  
    const encryptedFile = new Blob(encryptedChunks);
    const url = URL.createObjectURL(encryptedFile);
    setDownloadUrl(url);
    setDownloadFileName(fileName + '.encr');
    setShowDownloadPopup(true);
    setShowNextButton(true);
  };
  
  const decryptReadFileWithSingleBlockCipher = async (bytes, password, iterations, fileName) => {
    const chunkSize = 16;
  
    if (fileName.endsWith('.encr')) {
      fileName = fileName.slice(0, -5);
    }
  
    const salt = bytes.slice(0, 32);
    toggleProgressAnimation(true);
    const derivedKey = await derive96BytesUsingHMACSHA512(password, salt, iterations);
    const blockCipherKey = derivedKey.slice(0, 32);
    const hmacKey = derivedKey.slice(32);
    toggleProgressAnimation(false);
  
    let decryptFunction;
    switch (encryptionType) {
      case 'AES-256 CBC':
        decryptFunction = decryptAES256ECB;
        break;
      case 'Twofish-256 CBC':
        decryptFunction = decryptTwofish256ECB;
        break;
      case 'Serpent-256 CBC':
        decryptFunction = decryptSerpent256ECB;
        break;
      default:
        throw new Error('Unsupported encryption type');
    }
  
    const extractedIV = bytes.slice(32, 48);
    const decryptedIV = await decryptFunction(extractedIV, blockCipherKey);
  
    setProcessingStep('Decrypting file');
    const decryptedTag = [];
    let previousCiphertext = decryptedIV;
    for (let i = 48; i < 112; i += chunkSize) {
      let chunk = bytes.slice(i, i + chunkSize);
      let decryptedChunk = await decryptFunction(chunk, blockCipherKey);
      let xorChunk = decryptedChunk.map((byte, index) => byte ^ previousCiphertext[index]);
      xorChunk.forEach(byte => decryptedTag.push(byte));
      previousCiphertext = chunk;
    }
  
    async function updateProgressWithDelay(progress) {
      setProcessingProgress(progress);
      // Introduce a small delay to allow the browser to update the UI
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  
    const decryptedData = [];
    const decryptedDataForWrite = [];
    let dataLengthNoLC = bytes.length - chunkSize;
    for (let i = 112; i < dataLengthNoLC; i += chunkSize) {
      let chunk = bytes.slice(i, i + chunkSize);
      let decryptedChunk = await decryptFunction(chunk, blockCipherKey);
      let xorChunk = decryptedChunk.map((byte, index) => byte ^ previousCiphertext[index]);
      xorChunk.forEach(byte => decryptedData.push(byte));
      decryptedDataForWrite.push(xorChunk);
      previousCiphertext = chunk;
  
      if ((i - 112) % 16000 === 0) {
        await updateProgressWithDelay(((i - 112) / (dataLengthNoLC - 112)) * 100);
      }
    }
  
    // Handle padding in the last block
    let encryptedLastBlock = bytes.slice(bytes.length - chunkSize);
    let decryptedLastBlock = await decryptFunction(encryptedLastBlock, blockCipherKey);
    let decryptedLastBlockXORed = decryptedLastBlock.map((byte, index) => byte ^ previousCiphertext[index]);
    let paddingLength = pkcs7PaddingConsumed(decryptedLastBlockXORed);
    await updateProgressWithDelay(100);
    let invalidPadding = false;
    let integrityFailed = false;
    if (paddingLength === 0) {
      invalidPadding = true;
    } else if (paddingLength === 16) {
      // Do nothing
    } else {
      let unpaddedLastBlock = decryptedLastBlockXORed.slice(0, 16 - paddingLength);
      unpaddedLastBlock.forEach(byte => decryptedData.push(byte));
      decryptedDataForWrite.push(unpaddedLastBlock);
    }
    toggleProgressAnimation(true);
    // Verify HMAC
    const computedTag = await computeTagForFileUsingHMACSHA512(hmacKey, new Uint8Array(decryptedData));
    if (!compareUint8Arrays(computedTag, decryptedTag)) {
      integrityFailed = true;
    }

    toggleProgressAnimation(false);
    await updateProgressWithDelay(100);
  
    if (invalidPadding && integrityFailed) {
      setProcessingStep('Decryption errors: invalid padding, integrity/authenticity verification failed');
    } else if (invalidPadding) {
      setProcessingStep('Decryption error: invalid padding');
    } else if (integrityFailed) {
      setProcessingStep('Decryption error: integrity/authenticicty verification failed');
    } else {
      setProcessingStep('File decrypted successfully!');
    }
  
    if (!integrityFailed) {
      const decryptedFile = new Blob(decryptedDataForWrite);
      const url = URL.createObjectURL(decryptedFile);
      setDownloadUrl(url);
      setDownloadFileName(fileName);
      setShowDownloadPopup(true);
    }
  };

  function compareUint8Arrays(a, b) {
    if (a.length !== b.length) return false;
    return a.every((val, index) => val === b[index]);
  }

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

  const encryptFileWithChaCha20 = async (bytes, password, iterations, fileName) => {
    const encryptedData = [];
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    encryptedData.push(salt);
    toggleProgressAnimation(true);
    const derivedKey = await derive96BytesUsingHMACSHA512(password, salt, iterations);
    const chacha20key = derivedKey.slice(0, 32);
    const nonce = derivedKey.slice(32, 40);
    const hmacKey = derivedKey.slice(40);
  
    const tag = await computeTagForFileUsingHMACSHA512(hmacKey, bytes);
  
    setProcessingStep('Preparing file for encryption');
    const tag_and_data = [...tag, ...bytes];
  
    async function updateProgressWithDelay(progress) {
      setProcessingProgress(progress);
      // Introduce a small delay to allow the browser to update the UI
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    setProcessingStep('Encrypting file');
    const chacha20 = new ChaCha20();

    const encryptedBytes = chacha20.encrypt(chacha20key, tag_and_data, nonce);
    encryptedData.push(encryptedBytes);
    toggleProgressAnimation(false);
    setProcessingStep('Encryption done!');
  
    const encryptedFile = new Blob(encryptedData);
    const url = URL.createObjectURL(encryptedFile);
    setDownloadUrl(url);
    setDownloadFileName(fileName + '.encr');
    setShowDownloadPopup(true);
    setShowNextButton(true);
  };
  
  const decryptFileWithChaCha20 = async (bytes, password, iterations, fileName) => {
    if (fileName.endsWith('.encr')) {
      fileName = fileName.slice(0, -5);
    }
  
    const salt = bytes.slice(0, 32);
    toggleProgressAnimation(true);
    const derivedKey = await derive96BytesUsingHMACSHA512(password, salt, iterations);
    const chacha20key = derivedKey.slice(0, 32);
    const nonce = derivedKey.slice(32, 40);
    const hmacKey = derivedKey.slice(40);
    toggleProgressAnimation(true);
  
    setProcessingStep('Decrypting file');
    const chacha20 = new ChaCha20();
  
    const ciphertext = bytes.slice(32);
    const decryptedBytes = chacha20.decrypt(chacha20key, ciphertext, nonce);
  
    const decryptedTag = decryptedBytes.slice(0, 64);
    const decryptedData = decryptedBytes.slice(64);
  
    setProcessingStep('Verifying file integrity');
    const newTag = await computeTagForFileUsingHMACSHA512(hmacKey, decryptedData);
  
    let integrityFailed = false;
    for (let i = 0; i < 64; i++) {
      if (decryptedTag[i] !== newTag[i]) {
        integrityFailed = true;
        break;
      }
    }
  
    if (integrityFailed) {
      setProcessingStep('Decryption error: integrity/authenticity verification failed');
    } else {
      setProcessingStep('File decrypted successfully!');
    }
  
    if (!integrityFailed) {
      // Prepare decrypted data in 16-byte chunks
      const chunkSize = 16;
      const decryptedChunks = [];
      for (let i = 0; i < decryptedData.length; i += chunkSize) {
        decryptedChunks.push(decryptedData.slice(i, i + chunkSize));
      }
  
      const decryptedFile = new Blob(decryptedChunks, { type: 'application/octet-stream' });
      const url = URL.createObjectURL(decryptedFile);
      setDownloadUrl(url);
      setDownloadFileName(fileName);
      setShowDownloadPopup(true);
    }
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

  const encryptFileWithChaCha20Chunked = async (bytes, password, iterations, fileName) => {
    const chunkSize = 256 * 1024;
    let offset = 0;
    const encryptedData = [];
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    encryptedData.push(salt);
    toggleProgressAnimation(true);
  
    const derivedKey = await derive192BytesUsingHMACSHA512(password, salt, iterations);
    let chacha20key = new Uint8Array(derivedKey.slice(0, 64));
    const hmacKey = derivedKey.slice(64);
  
    const tag = await computeTagForFileUsingHMACSHA512(hmacKey, bytes);
    setProcessingStep('Preparing file for encryption');
    const tag_and_data = new Uint8Array([...tag, ...bytes]);
    setProcessingStep('Encrypting file');
  
    async function updateProgressWithDelay(progress) {
      setProcessingProgress(progress);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  
    toggleProgressAnimation(false);
    const totalSize = tag_and_data.length;
    while (offset < totalSize) {
      const input = Array.from(chacha20key).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const sha512_output = CryptoJS.SHA512(input).toString();
      const sha512Array = hexStringToArray(sha512_output);
      const byteArray = new Uint8Array(sha512Array);
      const generatedHash = await whirlpool(byteArray);
      chacha20key = new Uint8Array(hexStringToArray(generatedHash));
  
      //console.log('Encryption chunk key:', chacha20key);
  
      const chunk = tag_and_data.slice(offset, Math.min(offset + chunkSize, totalSize));
      const nonce = chacha20key.slice(32, 40);
      const chacha20 = new ChaCha20();
      const encryptedChunk = chacha20.encrypt(chacha20key.slice(0, 32), chunk, nonce);
      encryptedData.push(encryptedChunk);
      offset += chunk.length;
  
      const progress = (offset / totalSize) * 100;
      await updateProgressWithDelay(progress);
    }
  
    await updateProgressWithDelay(100);
    setProcessingStep('Encryption done!');
    const encryptedFile = new Blob(encryptedData);
    const url = URL.createObjectURL(encryptedFile);
    setDownloadUrl(url);
    setDownloadFileName(fileName + '.encr');
    setShowDownloadPopup(true);
    setShowNextButton(true);
  };
  
  const decryptFileWithChaCha20Chunked = async (bytes, password, iterations, fileName) => {
    if (fileName.endsWith('.encr')) {
      fileName = fileName.slice(0, -5);
    }
    const salt = bytes.slice(0, 32);
    toggleProgressAnimation(true);
    const derivedKey = await derive192BytesUsingHMACSHA512(password, salt, iterations);
    let chacha20key = new Uint8Array(derivedKey.slice(0, 64));
    const hmacKey = derivedKey.slice(64);
    toggleProgressAnimation(false);
    setProcessingStep('Decrypting file');
    const chunkSize = 256 * 1024; // 256 KB chunks
    let offset = 32;
    const decryptedTag = new Uint8Array(64);
    const decryptedChunks = new Uint8Array(bytes.length - 96);
    let decryptedOffset = 0;
  
    async function updateProgressWithDelay(progress) {
      setProcessingProgress(progress);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  
    let isFirstChunk = true;
  
    while (offset < bytes.length) {
      const input = Array.from(chacha20key).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const sha512_output = CryptoJS.SHA512(input).toString();
      const sha512Array = hexStringToArray(sha512_output);
      const byteArray = new Uint8Array(sha512Array);
      const generatedHash = await whirlpool(byteArray);
      chacha20key = new Uint8Array(hexStringToArray(generatedHash));
  
      const chunk = bytes.slice(offset, Math.min(offset + chunkSize, bytes.length));
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

      offset += chunk.length;
      const progress = (offset / bytes.length) * 100;
      await updateProgressWithDelay(progress);
    }
  
    const decryptedData = decryptedChunks.slice(0, decryptedOffset);
    setProcessingStep('Verifying file integrity');
    const newTag = await computeTagForFileUsingHMACSHA512(hmacKey, decryptedData);
    let integrityFailed = false;
    for (let i = 0; i < 64; i++) {
      if (decryptedTag[i] !== newTag[i]) {
        integrityFailed = true;
        break;
      }
    }
  
    if (integrityFailed) {
      setProcessingStep('Decryption error: integrity/authenticity verification failed');
    } else {
      setProcessingStep('File decrypted successfully!');
    }
  
    if (!integrityFailed) {
      // Prepare decrypted data in 16-byte chunks
      const finalChunkSize = 16;
      const finalDecryptedChunks = [];
      for (let i = 0; i < decryptedData.length; i += finalChunkSize) {
        finalDecryptedChunks.push(decryptedData.slice(i, i + finalChunkSize));
      }
      const decryptedFile = new Blob(finalDecryptedChunks, { type: 'application/octet-stream' });
      const url = URL.createObjectURL(decryptedFile);
      setDownloadUrl(url);
      setDownloadFileName(fileName);
      setShowDownloadPopup(true);
    }
  };

  const encryptFileWithTwoCiphersCBC = async (bytes, password, iterations, fileName) => {
    const chunkSize = 256 * 1024;
    let offset = 0;
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    const encryptedChunks = [];
    
    encryptedChunks.push(salt);
    toggleProgressAnimation(true);
    
    const derivedKey = await derive224BytesUsingHMACSHA512(password, salt, iterations);
    let chacha20key = new Uint8Array(derivedKey.slice(0, 64));
    const blockCipherKey = derivedKey.slice(64, 96);
    const hmacKey = derivedKey.slice(96);
    
    const tag = await computeTagForFileUsingHMACSHA512(hmacKey, bytes);
    setProcessingStep('Preparing file for encryption');
    const tag_and_data = new Uint8Array([...tag, ...bytes]);
    const encryptedData = new Uint8Array(tag_and_data.length);
    setProcessingStep('Step 1/2 - Encrypting file with ChaCha20');
    
    async function updateProgressWithDelay(progress) {
      setProcessingProgress(progress);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    
    toggleProgressAnimation(false);
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
    
      const progress = (offset / totalSize) * 100;
      await updateProgressWithDelay(progress);
    }

    const blockcipher_chunk_size = 16;
    
    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    //console.log(encryptionType);
    
    let encryptFunction;
    switch (encryptionType) {
      case 'ChaCha20 (Chunked) + AES-256 CBC':
        encryptFunction = encryptAES256ECB;
        break;
      case 'ChaCha20 (Chunked) + Twofish-256 CBC':
        encryptFunction = encryptTwofish256ECB;
        break;
      case 'ChaCha20 (Chunked) + Serpent-256 CBC':
        encryptFunction = encryptSerpent256ECB;
        break;
      default:
        throw new Error('Unsupported encryption type');
    }
    
    const encryptedIV = await encryptFunction(iv, blockCipherKey);
    encryptedChunks.push(encryptedIV);
    
    switch (encryptionType) {
      case 'ChaCha20 (Chunked) + AES-256 CBC':
        setProcessingStep('Step 2/2 - Encrypting file with AES-256 CBC');
        break;
      case 'ChaCha20 (Chunked) + Twofish-256 CBC':
        setProcessingStep('Step 2/2 - Encrypting file with Twofish-256 CBC');
        break;
      case 'ChaCha20 (Chunked) + Serpent-256 CBC':
        setProcessingStep('Step 2/2 - Encrypting file with Serpent-256 CBC');
        break;
      default:
        throw new Error('Unsupported encryption type');
    }
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
      encryptedChunks.push(encryptedChunk);
      previousCiphertext = encryptedChunk;
    
      if (i % 16000 === 0) {
        await updateProgressWithDelay((i / encryptedData.length) * 100);
      }
    }
    await updateProgressWithDelay(100);
    setProcessingStep('Encryption done!');
    //console.log(encryptedData);
    const encryptedFile = new Blob(encryptedChunks);
    const url = URL.createObjectURL(encryptedFile);
    setDownloadUrl(url);
    setDownloadFileName(fileName + '.encr');
    setShowDownloadPopup(true);
    setShowNextButton(true);
  };

  const decryptFileWithTwoCiphersCBC = async (bytes, password, iterations, fileName) => {
    const chunkSize = 16;
  
    if (fileName.endsWith('.encr')) {
      fileName = fileName.slice(0, -5);
    }
  
    const salt = bytes.slice(0, 32);
    toggleProgressAnimation(true);
    const derivedKey = await derive224BytesUsingHMACSHA512(password, salt, iterations);
    let chacha20key = new Uint8Array(derivedKey.slice(0, 64));
    const blockCipherKey = derivedKey.slice(64, 96);
    const hmacKey = derivedKey.slice(96);
    toggleProgressAnimation(false);
  
    let decryptFunction;
    switch (encryptionType) {
      case 'ChaCha20 (Chunked) + AES-256 CBC':
        decryptFunction = decryptAES256ECB;
        break;
      case 'ChaCha20 (Chunked) + Twofish-256 CBC':
        decryptFunction = decryptTwofish256ECB;
        break;
      case 'ChaCha20 (Chunked) + Serpent-256 CBC':
        decryptFunction = decryptSerpent256ECB;
        break;
      default:
        throw new Error('Unsupported encryption type');
    }
  
    const extractedIV = bytes.slice(32, 48);
    const decryptedIV = await decryptFunction(extractedIV, blockCipherKey);
    switch (encryptionType) {
      case 'ChaCha20 (Chunked) + AES-256 CBC':
        setProcessingStep('Step 1/2 - Decrypting file with AES-256 CBC');
        break;
      case 'ChaCha20 (Chunked) + Twofish-256 CBC':
        setProcessingStep('Step 1/2 - Decrypting file with Twofish-256 CBC');
        break;
      case 'ChaCha20 (Chunked) + Serpent-256 CBC':
        setProcessingStep('Step 1/2 - Decrypting file with Serpent-256 CBC');
        break;
      default:
        throw new Error('Unsupported encryption type');
    }
    let previousCiphertext = decryptedIV;
  
    async function updateProgressWithDelay(progress) {
      setProcessingProgress(progress);
      // Introduce a small delay to allow the browser to update the UI
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  
    const decryptedData = [];
    const decryptedDataForWrite = [];
    let dataLengthNoLC = bytes.length - chunkSize;
    for (let i = 48; i < dataLengthNoLC; i += chunkSize) {
      let chunk = bytes.slice(i, i + chunkSize);
      let decryptedChunk = await decryptFunction(chunk, blockCipherKey);
      let xorChunk = decryptedChunk.map((byte, index) => byte ^ previousCiphertext[index]);
      xorChunk.forEach(byte => decryptedData.push(byte));
      previousCiphertext = chunk;
  
      if ((i - 112) % 16000 === 0) {
        await updateProgressWithDelay(((i - 112) / (dataLengthNoLC - 112)) * 100);
      }
    }
  
    // Handle padding in the last block
    let encryptedLastBlock = bytes.slice(bytes.length - chunkSize);
    let decryptedLastBlock = await decryptFunction(encryptedLastBlock, blockCipherKey);
    let decryptedLastBlockXORed = decryptedLastBlock.map((byte, index) => byte ^ previousCiphertext[index]);
    let paddingLength = pkcs7PaddingConsumed(decryptedLastBlockXORed);
    await updateProgressWithDelay(100);
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

    toggleProgressAnimation(false);
    setProcessingStep('Step 2/2 - Decrypting file with ChaCha20');
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
      const progress = (streamCipherOffset / decryptedDataUint8Array.length) * 100;
      await updateProgressWithDelay(progress);
    }
    
    const decryptedWithStreamCipher = decryptedChunks.slice(0, decryptedOffset);
    setProcessingStep('Verifying file integrity');
    const newTag = await computeTagForFileUsingHMACSHA512(hmacKey, decryptedWithStreamCipher);
    let integrityFailed = false;
    for (let i = 0; i < 64; i++) {
      if (decryptedTag[i] !== newTag[i]) {
        integrityFailed = true;
        break;
      }
    }
    
    if (invalidPadding && integrityFailed) {
      setProcessingStep('Decryption errors: invalid padding, integrity/authenticity verification failed');
    } else if (invalidPadding) {
      setProcessingStep('Decryption error: invalid padding');
    } else if (integrityFailed) {
      setProcessingStep('Decryption error: integrity/authenticity verification failed');
    } else {
      setProcessingStep('File decrypted successfully!');
    }
    
    if (!integrityFailed) {
      // Prepare decrypted data in 16-byte chunks
      const finalChunkSize = 16;
      const finalDecryptedChunks = [];
      for (let i = 0; i < decryptedWithStreamCipher.length; i += finalChunkSize) {
        finalDecryptedChunks.push(decryptedWithStreamCipher.slice(i, i + finalChunkSize));
      }
      const decryptedFile = new Blob(finalDecryptedChunks, { type: 'application/octet-stream' });
      const url = URL.createObjectURL(decryptedFile);
      setDownloadUrl(url);
      setDownloadFileName(fileName);
      setShowDownloadPopup(true);
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
  }

  const progressContainerRef = useRef(null);

  const toggleProgressAnimation = (isAnimating) => {
    const container = progressContainerRef.current;
    if (!container) return;
  
    if (isAnimating) {
      container.innerHTML = `
        <style>
          @keyframes moveBar {
            0%, 100% { left: 0; }
            50% { left: 80%; }
          }
          @keyframes shiftColor {
            0% { background-position: 0% 50%; }
            100% { background-position: 100% 50%; }
          }
          .animated-bar {
            width: 20%;
            height: 100%;
            background: linear-gradient(90deg, 
              rgba(121, 69, 197, 0.7), 
              rgba(0, 123, 255, 0.7), 
              rgba(121, 69, 197, 0.7), 
              rgba(0, 123, 255, 0.7)
            );
            background-size: 300% 100%;
            box-shadow: 0 3px 3px -5px rgba(121, 69, 197, 0.7), 0 2px 5px rgba(0, 123, 255, 0.7);
            position: absolute;
            top: 0;
            left: 0;
            border-radius: 15px;
            animation: 
              moveBar 2s linear infinite,
              shiftColor 4s linear infinite;
          }
        </style>
        <div class="animated-bar"></div>
      `;
    } else {
      container.innerHTML = `
        <style>
          .file-processing-popup-progress-done {
            background: linear-gradient(to left, rgba(121, 69, 197, 0.7), rgba(0, 123, 255, 0.7));
            box-shadow: 0 3px 3px -5px rgba(121, 69, 197, 0.7), 0 2px 5px rgba(0, 123, 255, 0.7);
            color: #FFFFFF;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100%;
            width: ${processingProgress}%;
            opacity: 1;
            border-radius: 15px;
          }
        </style>
        <div class="file-processing-popup-progress-done">
          ${processingProgress.toFixed(2)}%
        </div>
      `;
    }
  };
  
  useEffect(() => {
    if (showProcessingPopup) {
      toggleProgressAnimation(true);
    }
  }, [showProcessingPopup]);
  
  useEffect(() => {
    if (!showProcessingPopup) return;
    
    const container = progressContainerRef.current;
    if (!container) return;
  
    const progressDoneElement = container.querySelector('.file-processing-popup-progress-done');
    
    if (progressDoneElement) {
      progressDoneElement.style.width = `${processingProgress}%`;
      progressDoneElement.textContent = `${processingProgress.toFixed(2)}%`;
    }
  }, [processingProgress]);
  
  return (
    <div className="file-encryption-form-container">
      <div className="file-encryption-form-main">
      <p className="file-encryption-form-title" align="center">
        {encryptionType === 'ChaCha20' 
          ? 'ChaCha20 (Experimental, Glitchy, Unstable)' 
          : encryptionType}
      </p>
        <form className="file-encryption-form">
          <div className="file-encryption-form-input-container">
            <input
              className={`file-encryption-form-input-field ${isKeyHidden ? 'hidden' : ''}`}
              type={showKey ? "text" : "password"}
              placeholder="Key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
            />
            <button type="button" className="file-encryption-form-eye-button" onClick={() => setShowKey(!showKey)}>
              {showKey ? '🌕' : '🌑'}
            </button>
          </div>
          <div className="file-encryption-form-input-container">
            <input
              className={`file-encryption-form-input-field ${isIterationsHidden ? 'hidden' : ''}`}
              type={showIterations ? "text" : "password"}
              placeholder="PBKDF2 Iterations"
              value={iterations}
              onChange={(e) => setIterations(e.target.value)}
            />
            <button type="button" className="file-encryption-form-eye-button" onClick={() => setShowIterations(!showIterations)}>
              {showIterations ? '🌕' : '🌑'}
            </button>
          </div>
          <div className="file-encryption-form-button-container">
            <button type="button" className="file-encryption-form-button file-encryption-form-button-select" onClick={handleFileSelect}>Select Files</button>
            <button type="button" className="file-encryption-form-button file-encryption-form-button-generate" onClick={generateRandomKey}>Generate Random Key</button>
            <button type="button" className="file-encryption-form-button file-encryption-form-button-view" onClick={viewSelectedFiles}>View Selected Files</button>
            <button type="button" className="file-encryption-form-button file-encryption-form-button-encrypt" onClick={encryptFiles}>Encrypt Files</button>
            <button type="button" className="file-encryption-form-button file-encryption-form-button-decrypt" onClick={decryptFiles}>Decrypt Files</button>
          </div>
        </form>
      </div>
      {showPopup && (
        <div className="pop-up-filetable-container">
          <h1 className="pop-up-filetable-title">Selected Files</h1>
          <table className="pop-up-filetable">
            <thead>
              <tr>
                <th className="pop-up-filetable-header-cell">File Name</th>
                <th className="pop-up-filetable-header-cell">File Size (MB)</th>
                <th className="pop-up-filetable-header-cell">Action</th>
              </tr>
            </thead>
            <tbody>
              {selectedFiles.map((file, index) => (
                <tr key={index} className="pop-up-filetable-row">
                  <td className="pop-up-filetable-cell">{file.name}</td>
                  <td className="pop-up-filetable-cell">{file.size}</td>
                  <td className="pop-up-filetable-cell">
                    <button className="file-encryption-form-button" onClick={() => removeFile(file)}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button className="pop-up-filetable-close" onClick={() => setShowPopup(false)}>Close</button>
        </div>
      )}
      {showProcessingPopup && (
        <div id="file-processing-popup" className="file-processing-popup">
          <div className="file-processing-popup-main">
            <div className="file-processing-popup-content">
              <p id="file-processing-popup-message-line1" className="file-processing-popup-message-text">
                <span className="filename-span" dir="auto">{currentFileName}</span>
              </p>
              <p id="file-processing-popup-message-line2" className="file-processing-popup-message-text">
                {processingStep}
              </p>
              <div ref={progressContainerRef} className="file-processing-popup-progress">
                {/* Progress bar or animation will be inserted here */}
              </div>
              <div className="file-processing-popup-button-container">
                <a 
                  href={downloadUrl} 
                  id="file-processing-popup-download-button" 
                  className="file-processing-popup-button type--B" 
                  download={downloadFileName}
                  style={{display: showNextButton ? 'block' : 'none'}}
                >
                  <div className="button__line"></div>
                  <div className="button__line"></div>
                  <span id="downloadButton" className="button__text">Download</span>
                  <div className="button__drow1"></div>
                  <div className="button__drow2"></div>
                </a>
                <a 
                  id="file-processing-popup-next-button" 
                  className="file-processing-popup-button type--C"
                  style={{display: showNextButton ? 'block' : 'none'}}
                >
                  <div className="button__line"></div>
                  <div className="button__line"></div>
                  <span className="button__text">Proceed</span>
                  <div className="button__drow1"></div>
                  <div className="button__drow2"></div>
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default FileEncryptionForm;