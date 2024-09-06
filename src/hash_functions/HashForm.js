import React, { useState } from 'react';
import CryptoJS from 'crypto-js';
import { whirlpool, blake3, md5, md4, ripemd160 } from 'hash-wasm';
import './HashForm.css'; // Import the CSS file

const HashForm = ({ hashType }) => {
  const [input, setInput] = useState('');
  const [hash, setHash] = useState('');

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

  const generateHash = async (e) => {
    e.preventDefault();
    let generatedHash = '';

    switch (hashType) {
      case 'MD4':
        generatedHash = await md4(input);
        break;
      case 'MD5':
        generatedHash = await md5(input);
        break;
      case 'RIPEMD-160':
        generatedHash = await ripemd160(input);
        break;
      case 'Blake3':
        generatedHash = await blake3(input);
        break;
      case 'SHA-256':
        generatedHash = CryptoJS.SHA256(input).toString();
        break;
      case 'SHA-384':
        generatedHash = CryptoJS.SHA384(input).toString();
        break;
      case 'SHA-512':
        generatedHash = CryptoJS.SHA512(input).toString();
        break;
      case 'Whirlpool':
        generatedHash = await whirlpool(input);
        break;
      case 'SHA-512 + Whirlpool':
        const sha512_output = CryptoJS.SHA512(input).toString();
        const sha512Array = hexStringToArray(sha512_output);
        const byteArray = new Uint8Array(sha512Array);
        generatedHash = await whirlpool(byteArray);
        break;
      default:
        generatedHash = 'Unknown hash type';
    }

    setHash(generatedHash);
  };

  return (
    <div className="screen">
      <div className="screenContent">
        <form className="form" onSubmit={generateHash}>
          <h2 className="hashType">{hashType}</h2>
          <div className="inputField">
            <input
              type="text"
              className="input"
              placeholder="Enter string to hash"
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
          </div>
          <button type="submit" className="button">
            <span className="buttonText">Generate Hash</span>
          </button>
          {hash && (
            <div className="hashResult">
              <p>{hash}</p>
            </div>
          )}
        </form>
      </div>
      <div className="screenBackground">
        <span className="shape shape4"></span>
        <span className="shape shape3"></span>
        <span className="shape shape2"></span>
        <span className="shape shape1"></span>
      </div>
    </div>
  );
};

export default HashForm;