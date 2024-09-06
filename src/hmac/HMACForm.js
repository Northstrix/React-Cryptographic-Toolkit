import React, { useState } from 'react';
import CryptoJS from 'crypto-js';
import { oneTimeAuth } from '@stablelib/poly1305';
import { encode, decode } from '@stablelib/hex';
import './HMACForm.css';

const HMACForm = ({ hashType }) => {
  const [message, setMessage] = useState('');
  const [key, setKey] = useState('');
  const [tag, setTag] = useState('');

  const generateTag = (e) => {
    e.preventDefault();
    let generatedTag = '';

    try {
      switch (hashType) {
        case 'HMAC-SHA256':
          generatedTag = CryptoJS.HmacSHA256(message, key).toString();
          break;
        case 'HMAC-SHA512':
          generatedTag = CryptoJS.HmacSHA512(message, key).toString();
          break;
        case 'Poly1305':
            const keyBytes = decode(key);
            if (keyBytes.length !== 32) {
              throw new Error('Poly1305 requires the 32-byte key (64 hex characters)');
            }
            const inputDatForPoly1305 = [
                {
                    data: Array.from(message)
                    .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
                    .join(''),
                    pkey: key,
                },
            ];
          const results = inputDatForPoly1305.map(v => {
            const mac = oneTimeAuth(decode(v.pkey), decode(v.data));
            generatedTag =  encode(mac);
          });
          break;
        default:
          throw new Error('Unknown hash type');
      }
    } catch (error) {
      generatedTag = `Error: ${error.message}`;
    }

    setTag(generatedTag);
  };

  return (
    <div className='hmac-from-screen'>
      <div className='hmac-from-screenContent'>
        <form className='hmac-from-form' onSubmit={generateTag}>
          <h2 className='hmac-from-hashType'>{hashType}</h2>
          <div className='hmac-from-inputField'>
            <input
              type='text'
              className='hmac-from-input'
              placeholder='Enter message'
              value={message}
              onChange={(e) => setMessage(e.target.value)}
            />
            <input
              type='text'
              className='hmac-from-input-key'
              placeholder={hashType === 'Poly1305' ? 'Enter key (64 hex characters)' : 'Enter key'}
              value={key}
              onChange={(e) => setKey(e.target.value)}
            />
          </div>
          <button type='submit' className='hmac-from-button'>
            <span className='hmac-from-buttonText'>Generate Tag</span>
          </button>
          {tag && (
            <div className='hmac-from-hashResult'>
              <p>{tag}</p>
            </div>
          )}
        </form>
      </div>
      <div className='hmac-from-screenBackground'>
        <span className='hmac-from-shape hmacshape4'></span>
        <span className='hmac-from-shape hmacshape3'></span>
        <span className='hmac-from-shape hmacshape2'></span>
        <span className='hmac-from-shape hmacshape1'></span>
      </div>
    </div>
  );
};

export default HMACForm;