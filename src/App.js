import React, { useState, useEffect } from 'react';
import './App.css';
import './backgroundPatterns/circularPattern.css';
import './backgroundPatterns/ScottishPattern.css';
import Menu from './menu/Menu';
import MidbarCompatibleAES256CBC from './string_encryption/midbar-compatible-aes-256-cbc';
import HashForm from './hash_functions/HashForm';
import FileEncryptionForm from './file_encryption/FileEncryptionForm';
import HMACForm from './hmac/HMACForm';
import HomeCreditAboutForm from './HomeCreditAboutForm'; // Import the new form component

function App() {
  const backgroundClasses = ['circularPattern', 'ScottishPattern'];
  const [backgroundClass, setBackgroundClass] = useState('');

  useEffect(() => {
    const randomIndex = Math.floor(Math.random() * backgroundClasses.length);
    const selectedBackground = backgroundClasses[randomIndex];
    setBackgroundClass(selectedBackground);
  }, []);

  const [selectedComponent, setSelectedComponent] = useState('Home');

  const changeBackground = () => {
    setBackgroundClass(prevClass => prevClass === backgroundClasses[0] ? backgroundClasses[1] : backgroundClasses[0]);
  };

  const handleSelect = (component) => {
    if (component === 'Change Background') {
      changeBackground();
    } else {
      setSelectedComponent(component);
    }
  };

  const renderContent = () => {
    switch (selectedComponent) {
      case 'Home':
      case 'Credit':
      case 'About':
        return <HomeCreditAboutForm type={selectedComponent} />; // Pass the selected type as a prop
      case 'ChaCha20 for strings':
      case 'Midbar-Compatible AES-256 CBC':
      case 'Serpent CBC + Key Incrementation':
      case 'Twofish CBC + Key Incrementation':
      case 'ChaCha20 (Chunked) + AES-256 CBC for strings':
      case 'ChaCha20 (Chunked) + Serpent-256 CBC for strings':
      case 'ChaCha20 (Chunked) + Twofish-256 CBC for strings':
        return <MidbarCompatibleAES256CBC encryptionType={selectedComponent} />;
      case 'MD4':
      case 'MD5':
      case 'RIPEMD-160':
      case 'Blake3':
      case 'SHA-256':
      case 'SHA-384':
      case 'SHA-512':
      case 'Whirlpool':
      case 'SHA-512 + Whirlpool':
        return <HashForm hashType={selectedComponent} />;
      case 'ChaCha20':
      case 'ChaCha20 (Chunked)':
      case 'AES-256 CBC':
      case 'Serpent-256 CBC':
      case 'Twofish-256 CBC':
      case 'ChaCha20 (Chunked) + AES-256 CBC':
      case 'ChaCha20 (Chunked) + Serpent-256 CBC':
      case 'ChaCha20 (Chunked) + Twofish-256 CBC':
        return <FileEncryptionForm encryptionType={selectedComponent} />;
      case 'Poly1305':
      case 'HMAC-SHA256':
      case 'HMAC-SHA512':
        return <HMACForm hashType={selectedComponent} />;
      default:
        return <h2>{selectedComponent}</h2>;
    }
  };

  return (
    <div className={`App ${backgroundClass}`}>
      <Menu onSelect={handleSelect} />
      <header>
        {renderContent()}
      </header>
      <div id="notification-container" className="notification-container"></div>
      
      <footer>
        <p>Made by <a target="_blank" rel="noopener noreferrer" href="https://www.github.com/Northstrix">Maxim Bortnikov</a> with the help of <a target="_blank" rel="noopener noreferrer" href="https://www.perplexity.ai/">Perplexity</a></p>
      </footer>
    </div>
  );
}

export default App;