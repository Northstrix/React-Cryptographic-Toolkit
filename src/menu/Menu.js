import React, { useState } from 'react';
import './Menu.css';
import logo from '../logo.png'; // Adjust the path if necessary

const Menu = ({ onSelect }) => {
  const [menuOpen, setMenuOpen] = useState(false);

  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
  };

  const handleSelect = (item) => {
    onSelect(item);
    setMenuOpen(false); // Close the menu when an item is selected
  };

  return (
    <nav>
      <div className="wrapper">
        <div className="logo">
          <a href="#">
            <img src={logo} alt="React Logo" className="react-logo" />
          </a>
        </div>
        <div className={`menu-btn ${menuOpen ? 'active' : ''}`} onClick={toggleMenu}>
          <span className="bar"></span>
          <span className="bar"></span>
          <span className="bar"></span>
        </div>
        <ul className={`nav-links ${menuOpen ? 'show' : ''}`}>
          <li>
            <a href="#" className="desktop-item">File Encryption</a>
            <ul className="drop-menu">
              <li><a href="#" onClick={() => handleSelect('ChaCha20')}>ChaCha20</a></li>
              <li><a href="#" onClick={() => handleSelect('ChaCha20 (Chunked)')}>Chacha20 (Chunked)</a></li>
              <li><a href="#" onClick={() => handleSelect('AES-256 CBC')}>AES-256 CBC</a></li>
              <li><a href="#" onClick={() => handleSelect('Serpent-256 CBC')}>Serpent-256 CBC</a></li>
              <li><a href="#" onClick={() => handleSelect('Twofish-256 CBC')}>Twofish-256 CBC</a></li>
              <li><a href="#" onClick={() => handleSelect('ChaCha20 (Chunked) + AES-256 CBC')}>ChaCha20 (Chunked) + AES-256 CBC</a></li>
              <li><a href="#" onClick={() => handleSelect('ChaCha20 (Chunked) + Serpent-256 CBC')}>ChaCha20 (Chunked) + Serpent-256 CBC</a></li>
              <li><a href="#" onClick={() => handleSelect('ChaCha20 (Chunked) + Twofish-256 CBC')}>ChaCha20 (Chunked) + Twofish-256 CBC</a></li>
            </ul>
          </li>
          <li>
            <a href="#" className="desktop-item">String Encryption</a>
            <ul className="drop-menu">
              <li><a href="#" onClick={() => handleSelect('ChaCha20 for strings')}>Chacha20</a></li>
              <li><a href="#" onClick={() => handleSelect('Midbar-Compatible AES-256 CBC')}>Midbar-Compatible AES-256 CBC</a></li>
              <li><a href="#" onClick={() => handleSelect('Serpent CBC + Key Incrementation')}>Serpent CBC + Key Incrementation</a></li>
              <li><a href="#" onClick={() => handleSelect('Twofish CBC + Key Incrementation')}>Twofish CBC + Key Incrementation</a></li>
              <li><a href="#" onClick={() => handleSelect('ChaCha20 (Chunked) + AES-256 CBC for strings')}>ChaCha20 (Chunked) + AES-256 CBC</a></li>
              <li><a href="#" onClick={() => handleSelect('ChaCha20 (Chunked) + Serpent-256 CBC for strings')}>ChaCha20 (Chunked) + Serpent-256 CBC</a></li>
              <li><a href="#" onClick={() => handleSelect('ChaCha20 (Chunked) + Twofish-256 CBC for strings')}>ChaCha20 (Chunked) + Twofish-256 CBC</a></li>
            </ul>
          </li>
          <li>
            <a href="#" className="desktop-item">Hash Functions</a>
            <ul className="drop-menu">
              <li><a href="#" onClick={() => handleSelect('MD4')}>MD4</a></li>
              <li><a href="#" onClick={() => handleSelect('MD5')}>MD5</a></li>
              <li><a href="#" onClick={() => handleSelect('RIPEMD-160')}>RIPEMD-160</a></li>
              <li><a href="#" onClick={() => handleSelect('Blake3')}>Blake3</a></li>
              <li><a href="#" onClick={() => handleSelect('SHA-256')}>SHA-256</a></li>
              <li><a href="#" onClick={() => handleSelect('SHA-384')}>SHA384</a></li>
              <li><a href="#" onClick={() => handleSelect('SHA-512')}>SHA-512</a></li>
              <li><a href="#" onClick={() => handleSelect('Whirlpool')}>Whirlpool</a></li>
              <li><a href="#" onClick={() => handleSelect('SHA-512 + Whirlpool')}>SHA-512 + Whirlpool</a></li>
            </ul>
          </li>
          <li>
            <a href="#" className="desktop-item">HMAC</a>
            <ul className="drop-menu">
              <li><a href="#" onClick={() => handleSelect('Poly1305')}>Poly1305</a></li>
              <li><a href="#" onClick={() => handleSelect('HMAC-SHA256')}>HMAC-SHA256</a></li>
              <li><a href="#" onClick={() => handleSelect('HMAC-SHA512')}>HMAC-SHA512</a></li>
            </ul>
          </li>
          <li><a href="#" onClick={() => handleSelect('Change Background')}>Change Background</a></li>
          <li><a href="#" onClick={() => handleSelect('Credit')}>Credit</a></li>
          <li><a href="#" onClick={() => handleSelect('About')}>About</a></li>
        </ul>
      </div>
    </nav>
  );
};

export default Menu;