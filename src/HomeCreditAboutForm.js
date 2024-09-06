import React from 'react';
import './HomeCreditAboutForm.css'; // Ensure this file is imported

const HomeCreditAboutForm = ({ type, width = '640px' }) => { // Default width is set to 640px
    const renderContent = () => {
        switch (type) {
            case 'About':
            case 'Home':
                return (
                    <>
                        <h1 className="regular-font">React-Cryptographic-Toolkit</h1>
                        <p>&nbsp;</p>
                        <p>
                            Disclaimer: The "React-Cryptographic-Toolkit" is an independent software application and is not affiliated with or endorsed by Meta Platforms, Inc. "React" is a registered trademark of Meta Platforms, Inc. This name is used solely for identification purposes.
                        </p>
                        <p>&nbsp;</p>
                        <p>
                            You can use this app to encrypt your data, hash strings, and calculate tags using the available HMAC algorithms.
                        </p>
                        <p>&nbsp;</p>
                        <p className="disclaimer-warning">
                            This app is provided with no warranty or guarantees of any kind.
                        </p>
                        <p className="disclaimer-warning">
                            Use it at your own risk!
                        </p>
                    </>
                );
            case 'Credit':
                return (
                    <>
                        <h1>Credit</h1>
                        <p>&nbsp;</p>
                        <p>The project utilizes the following templates:</p>
                        <p>&nbsp;</p>
                        <ul style={{ paddingLeft: '20px' }}> {}
                            <li><a href="https://codepen.io/FlorinPop17/pen/xxORmaB" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/FlorinPop17/pen/xxORmaB</a></li>
                            <li><a href="https://codepen.io/t_afif/pen/JjByKMp" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/t_afif/pen/JjByKMp</a></li>
                            <li><a href="https://codepen.io/karaWhiteDragon/pen/zYGGMya" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/karaWhiteDragon/pen/zYGGMya</a></li>
                            <li><a href="https://codepen.io/andornagy/pen/ALbdbJ" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/andornagy/pen/ALbdbJ</a></li>
                            <li><a href="https://codepen.io/elujambio/pen/YLMVed" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/elujambio/pen/YLMVed</a></li>
                            <li><a href="https://codepen.io/sowg/pen/qBXjXoE" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/sowg/pen/qBXjXoE</a></li>
                            <li><a href="https://codepen.io/HighFlyer/pen/WNXRZBv" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/HighFlyer/pen/WNXRZBv</a></li>
                            <li><a href="https://codepen.io/Mohuth/pen/QWgrPvp" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/Mohuth/pen/QWgrPvp</a></li>
                            <li><a href="https://codepen.io/lukemeyrick/pen/rNmKdrg" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/lukemeyrick/pen/rNmKdrg</a></li>
                            <li><a href="https://codepen.io/fadzrinmadu/pen/bGqrJjB" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/fadzrinmadu/pen/bGqrJjB</a></li>
                            <li><a href="https://codepen.io/BrandonBradley/pen/NrzOPK" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/BrandonBradley/pen/NrzOPK</a></li>
                            <li><a href="https://codepen.io/Devel0per95/pen/rjOpdx" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/Devel0per95/pen/rjOpdx</a></li>
                            <li><a href="https://codepen.io/FlorinPop17/pen/yLyzmLZ" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/FlorinPop17/pen/yLyzmLZ</a></li>
                            <li><a href="https://codepen.io/celebstori/pen/NWLdVvv" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/celebstori/pen/NWLdVvv</a></li>
                            <li><a href="https://codepen.io/ash_creator/pen/oNyNbNO" target="_blank" rel="noopener noreferrer" style={{ color: '#161616' }}>https://codepen.io/ash_creator/pen/oNyNbNO</a></li>
                        </ul>
                    </>
                );
            default:
                return <p>Content not found.</p>;
        }
    };

    return (
        <div className="homecreditaboutform-screen-1" style={{ width }}> {/* Set width dynamically */}
            <div className="homecreditaboutform-content">
                {renderContent()}
            </div>
        </div>
    );
};

export default HomeCreditAboutForm;