document.addEventListener('DOMContentLoaded', () => {
    const statusValue = document.getElementById('status-value');

    const updateStatus = (mlReady) => {
        if (mlReady) {
            statusValue.innerHTML = '<span class="pulse"></span> LOCAL ML ACTIVE // SECURED';
            statusValue.style.color = '#2ed573';
        } else {
            statusValue.innerHTML = '<span class="pulse" style="background: #ffa502; box-shadow: 0 0 10px #ffa502;"></span> CLOUD API // SECURED';
            statusValue.style.color = '#ffa502';
        }
    };

    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        // Query background script for ML Engine status
        chrome.runtime.sendMessage({ action: "getStatus" }, (response) => {
            updateStatus(response && response.mlEngineReady);
        });
    } else {
        // Mock response for testing outside extension
        updateStatus(true);
    }
});
