importScripts('tf.min.js', 'ml_engine.js');

const API_URL = "http://127.0.0.1:8000/scan";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scanUrl") {
    handleScan(request.url).then(sendResponse);
    return true; // Keep the message channel open for async response
  } else if (request.action === "getStatus") {
    sendResponse({ mlEngineReady: self.mlEngineReady });
    return false;
  } else if (request.action === "reportFeedback") {
    const { url, isSafe } = request;
    console.log("Feedback received:", url, "Safe:", isSafe);
    
    if (isSafe) {
      try {
        const domain = new URL(url).hostname;
        // Add to Local Allowlist instead of retraining immediately
        chrome.storage.local.get(['phishwall_whitelist'], (result) => {
          const whitelist = result.phishwall_whitelist || [];
          if (!whitelist.includes(domain)) {
            whitelist.push(domain);
            chrome.storage.local.set({ phishwall_whitelist: whitelist });
            console.log("PhishWall: Added domain to local whitelist:", domain);
          }
        });
      } catch (e) {
        console.error("Invalid URL in feedback:", url);
      }
    }
    
    sendResponse({ success: true });
    return false;
  }
});

async function handleScan(url) {
  try {
    const domain = new URL(url).hostname;
    
    // Check Local Allowlist first
    const storageResult = await chrome.storage.local.get(['phishwall_whitelist']);
    const whitelist = storageResult.phishwall_whitelist || [];
    if (whitelist.includes(domain)) {
      return {
        success: true,
        data: { risk_score: 0, risk_level: 'LOW', reasons: [] }
      };
    }

    // Attempt local ML prediction first
    if (self.mlEngineReady) {
      const localScore = await predictUrl(url);
      if (localScore !== null) {
        const risk_score = Math.round(localScore * 100);
        let risk_level = 'LOW';
        if (risk_score > 75) risk_level = 'HIGH';
        else if (risk_score > 50) risk_level = 'MEDIUM';

        return {
          success: true,
          data: {
            risk_score: risk_score,
            risk_level: risk_level,
            reasons: risk_score > 50 ? ['Suspicious URL heuristics detected (Local ML)'] : []
          }
        };
      }
    }
    
    // Fallback to remote API
    const formData = new FormData();
    formData.append("input_text", url);

    const response = await fetch(API_URL, {
      method: "POST",
      body: formData,
    });
    
    const data = await response.json();
    return { success: true, data: data };
  } catch (error) {
    console.error("Error scanning URL:", error);
    return { success: false, error: error.message };
  }
}

