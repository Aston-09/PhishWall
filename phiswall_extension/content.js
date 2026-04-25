// PhishWall Content Script v2.0
// Neural Cybersecurity Interceptor

function showWarning(data, url, onProceed) {
    const existing = document.getElementById('phiswall-warning');
    if (existing) existing.remove();

    const riskLevel = data.risk_level === 'LOW' ? 'low' : (data.risk_score >= 70 ? 'high' : 'suspicious');
    const shieldIcon = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin-right: 8px;"><path d="M12 2L4 5V11C4 16.19 7.41 21.05 12 22.3C16.59 21.05 20 16.19 20 11V5L12 2Z" fill="#ffffff" stroke="#ffffff" stroke-width="1.5"/></svg>`;

    if (riskLevel === 'low') {
        const toast = document.createElement('div');
        toast.className = 'phiswall-toast';
        toast.innerHTML = `${shieldIcon} PhishWall Secured`;
        document.body.appendChild(toast);
        setTimeout(() => {
            toast.style.animation = 'phiswall-toast-fade-out 0.6s forwards';
            setTimeout(() => toast.remove(), 600);
        }, 3000);
        return; // Skip drawing the large overlay for safe sites
    }

    const overlay = document.createElement('div');
    overlay.id = 'phiswall-warning';
    overlay.className = 'phiswall-warning-overlay';

    const riskBadgeClass = `phiswall-risk-${riskLevel}`;
    const icon = riskLevel === 'high' ? '⚠️' : '⚠️';
    const title = riskLevel === 'high' ? 'CRITICAL ALERT' : 'Suspicious Site';

    overlay.innerHTML = `
        <div class="phiswall-warning-header">
            ${icon}
            <h3>${title}</h3>
        </div>
        <div class="phiswall-content-body">
            <div class="phiswall-risk-badge ${riskBadgeClass}">RISK: ${data.risk_level} (${data.risk_score}%)</div>
            <p style="font-size:16px; margin-bottom:12px; font-weight: 300;">Target: <strong style="color:#ffffff;">${new URL(url).hostname}</strong></p>
            <div class="phiswall-status-msg" style="color: #11c05d; font-size: 15px; margin-bottom: 20px;">
                ${riskLevel === 'low' ? 'This site is verified as safe.' : 'Proceed with extreme caution.'}
            </div>
            <div class="phiswall-actions">
                ${riskLevel === 'low' ?
            '' :
            `<button class="phiswall-btn phiswall-btn-proceed" id="phiswall-ignore">Proceed Anyway</button>
             <button class="phiswall-btn phiswall-btn-block" id="phiswall-safe">Stay Safe</button>`
        }
            </div>
            ${riskLevel !== 'low' ? `<div style="text-align: center; margin-top: 15px;">
                <a href="#" id="phiswall-report-fp" style="color: #888; font-size: 12px; text-decoration: underline;">Wait, this is a safe site! (Report False Positive)</a>
            </div>` : ''}
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById('phiswall-ignore').onclick = (e) => {
        overlay.remove();
        if (onProceed) onProceed();
    };
        document.getElementById('phiswall-safe').onclick = (e) => {
            overlay.remove();
            if (window.location.href === url) history.back();
        };
        document.getElementById('phiswall-report-fp').onclick = (e) => {
            e.preventDefault();
            const fpLink = document.getElementById('phiswall-report-fp');
            fpLink.innerText = "Reporting...";
            
            if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
                chrome.runtime.sendMessage({ action: "reportFeedback", url: url, isSafe: true }, (response) => {
                    fpLink.innerText = "Thanks! The model is learning.";
                    fpLink.style.color = "#11c05d";
                    fpLink.style.textDecoration = "none";
                });
            } else {
                fpLink.innerText = "Thanks! The model is learning.";
                fpLink.style.color = "#11c05d";
            }
        };

    if (riskLevel === 'high' && window.location.href === url) {
        blockSite(data);
    }
}

function blockSite(data) {
    document.documentElement.innerHTML = `
        <div class="phiswall-blocked-screen">
            <h1>THREAT BLOCKED</h1>
            <div class="phiswall-warning-box">
                <p style="font-size:24px; font-weight:300; margin-bottom:30px;">PhishWall Neural Engine has identified this site as a high-risk security threat.</p>
                <div class="phiswall-risk-badge phiswall-risk-high" style="font-size:18px; padding:10px 20px;">CRITICAL RISK: ${data.risk_score}%</div>
                <ul class="phiswall-reasons" style="text-align: left; margin: 30px 0;">
                    ${data.reasons.map(r => `<li style="color:white; border-bottom:1px solid rgba(255,255,255,0.1);">${r}</li>`).join('')}
                </ul>
                <div style="display:flex; gap:20px;">
                    <button class="phiswall-btn phiswall-btn-block" id="phiswall-back" style="padding:20px; font-size:16px;">Go Back to Safety</button>
                    <a href="https://www.sancharsaathi.gov.in/sfc/" target="_blank" class="phiswall-btn phiswall-btn-proceed" style="padding:20px; font-size:16px; display:flex; align-items:center; justify-content:center; text-decoration:none;">Report Threat</a>
                </div>
            </div>
        </div>
    `;
    document.getElementById('phiswall-back').onclick = () => {
        if (history.length > 1) history.back();
        else window.location.href = "about:blank";
    };
}

// Event Interception
document.addEventListener('click', (e) => {
    const anchor = e.target.closest('a');
    if (anchor && anchor.href && anchor.href.startsWith('http') && !anchor.href.includes('localhost') && !anchor.href.includes('127.0.0.1')) {
        if (anchor.dataset.phiswallVerified === 'true') return;

        // Preserve native behavior for modifier keys (open in new tab/window)
        if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || e.button !== 0) {
            return;
        }

        // Preserve native behavior for target="_blank" and downloads
        if (anchor.target === '_blank' || anchor.hasAttribute('download')) {
            return;
        }

        // Preserve SPA routing for same-origin links (fixes navigation issues on sites like GitHub)
        try {
            if (new URL(anchor.href).origin === window.location.origin) {
                return;
            }
        } catch (err) {}

        e.preventDefault();
        e.stopPropagation();

        const url = anchor.href;
        chrome.runtime.sendMessage({ action: "scanUrl", url: url }, (response) => {
            const proceed = () => {
                anchor.dataset.phiswallVerified = 'true';
                window.location.href = url;
            };

            if (response && response.success) {
                showWarning(response.data, url, proceed);
                if (response.data.risk_level === 'LOW') {
                    setTimeout(proceed, 500);
                }
            } else {
                proceed();
            }
        });
    }
}, true);

// Page Load Scan
if (window.location.href.startsWith('http') && !window.location.href.includes('localhost') && !window.location.href.includes('127.0.0.1')) {
    chrome.runtime.sendMessage({ action: "scanUrl", url: window.location.href }, (response) => {
        if (response && response.success) {
            showWarning(response.data, window.location.href);
        }
    });
}
