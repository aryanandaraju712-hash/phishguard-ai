// =====================================================
// PhishGuard AI - Frontend and Backend Integration
// =====================================================

// FastAPI backend URL
const API_BASE_URL = "http://127.0.0.1:8000";

// API endpoint for email analysis
const ANALYZE_ENDPOINT = `${API_BASE_URL}/api/analyze`;

let isAnalyzing = false;

// =====================================================
// Helper: Get elements safely
// =====================================================
function getElements() {
    return {
        form: document.getElementById("emailAnalysisForm"),
        subjectInput: document.getElementById("subject"),
        senderInput: document.getElementById("sender"),
        emailBodyInput: document.getElementById("emailBody"),
        analyzeButton: document.getElementById("analyzeBtn"),
        resultContainer: document.getElementById("analysisResult"),
        characterCount: document.getElementById("characterCount"),
        statusDot: document.getElementById("backendStatusDot"),
        statusText: document.getElementById("backendStatusText")
    };
}

// =====================================================
// Check Backend Connection
// =====================================================
async function checkBackendConnection() {
    const { statusDot, statusText } = getElements();

    try {
        const response = await fetch(`${API_BASE_URL}/api/health`, {
            method: "GET",
            headers: { "Accept": "application/json" }
        }).catch(() => fetch(`${API_BASE_URL}/`));

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        if (statusDot) statusDot.style.background = "#22c55e";
        if (statusText) statusText.textContent = "Backend Connected";
        console.log("PhishGuard Backend is connected and operational.");
    } catch (error) {
        if (statusDot) statusDot.style.background = "#ef4444";
        if (statusText) statusText.textContent = "Backend Disconnected";
        console.warn("Backend connection check failed:", error.message);
    }
}

// =====================================================
// Send Email Data to Backend
// =====================================================
async function analyzeEmailWithBackend(emailData) {
    let response;
    try {
        response = await fetch(ANALYZE_ENDPOINT, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify(emailData)
        });
    } catch (networkError) {
        throw new Error(
            `Unable to connect to PhishGuard backend at ${API_BASE_URL}. Please ensure the backend is running.`
        );
    }

    const responseText = await response.text();
    let data;

    try {
        data = JSON.parse(responseText);
    } catch {
        throw new Error(
            `The backend returned an unexpected response. HTTP ${response.status}.`
        );
    }

    if (!response.ok) {
        const detail =
            typeof data.detail === "string"
                ? data.detail
                : Array.isArray(data.detail)
                    ? data.detail.map(d => d.msg || JSON.stringify(d)).join(", ")
                    : JSON.stringify(data.detail || data);

        throw new Error(`Backend error (${response.status}): ${detail}`);
    }

    return data;
}

// =====================================================
// Display Loading Message
// =====================================================
function showLoading() {
    const { resultContainer } = getElements();
    if (!resultContainer) return;

    resultContainer.replaceChildren();

    const card = document.createElement("div");
    card.style.textAlign = "center";
    card.style.padding = "24px 12px";

    const spinner = document.createElement("div");
    spinner.textContent = "⚙";
    spinner.style.fontSize = "32px";
    spinner.style.marginBottom = "12px";
    spinner.style.animation = "spin 1s linear infinite";

    const message = document.createElement("p");
    message.textContent = "Analyzing email content, headers & threat indicators...";
    message.style.color = "#8bcfff";
    message.style.fontWeight = "600";

    card.append(spinner, message);
    resultContainer.appendChild(card);
    resultContainer.hidden = false;
    resultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// =====================================================
// Display Error Message
// =====================================================
function showError(message) {
    const { resultContainer } = getElements();
    if (!resultContainer) {
        alert(message);
        return;
    }

    resultContainer.replaceChildren();

    const heading = document.createElement("h2");
    heading.textContent = "⚠️ Analysis Notice";
    heading.style.color = "#ef4444";

    const errorText = document.createElement("p");
    errorText.textContent = message;
    errorText.style.color = "#fca5a5";
    errorText.style.marginTop = "8px";

    resultContainer.append(heading, errorText);
    resultContainer.hidden = false;
    resultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// =====================================================
// Display Analysis Result
// =====================================================
function displayAnalysisResult(result, submittedEmail) {
    const { resultContainer } = getElements();
    if (!resultContainer) return;

    resultContainer.replaceChildren();

    // Determine Risk Level & Colors
    const riskLevel = result.risk_level || (result.risk_score >= 80 ? "Critical" : result.risk_score >= 60 ? "High" : result.risk_score >= 30 ? "Medium" : "Low");
    const riskScore = typeof result.risk_score === "number" ? result.risk_score : 0;

    let badgeColor = "#22c55e"; // Low - Green
    let badgeText = "SAFE / LOW RISK";

    if (riskLevel.toLowerCase() === "critical") {
        badgeColor = "#ef4444"; // Red
        badgeText = "CRITICAL PHISHING THREAT";
    } else if (riskLevel.toLowerCase() === "high") {
        badgeColor = "#f97316"; // Orange
        badgeText = "HIGH RISK PHISHING";
    } else if (riskLevel.toLowerCase() === "medium") {
        badgeColor = "#eab308"; // Yellow
        badgeText = "SUSPICIOUS / MEDIUM RISK";
    }

    // Top Header & Badge
    const headerRow = document.createElement("div");
    headerRow.style.display = "flex";
    headerRow.style.justifyContent = "space-between";
    headerRow.style.alignItems = "center";
    headerRow.style.flexWrap = "wrap";
    headerRow.style.gap = "10px";
    headerRow.style.marginBottom = "16px";

    const heading = document.createElement("h2");
    heading.textContent = "Threat Analysis Report";
    heading.style.margin = "0";
    heading.style.color = "#7ec8ff";

    const badge = document.createElement("span");
    badge.textContent = badgeText;
    badge.style.background = badgeColor;
    badge.style.color = "#081426";
    badge.style.fontWeight = "bold";
    badge.style.fontSize = "12px";
    badge.style.padding = "5px 12px";
    badge.style.borderRadius = "20px";
    badge.style.letterSpacing = "0.5px";

    headerRow.append(heading, badge);
    resultContainer.appendChild(headerRow);

    // Score & Progress Bar
    const scoreContainer = document.createElement("div");
    scoreContainer.style.background = "#071326";
    scoreContainer.style.padding = "14px";
    scoreContainer.style.borderRadius = "10px";
    scoreContainer.style.marginBottom = "18px";
    scoreContainer.style.border = `1px solid ${badgeColor}40`;

    const scoreTitle = document.createElement("div");
    scoreTitle.style.display = "flex";
    scoreTitle.style.justifyContent = "space-between";
    scoreTitle.style.fontSize = "14px";
    scoreTitle.style.fontWeight = "bold";
    scoreTitle.style.color = "#eaf2ff";
    scoreTitle.innerHTML = `<span>Phishing Risk Score: <strong style="color:${badgeColor}; font-size:16px;">${riskScore.toFixed(1)}/100</strong></span><span>Confidence: <strong>${result.confidence_score || "High"}</strong></span>`;

    const progressBarOuter = document.createElement("div");
    progressBarOuter.style.background = "#13233c";
    progressBarOuter.style.borderRadius = "8px";
    progressBarOuter.style.height = "12px";
    progressBarOuter.style.marginTop = "10px";
    progressBarOuter.style.overflow = "hidden";

    const progressBarInner = document.createElement("div");
    progressBarInner.style.background = badgeColor;
    progressBarInner.style.height = "100%";
    progressBarInner.style.width = `${Math.min(100, Math.max(5, riskScore))}%`;
    progressBarInner.style.borderRadius = "8px";
    progressBarInner.style.transition = "width 0.4s ease";

    progressBarOuter.appendChild(progressBarInner);
    scoreContainer.append(scoreTitle, progressBarOuter);
    resultContainer.appendChild(scoreContainer);

    // AI Explanations section
    if (Array.isArray(result.ai_explanation) && result.ai_explanation.length > 0) {
        const aiSection = document.createElement("div");
        aiSection.style.marginBottom = "18px";

        const aiTitle = document.createElement("h3");
        aiTitle.textContent = "AI Threat Findings";
        aiTitle.style.color = "#55b6ff";
        aiTitle.style.fontSize = "15px";
        aiTitle.style.marginBottom = "8px";
        aiSection.appendChild(aiTitle);

        result.ai_explanation.forEach(item => {
            const itemBox = document.createElement("div");
            itemBox.style.background = "#0c1a2e";
            itemBox.style.borderLeft = `3px solid ${badgeColor}`;
            itemBox.style.padding = "10px 14px";
            itemBox.style.borderRadius = "4px";
            itemBox.style.marginBottom = "8px";

            const finding = document.createElement("strong");
            finding.textContent = item.finding || "Indicator Detected";
            finding.style.color = "#f0f6ff";
            finding.style.display = "block";
            finding.style.marginBottom = "4px";

            const reason = document.createElement("p");
            reason.textContent = item.why_it_matters || item.evidence || "";
            reason.style.margin = "0";
            reason.style.fontSize = "13px";
            reason.style.color = "#a5b7d1";

            itemBox.append(finding, reason);
            aiSection.appendChild(itemBox);
        });

        resultContainer.appendChild(aiSection);
    }

    // Heuristics / Indicator Details
    if (Array.isArray(result.indicator_details) && result.indicator_details.length > 0) {
        const indSection = document.createElement("div");
        indSection.style.marginBottom = "18px";

        const indTitle = document.createElement("h3");
        indTitle.textContent = `Security Indicators (${result.indicator_details.length} Flagged)`;
        indTitle.style.color = "#55b6ff";
        indTitle.style.fontSize = "15px";
        indTitle.style.marginBottom = "8px";
        indSection.appendChild(indTitle);

        const list = document.createElement("ul");
        list.style.paddingLeft = "20px";
        list.style.color = "#cbd5e1";
        list.style.fontSize = "13px";

        result.indicator_details.forEach(ind => {
            const li = document.createElement("li");
            li.style.marginBottom = "6px";
            li.innerHTML = `<strong style="color:#f8fafc;">[${ind.severity || "Info"}]</strong> ${ind.description} ${ind.evidence ? `<em>(${ind.evidence})</em>` : ""}`;
            list.appendChild(li);
        });

        indSection.appendChild(list);
        resultContainer.appendChild(indSection);
    }

    // Recommendations
    if (Array.isArray(result.recommendations) && result.recommendations.length > 0) {
        const recSection = document.createElement("div");
        recSection.style.background = "#09172c";
        recSection.style.border = "1px solid #1e3a62";
        recSection.style.borderRadius = "10px";
        recSection.style.padding = "14px";
        recSection.style.marginBottom = "18px";

        const recTitle = document.createElement("h3");
        recTitle.textContent = "🛡 Recommended Actions";
        recTitle.style.color = "#7dd3fc";
        recTitle.style.fontSize = "14px";
        recTitle.style.marginTop = "0";
        recTitle.style.marginBottom = "8px";
        recSection.appendChild(recTitle);

        const recList = document.createElement("ul");
        recList.style.paddingLeft = "20px";
        recList.style.margin = "0";
        recList.style.fontSize = "13px";
        recList.style.color = "#e2e8f0";

        result.recommendations.forEach(rec => {
            const li = document.createElement("li");
            li.textContent = rec;
            li.style.marginBottom = "4px";
            recList.appendChild(li);
        });

        recSection.appendChild(recList);
        resultContainer.appendChild(recSection);
    }

    // Extracted URLs
    if (Array.isArray(result.extracted_urls) && result.extracted_urls.length > 0) {
        const urlSection = document.createElement("div");
        urlSection.style.marginBottom = "18px";

        const urlTitle = document.createElement("h3");
        urlTitle.textContent = `Extracted URLs (${result.extracted_urls.length})`;
        urlTitle.style.fontSize = "14px";
        urlTitle.style.color = "#55b6ff";
        urlSection.appendChild(urlTitle);

        const urlList = document.createElement("div");
        urlList.style.fontSize = "12px";

        result.extracted_urls.forEach(u => {
            const urlItem = document.createElement("code");
            urlItem.style.display = "block";
            urlItem.style.background = "#06101f";
            urlItem.style.padding = "6px 10px";
            urlItem.style.borderRadius = "6px";
            urlItem.style.marginTop = "4px";
            urlItem.style.color = "#93c5fd";
            urlItem.textContent = u.defanged_url || u.original_url || u.domain;
            urlList.appendChild(urlItem);
        });

        urlSection.appendChild(urlList);
        resultContainer.appendChild(urlSection);
    }

    // Expandable Technical Details
    const details = document.createElement("details");
    details.style.marginTop = "14px";
    details.style.paddingTop = "10px";
    details.style.borderTop = "1px solid #1e3a62";

    const summary = document.createElement("summary");
    summary.textContent = "View raw technical payload (JSON)";
    summary.style.cursor = "pointer";
    summary.style.color = "#7dd3fc";
    summary.style.fontSize = "12px";

    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(result, null, 2);
    pre.style.marginTop = "8px";
    pre.style.padding = "10px";
    pre.style.background = "#06101f";
    pre.style.borderRadius = "6px";
    pre.style.fontSize = "11px";
    pre.style.overflowX = "auto";
    pre.style.color = "#94a3b8";

    details.append(summary, pre);
    resultContainer.appendChild(details);

    resultContainer.hidden = false;
    resultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// =====================================================
// Main Email Analysis Handler
// =====================================================
async function handleEmailAnalysis(event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }

    if (isAnalyzing) return;

    const { subjectInput, senderInput, emailBodyInput, analyzeButton } = getElements();

    if (!emailBodyInput) {
        console.error("Required emailBody input element not found in DOM.");
        return;
    }

    const rawBody = emailBodyInput.value.trim();

    if (!rawBody) {
        showError("Please enter or paste email content to analyze.");
        emailBodyInput.focus();
        return;
    }

    // Extract or fallback sender
    let sender = senderInput ? senderInput.value.trim() : "";
    if (!sender) {
        // Try to detect From: header from raw body text
        const fromMatch = rawBody.match(/From:\s*([^\r\n<]+<[^>]+>|[\w\.-]+@[\w\.-]+\.\w+)/i);
        if (fromMatch) {
            sender = fromMatch[1].trim();
        } else {
            sender = "unspecified-sender@external.mail";
        }
    }

    // Extract or fallback subject
    let subject = subjectInput ? subjectInput.value.trim() : "";
    if (!subject) {
        const subjectMatch = rawBody.match(/Subject:\s*([^\r\n]+)/i);
        if (subjectMatch) {
            subject = subjectMatch[1].trim();
        } else {
            subject = "Suspicious Email Analysis";
        }
    }

    const emailData = {
        subject: subject,
        sender: sender,
        reply_to: null,
        recipient: null,
        body: rawBody,
        urls: [],
        create_incident: true
    };

    isAnalyzing = true;
    showLoading();

    if (analyzeButton) {
        analyzeButton.disabled = true;
        analyzeButton.textContent = "Analyzing Threat...";
    }

    try {
        const result = await analyzeEmailWithBackend(emailData);
        displayAnalysisResult(result, emailData);
    } catch (error) {
        console.error("Email analysis failed:", error);
        showError(error.message);
    } finally {
        isAnalyzing = false;
        if (analyzeButton) {
            analyzeButton.disabled = false;
            analyzeButton.innerHTML = "<span>⌕</span> Analyze Email";
        }
    }
}

// =====================================================
// Initialize Listeners and DOM Bindings
// =====================================================
function initPhishGuard() {
    const { form, analyzeButton, emailBodyInput, characterCount } = getElements();

    // Prevent default form submit & trigger analysis
    if (form) {
        form.onsubmit = function (e) {
            if (e) e.preventDefault();
            handleEmailAnalysis(e);
            return false;
        };
        form.addEventListener("submit", handleEmailAnalysis);
    }

    if (analyzeButton) {
        analyzeButton.addEventListener("click", handleEmailAnalysis);
    }

    // Character counter
    if (emailBodyInput && characterCount) {
        const updateCount = () => {
            const count = emailBodyInput.value.length;
            characterCount.textContent = `${count} character${count === 1 ? "" : "s"}`;
        };
        emailBodyInput.addEventListener("input", updateCount);
        updateCount();
    }

    // Check backend readiness
    checkBackendConnection();
}

// Bind immediately if DOM is ready, or on DOMContentLoaded
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initPhishGuard);
} else {
    initPhishGuard();
}

// Expose globally for inline button fallback
window.handleEmailAnalysis = handleEmailAnalysis;