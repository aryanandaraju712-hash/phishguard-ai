import React, { useState, useEffect } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Mail,
  Globe,
  BarChart3,
  History,
  Info,
  Copy,
  Download,
  CheckCircle2,
  Trash2,
  ExternalLink,
  RefreshCw,
  FileText,
  Lock,
  AlertCircle,
  TrendingUp,
  Search,
  Filter,
  Sparkles,
  Zap,
  ArrowRight,
  Eye,
  X,
  QrCode,
  UploadCloud,
  Image as ImageIcon
} from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  AreaChart,
  Area,
  Legend
} from "recharts";

const API_BASE = "http://127.0.0.1:8000";

// Fallback sample dataset in case backend is offline
const DEFAULT_SAMPLES = [
  {
    id: "sample-meeting",
    title: "Normal Meeting",
    badge: "Legitimate / Low",
    type: "low",
    data: {
      subject: "Quarterly Operations Review & Planning Sync",
      sender: "Jessica Miller <jmiller@partner-consulting.com>",
      body: "Hi everyone,\n\nI hope you are having a productive week. Attached below is the agenda for our upcoming quarterly sync scheduled for next Tuesday at 2:00 PM EST.\n\nPlease let me know if you would like to include any specific operational review items before Friday.\n\nBest regards,\nJessica Miller"
    }
  },
  {
    id: "sample-spam",
    title: "Prize Lottery Spam",
    badge: "Spam / Moderate",
    type: "spam",
    data: {
      subject: "CONGRATULATIONS! You have won our $500,000 Cash Reward Prize!",
      sender: "Global Rewards Promotion <promo-winner@global-jackpot-draws.net>",
      body: "Congratulations Valued User!\n\nYou have been selected as our grand lottery winner for an exclusive cash reward of $500,000 in Bitcoin!\n\nThis is a limited time offer with guaranteed returns and passive income guaranteed! Act fast before it is gone.\n\nClaim your prize and free gift card now by confirming your payout.\n\nClick here to unsubscribe or to be removed from our list."
    }
  },
  {
    id: "sample-phishing",
    title: "Account Suspension",
    badge: "Phishing / High",
    type: "high",
    data: {
      subject: "CRITICAL: Unauthorized sign-in detected on your corporate account",
      sender: "IT Helpdesk <security-notification@internal-it-support-notice.com>",
      body: "CRITICAL SECURITY WARNING:\n\nOur automated security telemetry detected an unauthorized sign-in attempt to your corporate account from an unknown IP address in Moscow, Russia.\n\nYour account access will be deactivated and suspended within 24 hours unless you immediately verify your credentials and authenticate your account.\n\nClick below to verify your account:\nhttp://login.security-verification-portal.xyz/verify-auth\n\nIf you do not verify within 24 hours, all corporate access will be revoked permanently."
    }
  },
  {
    id: "sample-invoice",
    title: "Fake Invoice & Malware",
    badge: "Critical Malware",
    type: "crit",
    data: {
      subject: "FINAL NOTICE: Overdue Invoice INV-94819 Past Due - Legal Action Pending",
      sender: "QuickBooks Billing <billing-notice@quickbooks-accounting-hub.org>",
      body: "Dear Accounts Payable,\n\nWe have not received payment for invoice INV-94819 totaling $14,250.00 which is now 45 days overdue.\n\nImmediate wire payment is required today. Failure to remit payment within 24 hours will result in immediate suspension of services and legal escalation.\n\nPlease find the detailed line-item statement attached: invoice_statement_94819.iso\n\nWire instructions are outlined inside the document. Please remit payment via bank transfer immediately."
    }
  },
  {
    id: "sample-bec",
    title: "CEO Wire Fraud (BEC)",
    badge: "Executive BEC",
    type: "crit",
    data: {
      subject: "Confidential Request from CEO Mark Sterling [CONFIDENTIAL]",
      sender: "Mark Sterling <m.sterling@executive-corporate-management.com>",
      body: "Good morning,\n\nI am currently in an all-day executive board meeting and cannot take phone calls right now.\n\nWe are closing an urgent strategic supplier acquisition today and need to process a confidential wire transfer of $38,500 immediately. I need you to handle this discreetly without discussing it with anyone in the office.\n\nPlease reply directly to this email so I can forward you the wire payment instructions and vendor routing number.\n\nThanks,\nMark Sterling\nChief Executive Officer"
    }
  }
];

const SAMPLE_URLS = [
  {
    label: "Raw Numeric IP Host",
    url: "http://185.193.12.84/m365/login?user=staff@org.com",
    tag: "High Risk"
  },
  {
    label: "Brand Typosquatting",
    url: "http://paypa1-security-verification.xyz/signin",
    tag: "Critical"
  },
  {
    label: "URL Shortener Lure",
    url: "http://bit.ly/claim-crypto-prize-reward",
    tag: "Suspicious"
  },
  {
    label: "IDN Homoglyph (Apple)",
    url: "http://xn--pple-43d.com/auth/login",
    tag: "Homoglyph"
  },
  {
    label: "Legitimate IDN (müller.de)",
    url: "https://xn--mller-kva.de/contact",
    tag: "Legit IDN"
  },
  {
    label: "Legitimate Corporate URL",
    url: "https://support.microsoft.com/en-us/security",
    tag: "Low Risk"
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState("message");
  const [backendStatus, setBackendStatus] = useState("Checking...");

  // Message Analysis State
  const [subject, setSubject] = useState("");
  const [sender, setSender] = useState("");
  const [messageBody, setMessageBody] = useState("");
  const [isAnalyzingMessage, setIsAnalyzingMessage] = useState(false);
  const [messageReport, setMessageReport] = useState(null);
  const [messageError, setMessageError] = useState(null);
  const [copiedMessageReport, setCopiedMessageReport] = useState(false);

  // URL & QR Analysis State
  const [urlInputMode, setUrlInputMode] = useState("url"); // "url" | "qr"
  const [targetUrl, setTargetUrl] = useState("");
  const [isAnalyzingUrl, setIsAnalyzingUrl] = useState(false);
  const [urlReport, setUrlReport] = useState(null);
  const [urlError, setUrlError] = useState(null);
  const [copiedUrlReport, setCopiedUrlReport] = useState(false);

  // QR Code Image State
  const [qrFile, setQrFile] = useState(null);
  const [qrPreview, setQrPreview] = useState(null);
  const [isAnalyzingQr, setIsAnalyzingQr] = useState(false);
  const [qrError, setQrError] = useState(null);

  // PDF Download State
  const [downloadingPdfId, setDownloadingPdfId] = useState(null);
  const [pdfDownloadError, setPdfDownloadError] = useState(null);
  const [pdfDownloadSuccess, setPdfDownloadSuccess] = useState(null);

  // Dashboard & History State
  const [dashboardStats, setDashboardStats] = useState(null);
  const [historyList, setHistoryList] = useState([]);
  const [historySearch, setHistorySearch] = useState("");
  const [historyFilter, setHistoryFilter] = useState("ALL");
  const [selectedHistoryItem, setSelectedHistoryItem] = useState(null);
  const [samples, setSamples] = useState(DEFAULT_SAMPLES);

  // Check Backend Connection on mount and periodically
  useEffect(() => {
    checkConnection();
    const interval = setInterval(checkConnection, 15000);
    return () => clearInterval(interval);
  }, []);

  async function checkConnection() {
    try {
      const res = await fetch(`${API_BASE}/api/health`, { method: "GET" }).catch(() =>
        fetch(`${API_BASE}/`)
      );
      if (res && res.ok) {
        setBackendStatus("Connected");
      } else {
        setBackendStatus("Disconnected");
      }
    } catch {
      setBackendStatus("Disconnected");
    }
  }

  // Load samples and history on start
  useEffect(() => {
    loadSamples();
    loadDashboardStats();
    loadHistory();
  }, []);

  async function loadSamples() {
    try {
      const res = await fetch(`${API_BASE}/api/samples`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) {
          setSamples(data);
        }
      }
    } catch (e) {
      console.warn("Using local samples fallback");
    }
  }

  async function loadDashboardStats() {
    try {
      const res = await fetch(`${API_BASE}/api/dashboard/stats`);
      if (res.ok) {
        const data = await res.json();
        setDashboardStats(data);
      }
    } catch (e) {
      console.warn("Could not load live dashboard stats");
    }
  }

  async function loadHistory() {
    try {
      const res = await fetch(`${API_BASE}/api/history?limit=50`);
      if (res.ok) {
        const data = await res.json();
        setHistoryList(data);
      }
    } catch (e) {
      console.warn("Could not load history list");
    }
  }

  // Handle Message Triage Analysis
  async function handleAnalyzeMessage(e) {
    if (e) e.preventDefault();
    setMessageError(null);

    const bodyText = messageBody.trim();
    if (!bodyText) {
      setMessageError("Please enter or paste message content before running triage analysis.");
      return;
    }

    setIsAnalyzingMessage(true);
    setMessageReport(null);

    let senderVal = sender.trim();
    if (!senderVal) {
      const match = bodyText.match(/From:\s*([^\r\n<]+<[^>]+>|[\w.-]+@[\w.-]+\.\w+)/i);
      senderVal = match ? match[1].trim() : "unspecified-sender@external.mail";
    }

    const payload = {
      subject: subject.trim() || "Message Triage",
      sender: senderVal,
      body: bodyText,
      create_incident: true
    };

    try {
      const res = await fetch(`${API_BASE}/api/analyze-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Server responded with HTTP ${res.status}`);
      }

      const report = await res.json();
      setMessageReport(report);
      loadDashboardStats();
      loadHistory();
    } catch (err) {
      setMessageError(
        `Analysis failed: ${err.message}. Ensure the backend is running at ${API_BASE}.`
      );
    } finally {
      setIsAnalyzingMessage(false);
    }
  }

  // Handle URL Triage Analysis
  async function handleAnalyzeUrl(e) {
    if (e) e.preventDefault();
    setUrlError(null);

    const rawUrl = targetUrl.trim();
    if (!rawUrl) {
      setUrlError("Please enter a target URL before initiating inspection.");
      return;
    }

    setIsAnalyzingUrl(true);
    setUrlReport(null);

    try {
      const res = await fetch(`${API_BASE}/api/analyze-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: rawUrl, create_incident: true })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Server error: HTTP ${res.status}`);
      }

      const report = await res.json();
      setUrlReport(report);
      loadDashboardStats();
      loadHistory();
    } catch (err) {
      setUrlError(`URL analysis failed: ${err.message}`);
    } finally {
      setIsAnalyzingUrl(false);
    }
  }

  function handleSelectSample(s) {
    if (s.data) {
      setSubject(s.data.subject || "");
      setSender(s.data.sender || "");
      setMessageBody(s.data.body || "");
      setMessageReport(null);
      setMessageError(null);
    }
  }

  function handleSelectSampleUrl(u) {
    setTargetUrl(u.url);
    setUrlReport(null);
    setUrlError(null);
  }

  function handleClearMessage() {
    setSubject("");
    setSender("");
    setMessageBody("");
    setMessageReport(null);
    setMessageError(null);
  }

  function handleClearUrl() {
    setTargetUrl("");
    setQrFile(null);
    if (qrPreview) {
      URL.revokeObjectURL(qrPreview);
      setQrPreview(null);
    }
    setUrlReport(null);
    setUrlError(null);
    setQrError(null);
  }

  function handleQrFileChange(e) {
    const file = e.target.files?.[0];
    if (file) {
      setQrFile(file);
      setQrError(null);
      setUrlReport(null);
      const previewUrl = URL.createObjectURL(file);
      setQrPreview(previewUrl);
    }
  }

  async function handleAnalyzeQr(e) {
    if (e) e.preventDefault();
    setQrError(null);

    if (!qrFile) {
      setQrError("Please select a QR-code image to analyze (.png, .jpg, .webp).");
      return;
    }

    setIsAnalyzingQr(true);
    setUrlReport(null);

    try {
      const formData = new FormData();
      formData.append("file", qrFile);

      const res = await fetch(`${API_BASE}/api/analyze-qr`, {
        method: "POST",
        body: formData
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Server error: HTTP ${res.status}`);
      }

      const report = await res.json();
      setUrlReport(report);
      loadDashboardStats();
      loadHistory();
    } catch (err) {
      setQrError(`QR analysis failed: ${err.message}`);
    } finally {
      setIsAnalyzingQr(false);
    }
  }

  function copyToClipboard(text, isUrl = false) {
    navigator.clipboard.writeText(text);
    if (isUrl) {
      setCopiedUrlReport(true);
      setTimeout(() => setCopiedUrlReport(false), 2500);
    } else {
      setCopiedMessageReport(true);
      setTimeout(() => setCopiedMessageReport(false), 2500);
    }
  }

  function downloadReport(report, filename = "phishguard_triage_report.json") {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", filename);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  // Handle PDF Security Report Download from Backend
  async function handleDownloadPdfReport(report, isUrl = false) {
    if (!report) return;
    const targetId = report.id || report.analysis_id;
    if (!targetId) return;

    setDownloadingPdfId(targetId);
    setPdfDownloadError(null);
    setPdfDownloadSuccess(null);

    const isQr = report.source_type === "qr_code_image" || (targetId && targetId.startsWith("QR-"));
    const endpoint = isQr 
      ? `${API_BASE}/api/report/qr`
      : (isUrl ? `${API_BASE}/api/report/url` : `${API_BASE}/api/report/email`);
    const payload = {
      analysis_id: targetId,
      id: targetId,
      ...report
    };

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Server returned HTTP ${res.status}`);
      }

      const blob = await res.blob();
      
      let filename = `PhishGuard_${isUrl ? "URL" : "Email"}_Report_${targetId}.pdf`;
      const disposition = res.headers.get("content-disposition");
      if (disposition && disposition.includes("filename=")) {
        const match = disposition.match(/filename="?([^";]+)"?/);
        if (match && match[1]) {
          filename = match[1].trim();
        }
      }

      const blobUrl = window.URL.createObjectURL(blob);
      const downloadAnchor = document.createElement("a");
      downloadAnchor.href = blobUrl;
      downloadAnchor.download = filename;
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      window.URL.revokeObjectURL(blobUrl);

      // Never display a successful download message before the download request succeeds!
      setPdfDownloadSuccess(`Downloaded report: ${filename}`);
      setTimeout(() => setPdfDownloadSuccess(null), 4000);
    } catch (err) {
      console.error("PDF download failed:", err);
      setPdfDownloadError(`PDF Download failed: ${err.message}`);
      setTimeout(() => setPdfDownloadError(null), 5000);
    } finally {
      setDownloadingPdfId(null);
    }
  }

  // Format Text Report for Clipboard
  function buildFormattedTextReport(report) {
    if (!report) return "";
    return `=====================================================
PHISHGUARD AI — TRIAGE ASSESSMENT REPORT
ID: ${report.id}
Timestamp: ${new Date(report.created_at).toUTCString()}
=====================================================
FINAL CLASSIFICATION: ${report.classification || "Unknown"}
RISK SCORE: ${report.risk_score} / 100 (${report.risk_level} Risk)
CONFIDENCE: ${report.confidence_score || "Moderate"}
IS SPAM: ${report.is_spam ? "YES" : "NO"}

SUBJECT / TARGET: ${report.subject}
SENDER: ${report.sender}

KEY INDICATORS DETECTED (${(report.indicator_details || []).length}):
${(report.indicator_details || [])
  .map((i, idx) => `  ${idx + 1}. [${i.severity}] ${i.category}: ${i.description}`)
  .join("\n")}

RECOMMENDED ACTIONS:
${(report.recommendations || []).map((r, idx) => `  - ${r}`).join("\n")}

DISCLAIMER:
Automated heuristic assessment. Does not guarantee 100% safety.
=====================================================`;
  }

  // Helper for Risk Theme
  function getRiskMeta(score, level) {
    const s = Number(score) || 0;
    if (s <= 24) {
      return { color: "#10b981", label: "Low Risk", bg: "rgba(16, 185, 129, 0.12)", border: "#10b981" };
    }
    if (s <= 49) {
      return { color: "#f59e0b", label: "Moderate Risk", bg: "rgba(245, 158, 11, 0.12)", border: "#f59e0b" };
    }
    if (s <= 74) {
      return { color: "#f97316", label: "High Risk", bg: "rgba(249, 115, 22, 0.12)", border: "#f97316" };
    }
    return { color: "#ef4444", label: "Critical Risk", bg: "rgba(239, 68, 68, 0.14)", border: "#ef4444" };
  }

  // Helper for Classification Badge
  function getClassificationBadge(classification, isSpam) {
    const cls = classification || (isSpam ? "Spam" : "Legitimate");
    if (cls === "Potential Phishing") {
      return <span className="classification-badge badge-phishing">⚠️ Potential Phishing</span>;
    }
    if (cls === "Spam" || isSpam) {
      return <span className="classification-badge badge-spam">📢 Unsolicited Spam</span>;
    }
    if (cls === "Suspicious") {
      return <span className="classification-badge badge-suspicious">⚡ Suspicious Message</span>;
    }
    return <span className="classification-badge badge-legitimate">✓ Legitimate / Benign</span>;
  }

  // Chart Data preparation
  const distributionData = dashboardStats?.risk_distribution
    ? [
        { name: "Low Risk", value: dashboardStats.risk_distribution.low, color: "#10b981" },
        { name: "Moderate", value: dashboardStats.risk_distribution.medium, color: "#f59e0b" },
        { name: "High Risk", value: dashboardStats.risk_distribution.high, color: "#f97316" },
        { name: "Critical", value: dashboardStats.risk_distribution.critical, color: "#ef4444" }
      ]
    : [
        { name: "Low Risk", value: 4, color: "#10b981" },
        { name: "Moderate", value: 3, color: "#f59e0b" },
        { name: "High Risk", value: 5, color: "#f97316" },
        { name: "Critical", value: 2, color: "#ef4444" }
      ];

  const trendData = dashboardStats?.daily_activity || [
    { date: "Oct 04", count: 2, avg_score: 22 },
    { date: "Oct 05", count: 4, avg_score: 45 },
    { date: "Oct 06", count: 3, avg_score: 60 },
    { date: "Oct 07", count: 6, avg_score: 55 },
    { date: "Oct 08", count: 5, avg_score: 38 },
    { date: "Oct 09", count: 8, avg_score: 72 },
    { date: "Oct 10", count: 4, avg_score: 30 }
  ];

  return (
    <div className="app-container">
      {/* Top Navigation */}
      <header className="app-navbar">
        <div className="brand-wrapper">
          <div className="brand-shield">
            <Shield size={24} />
          </div>
          <div>
            <div className="brand-name">
              PhishGuard <span>AI</span>
            </div>
            <div className="brand-tagline">Triage for Small Organizations</div>
          </div>
        </div>

        <nav className="nav-tabs">
          <button
            className={`nav-tab-btn ${activeTab === "message" ? "active" : ""}`}
            onClick={() => setActiveTab("message")}
          >
            <Mail size={16} /> Message Analysis
          </button>
          <button
            className={`nav-tab-btn ${activeTab === "url" ? "active" : ""}`}
            onClick={() => setActiveTab("url")}
          >
            <Globe size={16} /> URL Analysis
          </button>
          <button
            className={`nav-tab-btn ${activeTab === "dashboard" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("dashboard");
              loadDashboardStats();
            }}
          >
            <BarChart3 size={16} /> Dashboard
          </button>
          <button
            className={`nav-tab-btn ${activeTab === "history" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("history");
              loadHistory();
            }}
          >
            <History size={16} /> History
          </button>
          <button
            className={`nav-tab-btn ${activeTab === "about" ? "active" : ""}`}
            onClick={() => setActiveTab("about")}
          >
            <Info size={16} /> About & Guide
          </button>
        </nav>

        <div className="status-pill" title="FastAPI Backend Status">
          <span className={`pulse-dot ${backendStatus === "Connected" ? "online" : "offline"}`} />
          <span>{backendStatus === "Connected" ? "Backend Connected" : "Backend Offline"}</span>
        </div>
      </header>

      {/* Hero Header */}
      <section className="hero-section">
        <div className="eyebrow-pill">
          <Sparkles size={14} /> AI-POWERED PHISHING TRIAGE
        </div>
        <h1 className="hero-title">AI-Powered Phishing Triage</h1>
        <p className="hero-subtitle">Detect threats before they reach your organization.</p>
        <p className="hero-description">
          Analyze suspicious emails, messages, and URLs to instantly determine if content is{" "}
          <strong style={{ color: "#10b981" }}>Legitimate</strong>,{" "}
          <strong style={{ color: "#eab308" }}>Spam</strong>,{" "}
          <strong style={{ color: "#f59e0b" }}>Suspicious</strong>, or a{" "}
          <strong style={{ color: "#ef4444" }}>Potential Phishing Attack</strong>. Designed for small organizations
          without a dedicated SOC.
        </p>
      </section>

      {/* Main Content Area */}
      <main className="main-container">
        {/* =========================================================================
            TAB 1: MESSAGE ANALYSIS
           ========================================================================= */}
        {activeTab === "message" && (
          <div>
            <div className="card">
              <div className="card-header">
                <div className="card-title-group">
                  <div className="card-icon-badge">
                    <Mail size={22} />
                  </div>
                  <div>
                    <h2 className="card-title">Message & Email Threat Detection</h2>
                    <p className="card-desc">
                      Paste an email, SMS, chat message, or suspicious text to receive a rapid triage verdict.
                    </p>
                  </div>
                </div>
              </div>

              {/* Sample Chips */}
              <div className="sample-chips-bar">
                <span className="sample-chips-label">
                  <Zap size={13} /> Test Sample:
                </span>
                {samples.map((s) => (
                  <button
                    key={s.id}
                    className="sample-chip"
                    onClick={() => handleSelectSample(s)}
                    type="button"
                  >
                    <span className={`chip-dot ${s.type || "mod"}`} />
                    {s.title}
                  </button>
                ))}
              </div>

              {/* Input Form */}
              <form onSubmit={handleAnalyzeMessage}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label">Subject / Header (Optional)</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="e.g. Account Verification Required"
                      value={subject}
                      onChange={(e) => setSubject(e.target.value)}
                    />
                  </div>
                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label">Sender Email / Address (Optional)</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="e.g. alerts@service-update.com"
                      value={sender}
                      onChange={(e) => setSender(e.target.value)}
                    />
                  </div>
                </div>

                <div className="form-group">
                  <div className="form-label">
                    <span>Suspicious Message Content / Body *</span>
                    <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                      {messageBody.length} characters · {messageBody.trim() ? messageBody.trim().split(/\s+/).length : 0} words
                    </span>
                  </div>
                  <textarea
                    className="form-textarea"
                    placeholder="Paste the suspicious email, SMS, or chat text here..."
                    value={messageBody}
                    onChange={(e) => setMessageBody(e.target.value)}
                    required
                  />
                  <div className="form-footer-meta">
                    <span>Inspects urgent phrasing, impersonation, payment demands, and credential harvesting.</span>
                  </div>
                </div>

                {messageError && (
                  <div style={{ padding: "12px 16px", background: "rgba(239, 68, 68, 0.12)", border: "1px solid #ef4444", borderRadius: "8px", color: "#fca5a5", fontSize: "13px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
                    <AlertTriangle size={16} /> {messageError}
                  </div>
                )}

                <div className="action-row">
                  <button
                    type="submit"
                    className="btn-primary"
                    disabled={isAnalyzingMessage || !messageBody.trim()}
                  >
                    {isAnalyzingMessage ? (
                      <>
                        <RefreshCw size={16} className="animate-spin" /> Analyzing Message Threat...
                      </>
                    ) : (
                      <>
                        <ShieldAlert size={16} /> Analyze Message
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={handleClearMessage}
                    disabled={isAnalyzingMessage}
                  >
                    <Trash2 size={15} /> Clear
                  </button>
                </div>
              </form>
            </div>

            {/* Message Report */}
            {messageReport && (
              <ReportDisplay
                report={messageReport}
                isUrlView={false}
                onCopy={() => copyToClipboard(buildFormattedTextReport(messageReport), false)}
                copied={copiedMessageReport}
                onDownload={() => downloadReport(messageReport, `triage_report_${messageReport.id}.json`)}
                onDownloadPdf={() => handleDownloadPdfReport(messageReport, false)}
                isDownloadingPdf={downloadingPdfId === messageReport.id}
                pdfDownloadError={pdfDownloadError}
                pdfDownloadSuccess={pdfDownloadSuccess}
              />
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 2: URL ANALYSIS
           ========================================================================= */}
        {activeTab === "url" && (
          <div>
            <div className="card">
              <div className="card-header">
                <div className="card-title-group">
                  <div className="card-icon-badge">
                    <Globe size={22} />
                  </div>
                  <div>
                    <h2 className="card-title">Static URL & QR-Code Threat Triage</h2>
                    <p className="card-desc">
                      Inspect target URLs and uploaded QR codes statically without clicking or executing them. Defangs links safely.
                    </p>
                  </div>
                </div>
              </div>

              {/* Ingestion Mode Switcher */}
              <div style={{ display: "flex", gap: "10px", padding: "0 24px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
                <button
                  type="button"
                  className={`btn-secondary ${urlInputMode === "url" ? "active" : ""}`}
                  style={{
                    padding: "7px 16px",
                    fontSize: "12px",
                    fontWeight: "600",
                    background: urlInputMode === "url" ? "rgba(56, 189, 248, 0.15)" : "transparent",
                    borderColor: urlInputMode === "url" ? "#38bdf8" : "var(--border-subtle)",
                    color: urlInputMode === "url" ? "#38bdf8" : "var(--text-muted)"
                  }}
                  onClick={() => { setUrlInputMode("url"); setQrError(null); }}
                >
                  <Globe size={14} style={{ marginRight: "6px", verticalAlign: "middle" }} />
                  Direct URL String
                </button>
                <button
                  type="button"
                  className={`btn-secondary ${urlInputMode === "qr" ? "active" : ""}`}
                  style={{
                    padding: "7px 16px",
                    fontSize: "12px",
                    fontWeight: "600",
                    background: urlInputMode === "qr" ? "rgba(168, 85, 247, 0.15)" : "transparent",
                    borderColor: urlInputMode === "qr" ? "#a855f7" : "var(--border-subtle)",
                    color: urlInputMode === "qr" ? "#c084fc" : "var(--text-muted)"
                  }}
                  onClick={() => { setUrlInputMode("qr"); setUrlError(null); }}
                >
                  <QrCode size={14} style={{ marginRight: "6px", verticalAlign: "middle" }} />
                  QR-Code Image (Quishing Triage)
                </button>
              </div>

              {urlInputMode === "qr" ? (
                /* QR-Code Image Upload Mode */
                <form onSubmit={handleAnalyzeQr} style={{ padding: "20px 24px" }}>
                  <div className="form-group">
                    <label className="form-label">
                      <span>Upload QR-Code Image *</span>
                      <span style={{ color: "#c084fc", fontSize: "11px" }}>Optical Decoding without Link Execution</span>
                    </label>
                    <div
                      style={{
                        border: "2px dashed rgba(168, 85, 247, 0.4)",
                        borderRadius: "10px",
                        padding: "24px",
                        textAlign: "center",
                        background: "rgba(15, 23, 42, 0.4)",
                        cursor: "pointer",
                        position: "relative"
                      }}
                      onClick={() => document.getElementById("qr-file-input")?.click()}
                    >
                      <input
                        id="qr-file-input"
                        type="file"
                        accept="image/png,image/jpeg,image/webp,image/bmp,image/gif"
                        style={{ display: "none" }}
                        onChange={handleQrFileChange}
                      />
                      {qrPreview ? (
                        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "10px" }}>
                          <img
                            src={qrPreview}
                            alt="QR Preview"
                            style={{ maxHeight: "150px", maxWidth: "150px", borderRadius: "8px", border: "2px solid #a855f7" }}
                          />
                          <span style={{ fontSize: "12px", color: "#c084fc", fontWeight: "600" }}>
                            {qrFile?.name} ({(qrFile?.size / 1024).toFixed(1)} KB)
                          </span>
                          <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>Click to select another image</span>
                        </div>
                      ) : (
                        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "8px" }}>
                          <UploadCloud size={32} style={{ color: "#a855f7" }} />
                          <span style={{ fontSize: "14px", fontWeight: "600", color: "#f8fafc" }}>
                            Click to browse or drop QR-code image here
                          </span>
                          <span style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                            PNG, JPEG, WebP, BMP, GIF (Max 5MB, up to 4096x4096px)
                          </span>
                        </div>
                      )}
                    </div>
                    <div className="form-footer-meta">
                      <span>Decodes QR optical matrix safely offline. Never navigates to or executes decoded links.</span>
                    </div>
                  </div>

                  {qrError && (
                    <div style={{ padding: "12px 16px", background: "rgba(239, 68, 68, 0.12)", border: "1px solid #ef4444", borderRadius: "8px", color: "#fca5a5", fontSize: "13px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
                      <AlertTriangle size={16} /> {qrError}
                    </div>
                  )}

                  <div className="action-row">
                    <button
                      type="submit"
                      className="btn-primary"
                      disabled={isAnalyzingQr || !qrFile}
                      style={{ background: "#7e22ce", borderColor: "#a855f7" }}
                    >
                      {isAnalyzingQr ? (
                        <>
                          <RefreshCw size={16} className="animate-spin" /> Decoding QR Optical Matrix...
                        </>
                      ) : (
                        <>
                          <QrCode size={16} /> Analyze QR Image
                        </>
                      )}
                    </button>

                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={handleClearUrl}
                      disabled={isAnalyzingQr}
                    >
                      <Trash2 size={15} /> Clear
                    </button>
                  </div>
                </form>
              ) : (
                /* Direct URL Mode */
                <>
                  <div className="sample-chips-bar">
                    <span className="sample-chips-label">
                      <Zap size={13} /> Test Target:
                    </span>
                    {SAMPLE_URLS.map((u, i) => (
                      <button
                        key={i}
                        className="sample-chip"
                        onClick={() => handleSelectSampleUrl(u)}
                        type="button"
                      >
                        <span className="chip-dot mod" />
                        {u.label}
                      </button>
                    ))}
                  </div>

                  <form onSubmit={handleAnalyzeUrl}>
                    <div className="form-group">
                      <label className="form-label">
                        <span>Target URL to Inspect *</span>
                        <span style={{ color: "#38bdf8", fontSize: "11px" }}>Safe Offline Heuristic Inspection</span>
                      </label>
                      <input
                        type="text"
                        className="form-input"
                        placeholder="e.g. http://185.193.12.84/m365/login or http://xn--pple-43d.com"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        required
                      />
                      <div className="form-footer-meta">
                        <span>Checks IDN homoglyphs, bare IP hosts, high-risk TLDs, punycode, and URL shorteners.</span>
                      </div>
                    </div>

                    {urlError && (
                      <div style={{ padding: "12px 16px", background: "rgba(239, 68, 68, 0.12)", border: "1px solid #ef4444", borderRadius: "8px", color: "#fca5a5", fontSize: "13px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
                        <AlertTriangle size={16} /> {urlError}
                      </div>
                    )}

                    <div className="action-row">
                      <button
                        type="submit"
                        className="btn-primary"
                        disabled={isAnalyzingUrl || !targetUrl.trim()}
                      >
                        {isAnalyzingUrl ? (
                          <>
                            <RefreshCw size={16} className="animate-spin" /> Inspecting URL Structure...
                          </>
                        ) : (
                          <>
                            <Globe size={16} /> Analyze URL
                          </>
                        )}
                      </button>

                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={handleClearUrl}
                        disabled={isAnalyzingUrl}
                      >
                        <Trash2 size={15} /> Clear
                      </button>
                    </div>
                  </form>
                </>
              )}
            </div>

            {/* URL Report */}
            {urlReport && (
              <ReportDisplay
                report={urlReport}
                isUrlView={true}
                onCopy={() => copyToClipboard(buildFormattedTextReport(urlReport), true)}
                copied={copiedUrlReport}
                onDownload={() => downloadReport(urlReport, `url_triage_${urlReport.id}.json`)}
                onDownloadPdf={() => handleDownloadPdfReport(urlReport, true)}
                isDownloadingPdf={downloadingPdfId === urlReport.id}
                pdfDownloadError={pdfDownloadError}
                pdfDownloadSuccess={pdfDownloadSuccess}
              />
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 3: DASHBOARD
           ========================================================================= */}
        {activeTab === "dashboard" && (
          <div>
            {/* Top Stat Cards */}
            <div className="metrics-grid">
              <div className="metric-card">
                <div className="metric-card-top">
                  <span className="metric-label">TOTAL ANALYZED</span>
                  <div className="metric-icon-box" style={{ color: "#38bdf8" }}>
                    <FileText size={20} />
                  </div>
                </div>
                <div className="metric-value">{dashboardStats?.total_emails_analyzed ?? 0}</div>
                <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Real database analysis records</div>
              </div>

              <div className="metric-card">
                <div className="metric-card-top">
                  <span className="metric-label">POTENTIAL PHISHING</span>
                  <div className="metric-icon-box" style={{ color: "#ef4444" }}>
                    <ShieldAlert size={20} />
                  </div>
                </div>
                <div className="metric-value" style={{ color: "#ef4444" }}>
                  {dashboardStats?.phishing_count ?? dashboardStats?.high_critical_count ?? 0}
                </div>
                <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>High or Critical threat severity</div>
              </div>

              <div className="metric-card">
                <div className="metric-card-top">
                  <span className="metric-label">UNSOLICITED SPAM</span>
                  <div className="metric-icon-box" style={{ color: "#eab308" }}>
                    <AlertTriangle size={20} />
                  </div>
                </div>
                <div className="metric-value" style={{ color: "#eab308" }}>
                  {dashboardStats?.spam_count ?? 0}
                </div>
                <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Bulk marketing & prize scams</div>
              </div>

              <div className="metric-card">
                <div className="metric-card-top">
                  <span className="metric-label">SUSPICIOUS MESSAGES</span>
                  <div className="metric-icon-box" style={{ color: "#f59e0b" }}>
                    <AlertCircle size={20} />
                  </div>
                </div>
                <div className="metric-value" style={{ color: "#f59e0b" }}>
                  {dashboardStats?.suspicious_count ?? dashboardStats?.risk_distribution?.medium ?? 0}
                </div>
                <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Moderate risk (Score 25-49)</div>
              </div>

              <div className="metric-card">
                <div className="metric-card-top">
                  <span className="metric-label">LEGITIMATE / LOW RISK</span>
                  <div className="metric-icon-box" style={{ color: "#10b981" }}>
                    <ShieldCheck size={20} />
                  </div>
                </div>
                <div className="metric-value" style={{ color: "#10b981" }}>
                  {dashboardStats?.legitimate_count ?? dashboardStats?.risk_distribution?.low ?? 0}
                </div>
                <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Low risk baseline (Score 0-24)</div>
              </div>
            </div>

            {/* Visual Charts Row */}
            <div className="charts-row">
              <div className="chart-card">
                <div className="chart-title">
                  <PieChart size={18} style={{ color: "#00f0ff" }} /> Risk Classification Distribution
                </div>
                <div style={{ height: "240px", width: "100%" }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={distributionData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        innerRadius={45}
                        paddingAngle={4}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      >
                        {distributionData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: "#0b1a30", borderColor: "#1e3a62", borderRadius: "8px", fontSize: "12px" }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="chart-card">
                <div className="chart-title">
                  <TrendingUp size={18} style={{ color: "#00f0ff" }} /> 7-Day Triage Volume & Trend
                </div>
                <div style={{ height: "240px", width: "100%" }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={trendData}>
                      <defs>
                        <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#00f0ff" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
                      <YAxis stroke="#64748b" fontSize={11} />
                      <Tooltip
                        contentStyle={{ background: "#0b1a30", borderColor: "#1e3a62", borderRadius: "8px", fontSize: "12px" }}
                      />
                      <Area type="monotone" dataKey="count" stroke="#00f0ff" fillOpacity={1} fill="url(#colorCount)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* Recent Analyses in Dashboard */}
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Recent Triage Analyses</h3>
                <button
                  className="btn-secondary"
                  style={{ padding: "6px 14px", fontSize: "12px" }}
                  onClick={loadDashboardStats}
                >
                  <RefreshCw size={13} /> Refresh Data
                </button>
              </div>

              <div className="table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Analysis ID</th>
                      <th>Subject / Destination</th>
                      <th>Verdict</th>
                      <th>Score</th>
                      <th>Timestamp</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(dashboardStats?.recent_analyses || []).length > 0 ? (
                      dashboardStats.recent_analyses.map((item) => (
                        <tr key={item.id}>
                          <td><code>{item.id}</code></td>
                          <td style={{ maxWidth: "240px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                            {item.subject}
                          </td>
                          <td>{getClassificationBadge(item.classification, item.is_spam)}</td>
                          <td>
                            <strong style={{ color: getRiskMeta(item.risk_score).color }}>
                              {item.risk_score}
                            </strong>
                          </td>
                          <td style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                            {new Date(item.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                          </td>
                          <td>
                            <button
                              className="btn-secondary"
                              style={{ padding: "4px 10px", fontSize: "11px" }}
                              onClick={() => setSelectedHistoryItem(item)}
                            >
                              <Eye size={12} /> View
                            </button>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={6} style={{ textAlign: "center", color: "var(--text-dim)", padding: "24px" }}>
                          No analysis records found. Analyze a message or URL above to populate real metrics.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 4: ANALYSIS HISTORY
           ========================================================================= */}
        {activeTab === "history" && (
          <div>
            <div className="card">
              <div className="card-header">
                <div className="card-title-group">
                  <div className="card-icon-badge">
                    <History size={22} />
                  </div>
                  <div>
                    <h2 className="card-title">Analysis Records & Audit Log</h2>
                    <p className="card-desc">Search and filter historical threat analyses persisted in your database.</p>
                  </div>
                </div>

                <a
                  href={`${API_BASE}/api/reports/export/csv`}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-secondary"
                  style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}
                >
                  <Download size={14} /> Export CSV Report
                </a>
              </div>

              {/* Filters */}
              <div style={{ display: "flex", gap: "12px", marginBottom: "20px", flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: "220px", position: "relative" }}>
                  <Search size={16} style={{ position: "absolute", left: "14px", top: "14px", color: "var(--text-dim)" }} />
                  <input
                    type="text"
                    className="form-input"
                    style={{ paddingLeft: "38px" }}
                    placeholder="Search by subject, sender, or content snippet..."
                    value={historySearch}
                    onChange={(e) => setHistorySearch(e.target.value)}
                  />
                </div>

                <select
                  className="form-input"
                  style={{ width: "auto", minWidth: "180px" }}
                  value={historyFilter}
                  onChange={(e) => setHistoryFilter(e.target.value)}
                >
                  <option value="ALL">All Verdicts</option>
                  <option value="Potential Phishing">Potential Phishing</option>
                  <option value="Spam">Spam</option>
                  <option value="Suspicious">Suspicious</option>
                  <option value="Legitimate">Legitimate / Low</option>
                </select>

                <button className="btn-secondary" onClick={loadHistory}>
                  <RefreshCw size={14} />
                </button>
              </div>

              {/* History Table */}
              <div className="table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Record ID</th>
                      <th>Subject / Title</th>
                      <th>Sender / Origin</th>
                      <th>Verdict</th>
                      <th>Score</th>
                      <th>Timestamp</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historyList
                      .filter((item) => {
                        if (historyFilter !== "ALL") {
                          if (historyFilter === "Spam" && !item.is_spam && item.classification !== "Spam") return false;
                          if (historyFilter !== "Spam" && item.classification !== historyFilter) return false;
                        }
                        if (historySearch.trim()) {
                          const q = historySearch.toLowerCase();
                          return (
                            item.subject?.toLowerCase().includes(q) ||
                            item.sender?.toLowerCase().includes(q) ||
                            item.id?.toLowerCase().includes(q)
                          );
                        }
                        return true;
                      })
                      .map((item) => (
                        <tr key={item.id}>
                          <td><code>{item.id}</code></td>
                          <td style={{ maxWidth: "280px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                            {item.subject}
                          </td>
                          <td style={{ maxWidth: "200px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", color: "var(--text-muted)" }}>
                            {item.sender}
                          </td>
                          <td>{getClassificationBadge(item.classification, item.is_spam)}</td>
                          <td>
                            <strong style={{ color: getRiskMeta(item.risk_score).color }}>
                              {item.risk_score}
                            </strong>
                          </td>
                          <td style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                            {new Date(item.created_at).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}
                          </td>
                          <td>
                            <button
                              className="btn-secondary"
                              style={{ padding: "4px 10px", fontSize: "11px" }}
                              onClick={() => setSelectedHistoryItem(item)}
                            >
                              <Eye size={12} /> Inspect
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 5: ABOUT & GUIDE
           ========================================================================= */}
        {activeTab === "about" && (
          <div className="about-grid">
            <div className="about-card">
              <h3>
                <Shield size={20} /> Hybrid Detection Pipeline
              </h3>
              <p>
                PhishGuard AI employs a defense-in-depth triage methodology tailored specifically for small organizations:
              </p>
              <ul>
                <li><strong>1. Input Normalization:</strong> Strips obfuscated wrappers, normalizes leetspeak, and extracts embedded links and attachments safely.</li>
                <li><strong>2. Rule-Based Lexical Heuristics:</strong> Inspects coercive urgency, false account suspension warnings, and credential harvesting lures.</li>
                <li><strong>3. Brand Mimicry & Typosquatting:</strong> Computes Levenshtein distance against high-profile targets to catch lookalike domains.</li>
                <li><strong>4. Spam & Bulk Lure Detection:</strong> Evaluates promotional scams, fake crypto multipliers, and lottery lures to distinguish spam from phishing.</li>
              </ul>
            </div>

            <div className="about-card">
              <h3>
                <AlertTriangle size={20} /> Transparent Limitations
              </h3>
              <p>
                Automated heuristic triage can produce both false positives and false negatives. Please keep the following principles in mind:
              </p>
              <ul>
                <li><strong>No Guaranteed Safety:</strong> A "Low Risk" (0–24) score indicates that no known static attack markers were flagged. It does not certify a message as 100% safe.</li>
                <li><strong>Zero-Day & BEC:</strong> Compromised legitimate vendor accounts or highly personalized social engineering may lack conspicuous static markers.</li>
                <li><strong>Independent Verification:</strong> Always confirm unusual financial or credential requests through established out-of-band channels.</li>
              </ul>
            </div>

            <div className="about-card">
              <h3>
                <Lock size={20} /> Privacy Notice & Link Safety
              </h3>
              <p>
                How PhishGuard AI handles and secures submitted message content:
              </p>
              <ul>
                <li><strong>No Live Execution:</strong> Links submitted for analysis are inspected statically and defanged (`hxxp://...[.]com`). They are never loaded or followed.</li>
                <li><strong>Privacy-Conscious Retention:</strong> Full raw email bodies can be configured not to persist long-term in the SQLite database (`RETAIN_FULL_BODY=False`).</li>
                <li><strong>Local First:</strong> The detection engine runs fully offline on your own local server without transmitting message contents to third-party endpoints.</li>
              </ul>
            </div>

            <div className="about-card">
              <h3>
                <CheckCircle2 size={20} /> Small Organization Response Protocol
              </h3>
              <p>
                Recommended action steps when an employee receives a suspicious message:
              </p>
              <ul>
                <li>1. <strong>Do Not Click:</strong> Do not open embedded links or download attachments.</li>
                <li>2. <strong>Do Not Reply:</strong> Replying confirms active mailbox ownership to attackers.</li>
                <li>3. <strong>Triage & Quarantine:</strong> Paste content into PhishGuard AI. If risk score is ≥ 50, notify your IT administrator immediately.</li>
                <li>4. <strong>Password Revocation:</strong> If credentials were entered, immediately reset passwords and terminate all active sessions.</li>
              </ul>
            </div>
          </div>
        )}
      </main>

      {/* Modal for Viewing History Item */}
      {selectedHistoryItem && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0, 0, 0, 0.75)", backdropFilter: "blur(4px)", zIndex: 1000, display: "flex", justifyContent: "center", alignItems: "center", padding: "20px" }}>
          <div style={{ background: "var(--bg-card)", border: "1px solid var(--border-medium)", borderRadius: "var(--radius-lg)", width: "min(840px, 95%)", maxHeight: "90vh", overflowY: "auto", padding: "28px", position: "relative" }}>
            <button
              onClick={() => setSelectedHistoryItem(null)}
              style={{ position: "absolute", top: "18px", right: "18px", background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
            >
              <X size={20} />
            </button>
            <ReportDisplay
              report={selectedHistoryItem}
              isUrlView={selectedHistoryItem.analysis_type === "url"}
              onCopy={() => copyToClipboard(buildFormattedTextReport(selectedHistoryItem))}
              copied={copiedMessageReport}
              onDownload={() => downloadReport(selectedHistoryItem, `triage_${selectedHistoryItem.id}.json`)}
            />
          </div>
        </div>
      )}
    </div>
  );
}

// =========================================================================
// Subcomponent: Full Triage Report Display
// =========================================================================
function ReportDisplay({
  report,
  isUrlView = false,
  onCopy,
  copied,
  onDownload,
  onDownloadPdf,
  isDownloadingPdf,
  pdfDownloadError,
  pdfDownloadSuccess
}) {
  if (!report) return null;

  const riskMeta = (() => {
    const s = Number(report.risk_score) || 0;
    if (s <= 24) return { color: "#10b981", label: "Low Risk", bg: "rgba(16, 185, 129, 0.12)" };
    if (s <= 49) return { color: "#f59e0b", label: "Moderate Risk", bg: "rgba(245, 158, 11, 0.12)" };
    if (s <= 74) return { color: "#f97316", label: "High Risk", bg: "rgba(249, 115, 22, 0.12)" };
    return { color: "#ef4444", label: "Critical Risk", bg: "rgba(239, 68, 68, 0.14)" };
  })();

  const classification = report.classification || (report.is_spam ? "Spam" : "Legitimate");

  return (
    <div className="report-panel">
      {/* Top Banner */}
      <div className="report-header-banner">
        <div>
          <span style={{ fontSize: "11px", color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "1px" }}>
            Triage ID: {report.id} · {new Date(report.created_at).toLocaleTimeString()}
          </span>
          <h2 style={{ fontSize: "22px", fontWeight: "800", color: "#f8fafc", marginTop: "4px" }}>
            Security Assessment Report
          </h2>
        </div>

        <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
          {classification === "Potential Phishing" && (
            <span className="classification-badge badge-phishing">⚠️ Potential Phishing</span>
          )}
          {classification === "Spam" && (
            <span className="classification-badge badge-spam">📢 Unsolicited Spam</span>
          )}
          {classification === "Suspicious" && (
            <span className="classification-badge badge-suspicious">⚡ Suspicious Message</span>
          )}
          {classification === "Legitimate" && (
            <span className="classification-badge badge-legitimate">✓ Legitimate / Low Risk</span>
          )}

          <button
            className="btn-primary"
            onClick={onDownloadPdf}
            disabled={isDownloadingPdf}
            style={{
              padding: "8px 14px",
              fontSize: "12px",
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              cursor: isDownloadingPdf ? "wait" : "pointer"
            }}
            title="Download Official PDF Security Report"
          >
            <FileText size={13} /> {isDownloadingPdf ? "Generating PDF..." : "Download PDF"}
          </button>
          <button className="btn-secondary" onClick={onCopy} style={{ padding: "8px 14px", fontSize: "12px" }}>
            <Copy size={13} /> {copied ? "Copied!" : "Copy Report"}
          </button>
          <button className="btn-secondary" onClick={onDownload} style={{ padding: "8px 14px", fontSize: "12px" }}>
            <Download size={13} /> JSON
          </button>
        </div>
      </div>

      {/* PDF Download Feedback */}
      {pdfDownloadSuccess && (
        <div style={{ padding: "10px 16px", background: "rgba(16, 185, 129, 0.12)", border: "1px solid #10b981", borderRadius: "8px", color: "#a7f3d0", fontSize: "13px", marginTop: "12px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
          <CheckCircle2 size={16} /> {pdfDownloadSuccess}
        </div>
      )}
      {pdfDownloadError && (
        <div style={{ padding: "10px 16px", background: "rgba(239, 68, 68, 0.12)", border: "1px solid #ef4444", borderRadius: "8px", color: "#fca5a5", fontSize: "13px", marginTop: "12px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
          <AlertTriangle size={16} /> {pdfDownloadError}
        </div>
      )}

      {/* QR Code Ingestion Details (If Present) */}
      {(report.source_type === "qr_code_image" || report.qr_detected) && (
        <div style={{ background: "rgba(168, 85, 247, 0.08)", border: "1px solid rgba(168, 85, 247, 0.35)", borderRadius: "8px", padding: "14px 18px", marginBottom: "20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px", flexWrap: "wrap", gap: "8px" }}>
            <span style={{ fontSize: "14px", fontWeight: "700", color: "#c084fc", display: "flex", alignItems: "center", gap: "6px" }}>
              <QrCode size={16} /> Optical QR-Code Ingestion
            </span>
            <span style={{ fontSize: "11px", color: "#e9d5ff", background: "rgba(168, 85, 247, 0.2)", padding: "2px 8px", borderRadius: "4px", fontWeight: "600" }}>
              Codes Extracted: {report.qr_count || 1}
            </span>
          </div>
          <div style={{ fontSize: "13px", color: "#cbd5e1", lineHeight: "1.6" }}>
            <div>
              <span style={{ color: "var(--text-dim)" }}>Decoded Content (Defanged): </span>
              <code style={{ color: "#a855f7", wordBreak: "break-all", background: "rgba(0,0,0,0.3)", padding: "2px 6px", borderRadius: "4px" }}>
                {report.defanged_content || report.decoded_content || report.defanged_url}
              </code>
            </div>
            {report.features && (
              <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", fontSize: "11px", color: "var(--text-dim)", marginTop: "6px" }}>
                {report.features.image_width && <span>Dimensions: {report.features.image_width}×{report.features.image_height}px</span>}
                {report.features.image_format && <span>Format: {report.features.image_format}</span>}
                {report.features.file_size_bytes && <span>Size: {(report.features.file_size_bytes / 1024).toFixed(1)} KB</span>}
                <span>Mode: Static Offline Extraction</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Internationalized Domain / Homoglyph Breakdown (If Present) */}
      {report.features && (report.features.is_punycode || report.features.is_mixed_script || report.features.decoded_hostname) && report.features.decoded_hostname !== report.features.hostname && (
        <div style={{ background: "rgba(14, 165, 233, 0.08)", border: "1px solid rgba(14, 165, 233, 0.35)", borderRadius: "8px", padding: "14px 18px", marginBottom: "20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px", flexWrap: "wrap", gap: "8px" }}>
            <span style={{ fontSize: "14px", fontWeight: "700", color: "#38bdf8", display: "flex", alignItems: "center", gap: "6px" }}>
              <Globe size={16} /> Internationalized Domain & Homoglyph Intelligence
            </span>
            {report.features.is_mixed_script ? (
              <span style={{ fontSize: "11px", color: "#ef4444", background: "rgba(239, 68, 68, 0.15)", border: "1px solid #ef4444", padding: "2px 8px", borderRadius: "4px", fontWeight: "700" }}>
                ⚠️ Mixed-Script Lookalike
              </span>
            ) : (
              <span style={{ fontSize: "11px", color: "#10b981", background: "rgba(16, 185, 129, 0.15)", border: "1px solid #10b981", padding: "2px 8px", borderRadius: "4px", fontWeight: "600" }}>
                ✓ Single-Script IDN
              </span>
            )}
          </div>
          <div style={{ fontSize: "13px", color: "#cbd5e1", lineHeight: "1.6" }}>
            <div>
              <span style={{ color: "var(--text-dim)" }}>Punycode Hostname: </span>
              <code style={{ color: "#38bdf8" }}>{report.features.hostname}</code>
            </div>
            <div>
              <span style={{ color: "var(--text-dim)" }}>Decoded Unicode Hostname: </span>
              <strong style={{ color: "#f8fafc" }}>{report.features.decoded_hostname}</strong>
            </div>
            {report.features.scripts_detected && (
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>
                Scripts Detected: <strong style={{ color: "#94a3b8" }}>{report.features.scripts_detected.join(", ")}</strong>
              </div>
            )}
            {report.features.homoglyph_brand_target && (
              <div style={{ color: "#f87171", marginTop: "4px", fontWeight: "600" }}>
                Target Brand Impersonation: '{report.features.homoglyph_brand_target}'
              </div>
            )}
          </div>
        </div>
      )}

      {/* Visual Risk Meter */}
      <div className="meter-wrapper">
        <div className="meter-header">
          <div className="meter-score-display">
            <span className="meter-score-number" style={{ color: riskMeta.color }}>
              {Number(report.risk_score).toFixed(1)}
            </span>
            <span className="meter-score-max">/ 100</span>
            <span style={{ marginLeft: "12px", fontSize: "13px", fontWeight: "700", color: riskMeta.color, background: riskMeta.bg, padding: "3px 10px", borderRadius: "12px" }}>
              {riskMeta.label}
            </span>
          </div>

          <div style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Model Confidence: <strong>{report.confidence_score || "Moderate (70%)"}</strong>
          </div>
        </div>

        <div className="meter-track">
          <div
            className="meter-fill"
            style={{
              width: `${Math.min(100, Math.max(5, report.risk_score))}%`,
              background: riskMeta.color
            }}
          />
        </div>

        <div className="meter-scale-markers">
          <span style={{ color: "#10b981" }}>0 Low Risk (0–24)</span>
          <span style={{ color: "#f59e0b" }}>25 Moderate (25–49)</span>
          <span style={{ color: "#f97316" }}>50 High Risk (50–74)</span>
          <span style={{ color: "#ef4444" }}>75 Critical (75–100)</span>
        </div>

        <div className="meter-disclaimer">
          <Info size={13} />
          <span>Automated heuristic score is an estimate based on available signals, not a guarantee of safety.</span>
        </div>
      </div>

      {/* Spam Specific Notice */}
      {classification === "Spam" && (
        <div style={{ background: "rgba(234, 179, 8, 0.1)", border: "1px solid rgba(234, 179, 8, 0.35)", borderRadius: "8px", padding: "14px 18px", marginBottom: "20px", display: "flex", alignItems: "flex-start", gap: "12px" }}>
          <AlertTriangle size={20} style={{ color: "#eab308", flexShrink: 0, marginTop: "2px" }} />
          <div>
            <strong style={{ color: "#fef08a", fontSize: "14px", display: "block", marginBottom: "4px" }}>
              Spam Classification Confirmed
            </strong>
            <p style={{ margin: 0, fontSize: "13px", color: "#fef9c3", lineHeight: "1.5" }}>
              This message has been classified as <strong>Unsolicited Bulk Spam / Promotional Scam</strong>. While it contains high-pressure marketing buzzwords, lottery winnings, or aggressive claims, it does not appear to be an active targeted credential-harvesting phishing attack.
            </p>
          </div>
        </div>
      )}

      {/* AI Spam Model Telemetry (If Present) */}
      {report.model_name && (
        <div style={{ background: "rgba(2, 132, 199, 0.08)", border: "1px solid rgba(2, 132, 199, 0.3)", borderRadius: "8px", padding: "14px 18px", marginBottom: "20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px", flexWrap: "wrap", gap: "8px" }}>
            <span style={{ fontSize: "14px", fontWeight: "700", color: "#38bdf8", display: "flex", alignItems: "center", gap: "6px" }}>
              <Sparkles size={16} /> Pretrained DistilBERT Spam Classifier
            </span>
            <span style={{ fontSize: "11px", color: "var(--text-dim)", fontFamily: "monospace", background: "rgba(255,255,255,0.06)", padding: "2px 8px", borderRadius: "4px" }}>
              Inference Device: <strong>{report.inference_device || "CPU"}</strong>
            </span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "10px", fontSize: "12px" }}>
            <div>
              <span style={{ color: "var(--text-dim)" }}>Pretrained Model: </span>
              <span style={{ color: "#f8fafc", fontFamily: "monospace" }}>{report.model_name}</span>
            </div>
            <div>
              <span style={{ color: "var(--text-dim)" }}>Raw Model Output: </span>
              <strong style={{ color: "#38bdf8" }}>{report.model_label || "LABEL_0"}</strong>
            </div>
            <div>
              <span style={{ color: "var(--text-dim)" }}>Model Classification Score: </span>
              <strong style={{ color: "#10b981" }}>{(Number(report.classification_score || 0) * 100).toFixed(1)}%</strong>
            </div>
          </div>
          <p style={{ margin: "8px 0 0 0", fontSize: "11px", color: "var(--text-dim)", fontStyle: "italic" }}>
            Note: The DistilBERT model detects promotional and unsolicited spam. Overall phishing triage risk is calculated separately by PhishGuard's multi-layered heuristic risk engine.
          </p>
        </div>
      )}

      {/* Highlighted Suspicious Phrases */}
      {Array.isArray(report.highlighted_phrases) && report.highlighted_phrases.length > 0 && (
        <div className="phrases-container">
          <h3 style={{ fontSize: "15px", fontWeight: "700", color: "#38bdf8", marginBottom: "8px", display: "flex", alignItems: "center", gap: "8px" }}>
            <Eye size={16} /> Highlighted Suspicious Phrases ({report.highlighted_phrases.length})
          </h3>
          <div className="phrases-list">
            {report.highlighted_phrases.map((item, idx) => (
              <div key={idx} className={`phrase-item ${item.category?.toLowerCase().includes("spam") ? "spam" : ""}`}>
                <span className="phrase-token">"{item.phrase}"</span>
                <div>
                  <strong style={{ color: "#ffffff", marginRight: "8px" }}>[{item.category}]</strong>
                  <span style={{ color: "var(--text-muted)" }}>{item.explanation}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Key Suspicious Indicators */}
      {Array.isArray(report.indicator_details) && report.indicator_details.length > 0 ? (
        <div style={{ marginBottom: "24px" }}>
          <h3 style={{ fontSize: "15px", fontWeight: "700", color: "#38bdf8", marginBottom: "8px", display: "flex", alignItems: "center", gap: "8px" }}>
            <AlertTriangle size={16} /> Key Security Indicators ({report.indicator_details.length} Flagged)
          </h3>
          <div className="indicator-grid">
            {report.indicator_details.map((ind, idx) => (
              <div key={idx} className="indicator-card">
                <div className="indicator-header">
                  <strong style={{ color: "#f8fafc", fontSize: "14px" }}>{ind.category}</strong>
                  <span className={`severity-chip sev-${ind.severity || "Medium"}`}>{ind.severity || "Medium"}</span>
                </div>
                <p style={{ margin: "4px 0", fontSize: "13px", color: "#cbd5e1" }}>{ind.description}</p>
                {ind.evidence && (
                  <div style={{ marginTop: "6px", fontSize: "12px", color: "var(--text-dim)", fontFamily: "monospace" }}>
                    Evidence: {ind.evidence}
                  </div>
                )}
                {ind.why_it_matters && (
                  <div style={{ marginTop: "6px", fontSize: "12px", color: "#93c5fd", background: "rgba(56, 189, 248, 0.08)", padding: "6px 10px", borderRadius: "4px" }}>
                    <strong>Why it matters:</strong> {ind.why_it_matters}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div style={{ padding: "14px", background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.25)", borderRadius: "8px", color: "#a7f3d0", fontSize: "13px", marginBottom: "20px" }}>
          ✓ No blatant structural or lexical threat indicators were identified in this sample.
        </div>
      )}

      {/* Recommended Next Steps */}
      {Array.isArray(report.recommendations) && report.recommendations.length > 0 && (
        <div className="recs-box">
          <div className="recs-title">
            <CheckCircle2 size={18} /> Recommended Next Steps
          </div>
          <ul className="recs-list">
            {report.recommendations.map((rec, idx) => (
              <li key={idx}>{rec}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Extracted URLs Preview */}
      {Array.isArray(report.extracted_urls) && report.extracted_urls.length > 0 && (
        <div style={{ marginBottom: "20px" }}>
          <h4 style={{ fontSize: "13px", color: "#38bdf8", marginBottom: "8px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Extracted & Defanged Destinations ({report.extracted_urls.length})
          </h4>
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {report.extracted_urls.map((u, idx) => (
              <div key={idx} style={{ background: "var(--bg-input)", padding: "8px 12px", borderRadius: "6px", border: "1px solid var(--border-subtle)", fontSize: "12px", fontFamily: "monospace", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ color: "#93c5fd" }}>{u.defanged_url || u.original_url}</span>
                {u.is_ip && <span style={{ color: "#ef4444", fontSize: "10px", fontWeight: "bold" }}>[NUMERIC IP]</span>}
                {u.is_lookalike && <span style={{ color: "#f97316", fontSize: "10px", fontWeight: "bold" }}>[LOOKALIKE]</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Expandable Technical JSON */}
      <details style={{ marginTop: "16px", paddingTop: "12px", borderTop: "1px solid var(--border-subtle)" }}>
        <summary style={{ cursor: "pointer", color: "#38bdf8", fontSize: "12px", fontWeight: "600" }}>
          View raw technical telemetry payload (JSON)
        </summary>
        <pre style={{ marginTop: "10px", padding: "12px", background: "#061325", borderRadius: "8px", fontSize: "11px", color: "#94a3b8", overflowX: "auto" }}>
          {JSON.stringify(report, null, 2)}
        </pre>
      </details>
    </div>
  );
}
