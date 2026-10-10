# PhishGuard AI — AI-Powered Phishing Triage for Small Organizations

PhishGuard AI is an explainable, multi-layered cyber threat triage platform built for small-to-medium organizations without dedicated 24/7 Security Operations Centers (SOCs). It provides automated, privacy-preserving triage across inbound **URLs**, **Emails**, and **QR Codes (Quishing)** using a combination of local neural NLP classification and transparent static rule-based heuristics.

---

## Architecture Overview

```
+-----------------------------------------------------------------------------------------+
|                                    PHISHGUARD AI SYSTEM                                 |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|   [ Inbound Triage Inputs ]                                                             |
|   ├── Direct URL / IDN Punycode String                                                  |
|   ├── Email Subject, Body, and Sender Headers                                           |
|   └── Optical QR Code Image Upload (PNG, JPG, WebP)                                     |
|                                                                                         |
|                                         │                                               |
|                                         ▼                                               |
|   +─────────────────────────────────────────────────────────────────────────────────+   |
|   |                           ANALYSIS & EXTRACTION ENGINES                         |   |
|   |                                                                                 |   |
|   |  1. Static URL & Homoglyph Analyzer:                                            |   |
|   |     - Safe defanging (hxxp://, [.])                                             |   |
|   |     - IDN Punycode decoding (xn--) & Unicode normalization                     |   |
|   |     - Cyrillic/Greek/Latin mixed-script confusable spoof detection              |   |
|   |     - IPv4/IPv6 host validation & brand lookalike skeleton distance             |   |
|   |     - 100% static: zero live HTTP network connections to target hosts           |   |
|   |                                                                                 |   |
|   |  2. Local AI Email Classifier:                                                  |   |
|   |     - Pretrained DistilBERT (GowthamAdhikarla/email-spam-detector-distilbert)   |   |
|   |     - Local inference on NVIDIA GPU (CUDA) with automatic CPU fallback          |   |
|   |     - Explainable pattern heuristics (Urgency, Credential lures, BEC, Scams)   |   |
|   |     - Concurrent embedded URL triage                                            |   |
|   |                                                                                 |   |
|   |  3. Optical QR-Code (Quishing) Analyzer:                                        |   |
|   |     - In-memory OpenCV matrix decoding                                          |   |
|   |     - Multi-payload extraction with 5MB / 4096x4096px bounds                    |   |
|   |     - Automatic route to Static URL analyzer for embedded web targets           |   |
|   +─────────────────────────────────────────────────────────────────────────────────+   |
|                                         │                                               |
|                                         ▼                                               |
|   +─────────────────────────────────────────────────────────────────────────────────+   |
|   |                        TRANSPARENT COMPOSITE RISK ENGINE                        |   |
|   |                                                                                 |   |
|   |   - Tiered Scoring: 0–24.9 (Low) | 25–49.9 (Medium) | 50–74.9 (High) | 75+ (Crit)   |   |
|   |   - Explicit separation of model confidence from overall incident risk          |   |
|   |   - Actionable remediation advice and missing evidence disclaimers              |   |
|   +─────────────────────────────────────────────────────────────────────────────────+   |
|                                         │                                               |
|                     ┌───────────────────┴───────────────────┐                           |
|                     ▼                                       ▼                           |
|       [ React 18 / Vite Frontend ]             [ Tamper-Resistant PDF Reports ]         |
|       - Real-time dark SOC dashboard           - Server-authoritative ReportLab         |
|       - Defanged preview & badge chips         - Defanged URLs & redacted PII           |
|       - Hardware inference status badge        - Cryptographic timestamp & UUID         |
+-----------------------------------------------------------------------------------------+
```

---

## Key Features

1. **Static URL Phishing Detection**:
   - Analyzes URL syntax, numeric IP hosts, deceptive subdomains, shortening services, and credential lure paths.
   - **IDN & Punycode Homoglyph Engine**: Decodes Internationalized Domain Names (`xn--...`), detects mixed-script attacks (e.g. Cyrillic `а` in `apple.com`), and compares confusable skeleton strings against targeted organizational brands.
   - **Zero Network Execution**: Submitted URLs are never resolved via DNS or connected to over HTTP/TCP, protecting analysts from drive-by payloads or tracking beacons.

2. **AI Email Spam & Triage Engine**:
   - Uses local DistilBERT sequence classification to identify unsolicited bulk messaging.
   - Explainable behavioral pattern analysis: flags coercive urgency, password/OTP demands, CEO wire fraud (BEC), fake invoices, and lottery scams.
   - Extracts all embedded URLs and triages them simultaneously.

3. **QR-Code Phishing (Quishing) Scanner**:
   - Accepts image uploads up to 5MB and 4096×4096 dimensions.
   - Extracts encoded QR payloads in-memory via OpenCV without temporary disk persistence.
   - Automatically defangs and triages extracted web links.

4. **Tamper-Resistant PDF Security Reports**:
   - Generated entirely in memory via ReportLab.
   - Resolves authoritative server-side analysis records by Analysis ID to prevent client-side score tampering.
   - Defangs all URLs and redacts sensitive PII.

5. **Production React Dashboard**:
   - Real-time SOC statistics (Total Analyzed, Phishing, Suspicious, Spam, Legitimate).
   - Filterable incident history and CSV export.
   - Instant live hardware inference indicator (CUDA GPU / CPU fallback).

---

## Technology Stack

- **Backend**: Python 3.14 / 3.12, FastAPI, Uvicorn, SQLAlchemy, SQLite, Pydantic v2.
- **Machine Learning & Vision**: PyTorch, Hugging Face Transformers (`DistilBERT`), OpenCV (`opencv-python-headless`), Python-IDNA.
- **Reporting**: ReportLab (PDF generation), Python CSV writer with formula-injection sanitization.
- **Frontend**: React 18, Vite 5, Lucide Icons, Recharts, Vanilla CSS Design System.
- **Test Framework**: Pytest (89 automated regression tests).

---

## Reproducible Windows Startup Guide

### Prerequisites
- Windows 10/11 with PowerShell.
- Python 3.10+ (Recommended: Python 3.11/3.12 for pre-built PyTorch CUDA wheels).
- Node.js 18+ and npm.

### Terminal 1: Python Backend (FastAPI)
Open PowerShell and run:
```powershell
# Navigate to backend directory
cd "c:\Users\Aryananda\OneDrive\Desktop\hackathon\backend"

# Activate the virtual environment
.\venv\Scripts\Activate.ps1

# Start the Uvicorn server on port 8000
$env:PYTHONPATH='.'
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend is live at:* `http://127.0.0.1:8000`  
*Swagger Documentation:* `http://127.0.0.1:8000/docs`

### Terminal 2: React Frontend (Vite)
Open a second PowerShell terminal and run:
```powershell
# Navigate to frontend directory
cd "c:\Users\Aryananda\OneDrive\Desktop\hackathon\frontend"

# Install packages if not already installed
npm install

# Start Vite development server on port 5173
npm run dev
```
*Frontend User Interface is live at:* `http://localhost:5173` (proxies `/api` to port 8000)

### Terminal 3: Verification & Health Checks
Open a third terminal to run health checks and verification commands:

1. **Check Backend Operational Health:**
   ```powershell
   Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health"
   ```
   *Expected Response:*
   ```json
   {
     "status": "healthy",
     "service": "PhishGuard AI — AI-Powered Phishing Triage API",
     "database": "sqlite_ready",
     "engine": "local_heuristics_active",
     "version": "1.0.0"
   }
   ```

2. **Check Model Loading & Inference Hardware:**
   ```powershell
   Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/model-status"
   ```
   *Expected Response:*
   ```json
   {
     "model_id": "GowthamAdhikarla/email-spam-detector-distilbert",
     "model_loaded": true,
     "inference_device": "cpu",
     "cuda_available": false,
     "gpu_name": null,
     "status": "ready",
     "error_message": null
   }
   ```

3. **Verify GPU Hardware & PyTorch Capability:**
   ```powershell
   # Inspect physical host GPU
   nvidia-smi

   # Inspect PyTorch CUDA support
   & "c:\Users\Aryananda\OneDrive\Desktop\hackathon\backend\venv\Scripts\python.exe" -c "import torch; print('CUDA Available:', torch.cuda.is_available()); print('Device:', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU Fallback')"
   ```

4. **Run Full Backend Regression Test Suite (89 Tests):**
   ```powershell
   cd "c:\Users\Aryananda\OneDrive\Desktop\hackathon\backend"
   & ".\venv\Scripts\python.exe" -m pytest tests -v
   ```
   *Verified Status:* **89 passed, 0 failed, 0 skipped**.

5. **Run Evaluation Benchmark Runner:**
   ```powershell
   cd "c:\Users\Aryananda\OneDrive\Desktop\hackathon\backend"
   & ".\venv\Scripts\python.exe" tests/run_evaluation.py
   ```

---

## GPU Inference Verification Guide

PhishGuard AI supports local GPU acceleration for neural network inference using NVIDIA CUDA.

### Hardware vs. Software Configuration
- **Host GPU:** NVIDIA GeForce RTX 3050 Laptop GPU (6GB VRAM, Driver 591.80, CUDA 13.1 supported).
- **Installed Virtualenv PyTorch:** `2.14.1+cpu` (CPU-only wheel).
- **Operational Mode:** The application detects `torch.cuda.is_available() == False` and smoothly activates CPU fallback mode (`inference_device: "cpu"`). Model inference executes locally on CPU cores in ~150ms without crashing.
- **Enabling CUDA Acceleration on NVIDIA GPUs:**
  To enable full GPU acceleration on CUDA-supported Python environments:
  ```powershell
  pip install --upgrade torch torchvision --index-url https://download.pytorch.org/whl/cu121
  ```

---

## Honest Evaluation Results & Detection Quality Review

The application was evaluated against a labeled, reproducible benchmark dataset containing diverse threat vectors.

### Evaluation Metrics Summary (12 Curated Samples)

| Metric | Measured Benchmark Value | Notes & Scope |
| :--- | :--- | :--- |
| **Total Evaluated** | **12 samples** | Small, reproducible evaluation benchmark |
| **True Positives (TP)** | **5** | Detected credential phishing, BEC, invoice lures, bulk spam |
| **False Positives (FP)** | **0** | Zero benign personal/corporate emails flagged as critical |
| **True Negatives (TN)** | **6** | Correctly cleared legitimate personal, corporate, and urgent emails |
| **False Negatives (FN)** | **1** | Stealth password lure without embedded link (`EML-PHISH-02`) |
| **Accuracy** | **91.7%** (0.9167) | Overall triage classification accuracy |
| **Precision** | **100.0%** (1.0000) | Positive predictions were true threats |
| **Recall (Sensitivity)** | **83.3%** (0.8333) | 5 out of 6 threats identified |
| **F1-Score** | **90.9%** (0.9091) | Harmonized balance of precision and recall |

### Detection Quality & Statistical Disclaimers
1. **Preliminary Results Notice:** These performance metrics represent preliminary validation against a curated 12-sample evaluation benchmark. They do **NOT** represent certified or guaranteed real-world performance across arbitrary internet traffic.
2. **Sample Size Scope:** More diverse, large-scale labeled samples are required to estimate true out-of-sample generalization and false-positive rates reliably.
3. **Model vs. Triage Separation:** DistilBERT is trained to identify bulk promotional spam, not targeted spear-phishing. PhishGuard deliberately separates the model classification score from the composite incident risk score.
4. **Heuristic Scores are Not Probabilities:** Risk scores (0–100) are explainable, additive weighted heuristics, not calibrated Bayesian probabilities.
5. **Acknowledge False Negatives:** Purely text-based password lures lacking links or coercive keywords can evade heuristic detection, highlighting the necessity of human verification.

---

## API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health status and database readiness |
| `GET` | `/api/model-status` | DistilBERT loading state and inference hardware (`cuda:0` / `cpu`) |
| `POST` | `/api/analyze-url` | Static URL and IDN homoglyph phishing inspection |
| `POST` | `/api/analyze-qr` | QR image upload, matrix decode, and embedded URL triage |
| `POST` | `/api/analyze-email` | AI email spam classification + pattern extraction + URL analysis |
| `POST` | `/api/reports/url` | Server-authoritative PDF report for URL analysis |
| `POST` | `/api/reports/email` | Server-authoritative PDF report for Email analysis |
| `POST` | `/api/reports/qr` | Server-authoritative PDF report for QR code analysis |
| `GET` | `/api/dashboard/stats`| Live organizational triage metrics and status history |
| `GET` | `/api/reports/export/csv` | Formula-injection-sanitized CSV incident export |

---

## Three-Minute Demonstration Script

### Minute 1: The Small Organization Challenge & Hybrid Architecture (0:00–1:00)

**Presenter Spoken Dialogue:**
> *"Small businesses, non-profits, and clinics are bombarded by phishing, wire fraud, and QR scams daily. Yet they lack $100K enterprise SOC budgets and dedicated security engineers.*
>
> *We built PhishGuard AI: an explainable, on-premises phishing triage platform. Rather than sending confidential emails to third-party cloud APIs, PhishGuard runs 100% locally with zero external data leakage.*
>
> *Our architecture combines local DistilBERT sequence classification for bulk spam detection with transparent, rule-based heuristics for urgency, credential theft, and embedded URL analysis. Notice our live hardware badge: running inference locally right now on our machine."*

**Cue Actions:**
1. Show the PhishGuard dashboard running on `http://localhost:5173`.
2. Point out the live **Hardware Status Badge** in the top navigation bar (`Model: Ready | Device: CPU / CUDA`).
3. Show the live organizational statistics cards (Total Analyzed, Phishing, Suspicious, Spam, Legitimate).

---

### Minute 2: Live Threat Triage Across URLs, Emails, and Quishing (1:00–2:00)

**Presenter Spoken Dialogue:**
> *"Let's test our first vector: an Internationalized Domain Name lookalike attack.*
>
> *Here is `http://xn--pple-43d.com/secure-login/update`. To the naked eye, this looks like apple.com, but it secretly uses a Cyrillic 'а'. Watch PhishGuard triage it in milliseconds without ever making an unsafe network connection to the server.*
>
> *It decodes the Punycode, flags the mixed-script homoglyph targeting Apple, defangs the link to `hxxp://`, and assigns an explainable Risk Score of 62.0.*
>
> *Now, let's triage an inbound corporate email lure: an urgent notice claiming direct deposit failure and directing staff to an external portal.*
>
> *PhishGuard runs DistilBERT NLP inference, detects coercive urgency, extracts the embedded link, triages it simultaneously, and computes a composite triage score of 72.9 with actionable employee guidance.*
>
> *Even if attackers bypass email filters using QR codes—known as Quishing—our optical scanner extracts the payload in memory, flags suspicious IP destinations, and triages it before a phone camera ever opens it."*

**Cue Actions:**
1. Switch to **URL Inspection** tab:
   - Paste URL: `http://xn--pple-43d.com/secure-login/update`
   - Click **Analyze URL**.
   - Point out: Risk Score **62.0 (High Risk)**, Verdict: `Potential Phishing`, Badge: `IDN Punycode Confusable (Apple)`, Defanged URL display.
2. Switch to **Email AI Triage** tab:
   - Click sample or paste:
     - Subject: `CRITICAL: Direct Deposit Update Required`
     - Body: `Immediate verification required at http://payroll-portal.corp-update.net/auth or salary disbursement will be suspended.`
   - Click **Triage Email**.
   - Point out: AI Model Spam Confidence (99.4%), Pattern detected (`Urgency / Threat of Account Suspension`), Embedded URL extracted and triaged, Composite Risk Score **72.9 (High Risk)**.
3. Switch to **QR Scanner** tab (if time permits):
   - Upload sample QR code image encoding `http://192.168.1.55/admin-reset?token=xyz`.
   - Point out: Decoded URL, defanged IP host, Risk Score **45.0 (Medium Risk)**, Verdict: `Suspicious`.

---

### Minute 3: Authoritative PDF Reports, Honest Evaluation, and Limitations (2:00–3:00)

**Presenter Spoken Dialogue:**
> *"When non-technical staff or junior IT responders need to escalate an incident, they click Download PDF Report.*
>
> *Notice what happens: the backend queries the authoritative server record—tamper-proof against client score spoofing—and compiles a clean, professional ReportLab PDF in memory. All URLs are defanged and credentials are redacted.*
>
> *Finally, our results: across our 12-sample reproducible benchmark, PhishGuard achieved 91.7% accuracy and 100% precision. But we want to be completely honest: these are preliminary results from a small benchmark. Real-world spear phishing evolves constantly, and heuristic tools cannot guarantee 100% detection.*
>
> *PhishGuard bridges the gap for small organizations by giving them explainable, privacy-preserving triage they can trust. Thank you!"*

**Cue Actions:**
1. Click **Download PDF Security Report** on the analyzed email.
2. Open the downloaded PDF in the browser: show the clean header, risk meter, defanged indicators, and remediation checklist.
3. Point to the **Limitations & Disclaimers** note at the bottom of the report and the Evaluation summary in the documentation.

---

## Safe Synthetic Demonstration Inputs

These safe, pre-tested inputs produce verified application scores:

| Test Case | Type | Input Content | Actual App Output |
| :--- | :--- | :--- | :--- |
| **Demo URL 1** | IDN Homoglyph Spoof | `http://xn--pple-43d.com/secure-login/update` | **Score: 62.0 (High Risk)**<br>Verdict: Potential Phishing<br>Badge: IDN Punycode Confusable (Apple) |
| **Demo URL 2** | IP Address Host | `http://192.168.1.1/admin-login` | **Score: 62.0 (High Risk)**<br>Verdict: Potential Phishing<br>Badge: IPv4 Numeric Host |
| **Demo Email 1** | Urgent Credential Extortion | **Subject:** `CRITICAL: Unauthorized sign-in detected on corporate account`<br>**Body:** `CRITICAL SECURITY WARNING: Your access will be suspended within 24 hours unless you verify your credentials at http://192.168.1.1/admin-login immediately.` | **Score: 94.0 (Critical Risk)**<br>Verdict: Potential Phishing<br>AI Model: Spam (`LABEL_1`)<br>URL Extracted: `http://192.168.1.1/admin-login` |
| **Demo Email 2** | Legitimate Meeting (Benign) | **Subject:** `Quarterly Operations Review & Planning Sync`<br>**Body:** `Hi team, attached is the agenda for our upcoming quarterly sync scheduled for next Tuesday at 2:00 PM EST. Please let me know if you would like to include any items.` | **Score: 5.0 (Low Risk)**<br>Verdict: Legitimate<br>Zero threat indicators flagged |
| **Demo QR Code**| Quishing (QR Phishing) | Image containing QR encoding: `http://192.168.1.55/admin-reset?token=xyz` | **Score: 45.0 (Medium Risk)**<br>Verdict: Suspicious<br>Badge: Numeric IP Address Host |

---

## Live Demo Fallback & Troubleshooting Plan

### 1. How to Restart Backend and Frontend
- **Backend Recovery (Terminal 1):**
  If the backend crashes or becomes unresponsive, press `Ctrl + C` and re-run:
  ```powershell
  cd "c:\Users\Aryananda\OneDrive\Desktop\hackathon\backend"
  .\venv\Scripts\Activate.ps1
  $env:PYTHONPATH='.'
  python -m uvicorn app.main:app --app-dir "c:\Users\Aryananda\OneDrive\Desktop\hackathon\backend" --host 127.0.0.1 --port 8000 --reload
  ```
- **Frontend Recovery (Terminal 2):**
  If the Vite dev server locks up or shows an EPERM dependency cache error, serve the production build directly:
  ```powershell
  cd "c:\Users\Aryananda\OneDrive\Desktop\hackathon\frontend"
  npm run preview -- --port 5173 --host 127.0.0.1
  ```

### 2. How to Diagnose a Failed Health Check
- Query the health endpoint from PowerShell:
  ```powershell
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health"
  ```
- If the request times out or is refused:
  1. Check if port 8000 is occupied by a lingering process:
     ```powershell
     netstat -ano | findstr :8000
     ```
  2. Kill any stale process: `taskkill /PID <PID> /F`.
  3. Verify that `phishguard.db` is writable. (FastAPI automatically initializes the database tables if absent).

### 3. What to Do If GPU Inference Fails / Switching to CPU Fallback
- Check current model status:
  ```powershell
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/model-status"
  ```
- **Automatic Fallback:** PhishGuard's `EmailSpamModelManager` automatically catches CUDA exceptions and switches to CPU fallback mode (`inference_device: "cpu"`).
- **Manual Force CPU:** To explicitly force CPU execution before a demo:
  ```powershell
  $env:CUDA_VISIBLE_DEVICES="-1"
  python -m uvicorn app.main:app --app-dir "c:\Users\Aryananda\OneDrive\Desktop\hackathon\backend" --host 127.0.0.1 --port 8000
  ```

### 4. How to Proceed If QR Analysis Is Unavailable
- QR-code (Quishing) inspection is an optional bonus module. If OpenCV is unavailable or camera captures fail, focus the demonstration on the **two primary workflows**:
  1. **URL Phishing Detection** (including IDN Punycode homoglyph detection).
  2. **AI Email Spam & Triage** (DistilBERT NLP + pattern analysis).
- These core workflows operate 100% independently of the QR image pipeline.

### 5. Demonstrating Archived Reports Without Misleading Judges
- If network or runtime issues prevent live submission, navigate to the **Incident Log / History** tab.
- Click any pre-seeded incident (e.g., `INC-2026-001` or `INC-2026-002`) to view the complete saved analysis breakdown and export its PDF.
- State clearly to the judges:
  > *"Here is an archived audit record from our persistent SQLite database demonstrating historical triage and tamper-proof PDF export."*

---

## Known Limitations

1. **Not a Replacement for Enterprise Firewalls**: PhishGuard is built for non-specialist triage, not as an inline perimeter firewall.
2. **Heuristic Scores are Not Probabilities**: Risk scores (0–100) are explainable additive heuristics, not calibrated probabilities.
3. **Static Limitations**: Static URL triage cannot inspect dynamic payloads loaded by client-side JavaScript execution without a dedicated sandbox.
4. **Homoglyph Scope**: The confusable engine detects mixed-script and target-brand lookalikes; it does not perform live WHOIS or reputation lookups.
5. **No Guarantee of Detection**: No automated tool can guarantee 100% detection of advanced spear phishing.

