# NEURO-NET: Cloud-Native Cybersecurity & Intrusion Profiling Platform

[![Runtime](https://img.shields.io/badge/Runtime-Vercel%20Serverless%20Python-black?logo=vercel)](https://vercel.com)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.0-00f3ff?logo=flask)](https://flask.palletsprojects.com/)
[![AIaaS](https://img.shields.io/badge/AIaaS-Google%20Gemini%202.5%20Flash-4285F4?logo=google)](https://ai.google.dev/)
[![DBaaS](https://img.shields.io/badge/DBaaS-MongoDB%20Atlas%20TTL%20Cache-47A248?logo=mongodb)](https://www.mongodb.com/)
[![BaaS](https://img.shields.io/badge/BaaS-Supabase%20Postgres%20%26%20Storage-3ECF8E?logo=supabase)](https://supabase.com/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**NeuroNet-Mobile** is a high-performance, mobile-optimized cybersecurity web application engineered specifically for **Vercel Serverless Functions**. It demonstrates modern **cloud computing architecture** using an integrated cloud stack: **Vercel Serverless & Edge Network**, **MongoDB Atlas (DBaaS)**, **Supabase (BaaS & Cloud Object Storage)**, and a **Google Gemini Multi-Key Round-Robin AI Pool (AIaaS)** — with zero additional third-party dependencies.

---

## Key Capabilities & Serverless Features

### 1. Cloud-Hardened Steganography Engine (Stego Drive)
- **Read-Only Filesystem Adaptation:** Completely refactored from local static writes to in-memory bytes processing (`io.BytesIO`) and temporary storage in `/tmp` using unique `uuid4` filenames with guaranteed cleanup.
- **Audio LSB Steganography:** Implements `.wav` LSB injection and extraction using Python's native `wave` module. Handles missing serverless `ffmpeg` dependencies gracefully with clean user guidance when `.mp3` is uploaded.
- **Cloud Object Storage (Supabase Storage):** Automatically uploads encoded artifacts (PNG/WAV) to the Supabase Storage bucket (`stego-vault`) and issues secure, time-limited signed download URLs (1-hour validity). Includes direct in-memory streaming fallback (`flask.send_file`) if cloud storage is unavailable.

### 2. Hardened Serverless Python Sandbox
- **Static AST Security Auditing:** Pre-parses user Python code into an Abstract Syntax Tree before execution, blocking dangerous imports (`os`, `sys`, `subprocess`, `socket`, `shutil`, `pathlib`, `ctypes`, `threading`, `time`) and sandbox escape vectors (`__subclasses__`, `__bases__`, `__mro__`, `__globals__`).
- **Stripped Builtins:** Removes destructive builtins (`open`, `eval`, `exec`, `compile`, `input`, `exit`) to protect cloud container environment variables and execution integrity.
- **Strict Import Whitelist:** Replaces `__import__` with a custom interceptor permitting only safe standard library modules: `math`, `random`, `json`, `datetime`, `re`, `hashlib`, `base64`, `string`, `collections`, `itertools`.
- **Thread-Safe Stream & Strict Timeout:** Utilizes a non-blocking `SafeStream` buffer to capture outputs cleanly, enforcing a strict timeout via synchronous worker join to guarantee functions never hang serverless containers.

### 3. Synchronous OS Kernel Simulation
- Replaced unjoined background threads (`threading.Thread`) with synchronous microsecond syscall pattern inspection. Serverless runtimes kill background threads as soon as HTTP responses return; the synchronous engine reliably isolates attacks and logs syscall traces.

### 4. Distributed Cloud Caching & Rate Limiting (MongoDB TTL)
- **AI Response Cache (24-Hour TTL):** Implements an `osint_cache` collection with MongoDB TTL indexing (`expireAfterSeconds=86400`). Dark Web OSINT scans query the distributed cache before reaching Gemini, reducing latency and API usage.
- **Distributed Threat Rate Limiting (1-Hour TTL):** Implements a `rate_limits` collection with MongoDB TTL indexing (`expireAfterSeconds=3600`) to track attacker IPs, cumulative threat scores, and request frequency across stateless serverless instances.
- **Graceful Fallback:** If MongoDB is offline, cache operations gracefully degrade to in-memory no-op mode without breaking application workflows.

### 5. Multi-Key Round-Robin AIaaS Pool (Google Gemini)
- Dynamic key pooling supporting up to 5 distributed `GOOGLE_API_KEY`s (`GOOGLE_API_KEY_1` through `GOOGLE_API_KEY_5`).
- Automatic failover and round-robin request distribution utilizing `gemini-2.5-flash` on `v1beta` with strict JSON mode.

### 6. Vercel Edge Geolocation & Telemetry
- Extracts Edge headers (`x-vercel-ip-country`, `x-vercel-ip-city`, `x-forwarded-for`) and Vercel runtime variables (`VERCEL`, `VERCEL_REGION`, `VERCEL_ENV`).
- Attaches real attacker geolocation and serverless execution regions to honeypot logs stored in Supabase and MongoDB.

### 7. Live Cloud Architecture & Health Dashboard
- Exposes `GET /api/cloud-health` providing live telemetry across Compute, AIaaS, DBaaS, and BaaS layers.
- Interactive 3D holographic diagonal wheel UI displaying real-time status badges (`ONLINE` / `FALLBACK`) and regional telemetry.

---

## Architecture Overview

```
                      +-------------------------------------+
                      |          Vercel Edge Network        |
                      |  - SSL Termination / Edge Headers   |
                      |  - IP & Country / City Geolocation  |
                      +------------------+------------------+
                                         |
                                         v
                      +-------------------------------------+
                      |      Vercel Serverless Function     |
                      |      main.py (Flask 3.0 / Python)   |
                      |  - Flask-Talisman CSP / Flask-WTF   |
                      |  - In-Memory & /tmp Ephemeral I/O   |
                      |  - Hardened Python Sandbox (AST)    |
                      |  - Synchronous OS Kernel Simulation |
                      +----+-------------+-------------+----+
                           |             |             |
        +------------------+             |             +------------------+
        |                                |                                |
        v                                v                                v
+----------------+              +----------------+              +-------------------+
|  Google Gemini |              | MongoDB Atlas  |              | Supabase Platform |
|  Multi-Key     |              |  Distributed   |              |  - Core Auth Logs |
|  AIaaS Pool    |              |  DBaaS & TTL   |              |  - User Activity  |
|  (Round-Robin  |              |  - 24h OSINT   |              |  - S3 Object      |
|   Failover)    |              |  - 1h Limits   |              |    Storage Bucket |
+----------------+              +----------------+              +-------------------+
```

---

## Repository Structure

```
NeuroNet-Mobile/
├── .env.example              # Sanitized configuration template
├── .gitignore                # Prevents secrets and pycache from being committed
├── LICENSE                   # MIT License
├── README.md                 # Project summary and quickstart
├── architecture.md           # Cloud computing architecture specification
├── implementation.md         # Technical implementation & serverless fixes deep-dive
├── guide.md                  # Comprehensive operator setup & troubleshooting guide
├── main.py                   # Flask application factory, Gunicorn & Vercel entrypoint
├── requirements.txt          # Production dependencies
├── vercel.json               # Vercel serverless routing configuration
├── app/
│   ├── __init__.py           # Package marker
│   ├── routes.py             # Route definitions, edge telemetry, and controllers
│   ├── static/               # Static assets (logo, icons)
│   └── templates/            # Cyberpunk mobile-responsive templates
│       ├── architecture.html # 3D Diagonal holographic cloud health visualizer
│       ├── chatbot.html      # Neural uplink chat interface
│       ├── cyber_feed.html   # Live threat intelligence feed
│       ├── darkweb.html      # OSINT breach and darkweb target scanner
│       ├── dashboard.html    # Admin intrusion monitoring dashboard
│       ├── decrypt.html      # Cryptographic hash and XOR decryptor
│       ├── encrypt.html      # XOR stream cipher encryptor
│       ├── ghost.html        # Deceptive honeypot tarpit dashboard
│       ├── login.html        # Behavioral keystroke honeypot login
│       ├── password.html     # AI entropy and password security analyzer
│       ├── profiler.html     # Social engineering & NLP psych profiler
│       ├── python_info.html  # System specifications and environment reader
│       ├── sandbox.html      # Hardened isolated code execution interface
│       ├── security_profile.html # User security posture and risk dashboard
│       ├── stego.html        # Stego Drive carrier injection and extraction
│       └── vault.html        # MongoDB encrypted credentials vault
└── core/
    ├── __init__.py           # Core package marker
    ├── ai_integrator.py      # Gemini multi-key pool with TTL cache integration
    ├── cloud_cache.py        # MongoDB Atlas TTL distributed cache & rate limiter
    ├── os_sim.py             # Synchronous kernel simulation and syscall checker
    ├── sandbox_exec.py       # Hardened serverless Python sandbox with AST checks
    ├── security_modules.py   # LSB image and WAV audio steganography engine
    └── structures.py         # Signature Trie and data structures
```

---

## Quickstart & Local Setup

### Prerequisites
- Python 3.12+ (or 3.14)
- Git

### 1. Clone & Set Up Virtual Environment
```bash
git clone https://github.com/sujay-237/NeuroNet-Mobile.git
cd NeuroNet-Mobile

python -m venv venv
# Linux / macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` and fill in your keys:
```bash
cp .env.example .env
```

### 4. Run Locally
```bash
python main.py
```
Visit `http://127.0.0.1:5000` in your browser.

---

## Deploying to Vercel

1. Push your repository to GitHub.
2. Go to [Vercel Dashboard](https://vercel.com/new) and import `NeuroNet-Mobile`.
3. In **Settings -> Environment Variables**, configure:
   - `GOOGLE_API_KEY_1` .. `GOOGLE_API_KEY_5` (or `GOOGLE_API_KEY`)
   - `SUPABASE_URL` and `SUPABASE_KEY`
   - `MONGO_URI`
   - `FLASK_SECRET_KEY`
4. Click **Deploy**. Vercel will build the project using `@vercel/python` as defined in `vercel.json`.

---

## Documentation Links

- **[Architecture Specification](architecture.md):** Cloud computing design, serverless constraints, and data flows.
- **[Implementation Deep-Dive](implementation.md):** Line-by-line implementation details and security hardening.
- **[Operator & Setup Guide](guide.md):** Complete configuration steps for Gemini, MongoDB Atlas, Supabase, and Vercel.
