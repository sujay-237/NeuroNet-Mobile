# Cloud Computing & Systems Architecture Specification

This document outlines the **Cloud Computing Architecture** of **NeuroNet-Mobile**, detailing its distributed topology, serverless execution model, data flows, and security model.

---

## 1. Architectural Philosophy

NeuroNet-Mobile is designed around the **Stateless Micro-Compute & Managed Cloud Services** pattern:
- **Zero Local Disk Dependency:** The application makes zero assumptions about persistent local storage. Ephemeral `/tmp` operations are strictly cleaned up within request boundaries.
- **Strictly Managed Stack:** Uses exclusively **Vercel**, **MongoDB Atlas**, **Supabase**, and **Google Gemini** with zero unnecessary microservices or external sandbox runtimes.
- **Resilience through Degradation:** Every external cloud dependency (MongoDB, Supabase, Gemini) features an automated, graceful fallback mechanism to ensure the application stays online 100% of the time.

---

## 2. Distributed Cloud Architecture Diagram

```mermaid
flowchart TD
    subgraph Client["Client Tier (Mobile / Desktop)"]
        UI["Cyberpunk 3D Diagonal HUD (HTML5 / WebGL / Canvas)"]
    end

    subgraph VercelEdge["Edge Layer (Vercel Global Edge Network)"]
        EdgeSSL["SSL / TLS Termination"]
        EdgeGeo["Edge Headers (x-vercel-ip-country, city, x-forwarded-for)"]
    end

    subgraph ServerlessCompute["Compute Layer (Vercel Serverless Function)"]
        WSGI["main.py (Flask 3.0 via @vercel/python)"]
        Talisman["Flask-Talisman CSP & CSRF Protection"]
        SandboxEngine["Hardened AST Sandbox (core/sandbox_exec.py)"]
        StegoEngine["LSB Stego Drive (core/security_modules.py)"]
        SimEngine["Synchronous OS Sim (core/os_sim.py)"]
    end

    subgraph AIaaS["AI as a Service Tier (Google Cloud)"]
        GeminiPool["Gemini Multi-Key Round-Robin Pool (gemini-2.5-flash / v1beta)"]
    end

    subgraph DBaaS["Database as a Service Tier (MongoDB Atlas)"]
        MongoCache["24h TTL AI Intelligence Cache (osint_cache)"]
        MongoLimits["1h TTL Distributed Rate Limits (rate_limits)"]
        MongoVault["Encrypted Credentials Vault (vault)"]
        MongoHoneypot["Attacker Logs (honeypot_attacks)"]
    end

    subgraph BaaS["Backend as a Service Tier (Supabase)"]
        SupaAuth["User Database & Roles (users)"]
        SupaLogs["Audit Trails & Activity (user_activity, attack_logs)"]
        SupaStorage["Cloud Object Storage Bucket (stego-vault)"]
    end

    UI -->|HTTPS Request| EdgeSSL
    EdgeSSL --> EdgeGeo
    EdgeGeo --> WSGI
    WSGI --> Talisman
    Talisman --> SandboxEngine
    Talisman --> StegoEngine
    Talisman --> SimEngine

    WSGI <-->|Round-Robin AI Calls| GeminiPool
    WSGI <-->|TTL Cache & Limits| DBaaS
    WSGI <-->|Auth & Object Storage| BaaS
```

---

## 3. Four Pillars of the Architecture

### Pillar 1: Serverless Micro-Compute (Vercel)
- **Engine:** `@vercel/python` packaging `main.py` entrypoint.
- **Stateless Execution:** Container instances spin up, process single requests, and scale to zero during inactivity.
- **Lifecycle Guarantees:** Ephemeral memory isolation; no cross-request state leakage through local disk.
- **Edge Metadata:** Enriched request headers provide geo-location (`x-vercel-ip-country`, `x-vercel-ip-city`) without requiring external MaxMind GeoIP databases.

### Pillar 2: AI as a Service — AIaaS (Google Gemini)
- **Model:** `gemini-2.5-flash` utilizing `v1beta` API endpoint with JSON MIME type enforcement.
- **High-Availability Key Pooling:** Multi-key round-robin pool distributing load across up to 5 distinct Gemini API keys.
- **Dynamic Failover:** Automatic failover upon HTTP 429 (rate limit) or quota exhaustion.

### Pillar 3: Distributed Caching & DBaaS (MongoDB Atlas)
- **Engine:** MongoDB Atlas with native Time-To-Live (TTL) B-tree indexes.
- **24-Hour OSINT Intelligence Cache (`osint_cache`):** Caches expensive LLM OSINT scans keyed by normalized query strings. Automatically expunged after 86,400 seconds.
- **1-Hour Distributed Rate Limiter (`rate_limits`):** Synchronizes threat scores and request volume across independent serverless function instances.

### Pillar 4: Backend as a Service — BaaS & Object Storage (Supabase)
- **Relational Storage:** PostgreSQL instance managing authenticated users, administrative approvals, and attack histories.
- **Cloud Object Storage (`stego-vault`):** S3-compatible cloud object storage hosting encoded steganographic images and audio waveforms.
- **Presigned URLs:** Generates 1-hour signed access URLs, offloading bandwidth and egress from Vercel serverless containers.

---

## 4. End-to-End Request Lifecycles

### A. Steganography Injection & Cloud Storage Workflow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Vercel as Vercel Serverless (main.py)
    participant Stego as StegoDrive Engine
    participant Supabase as Supabase Storage (stego-vault)

    User->>Vercel: POST /stego (Carrier File + Secret Text)
    Vercel->>Stego: encode(file_bytes, secret_text)
    Note over Stego: In-Memory LSB Pixel/Waveform Injection
    Stego-->>Vercel: (Success, Encoded Bytes)
    
    alt Supabase Storage Available
        Vercel->>Supabase: Upload bytes to stego-vault/{uuid}.png
        Supabase-->>Vercel: 200 OK
        Vercel->>Supabase: create_signed_url({uuid}.png, 3600s)
        Supabase-->>Vercel: Temporary Signed URL
        Vercel-->>User: Render /stego with Cloud Download Link
    else Supabase Storage Unavailable / Fails
        Vercel-->>User: flask.send_file(io.BytesIO(bytes), as_attachment=True)
    end
```

### B. Distributed Honeypot & Edge Geolocation Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant Edge as Vercel Edge Network
    participant Serverless as Flask routes.py
    participant OSSim as core/os_sim.py
    participant Mongo as MongoDB Atlas (rate_limits)
    participant AI as Gemini AIaaS Pool
    participant Supa as Supabase (attack_logs)

    Attacker->>Edge: POST /login (Malicious Payload + Keystroke Timings)
    Edge->>Serverless: Forward Request + (x-vercel-ip-country, city, ip)
    Serverless->>OSSim: run_in_sandbox(payload) [Synchronous]
    OSSim-->>Serverless: Syscall Status: BLOCKED / CLEARED
    
    Serverless->>AI: analyze_attack(payload, wpm, backspaces)
    AI-->>Serverless: Threat Profile JSON (Score: 0-100)
    
    Serverless->>Mongo: track_and_rate_limit(ip, threat_score)
    Mongo-->>Serverless: Cumulative IP Threat Status
    
    Serverless->>Supa: insert(log_entry with Country, City, Region)
    
    alt Threat Score >= 50 or Rate Blocked
        Serverless-->>Attacker: Redirect to /ghost (Tarpit Delay Trap)
    else Invalid Credential
        Serverless-->>Attacker: 200 JSON (Login Failed)
    end
```

---

## 5. Security Architecture

1. **Content Security Policy (CSP):** Managed via `Flask-Talisman`:
   - `default-src: 'self'`
   - `script-src: 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com`
   - `connect-src: 'self' https:` (ensures live `/api/cloud-health` AJAX and cloud assets operate without interruption)
   - `img-src: 'self' data: https:` (supports inline steganography previews and Supabase presigned URLs)
2. **CSRF Protection:** Managed globally via `Flask-WTF` (`CSRFProtect`).
3. **AST Sandbox Isolation:** Sandboxed code cannot execute system calls, inspect environment variables, or import unauthorized modules.
4. **Least-Privilege Secret Management:** Secrets are injected strictly via Vercel Environment Variables and never committed to version control.
