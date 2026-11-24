# Operator & Developer Setup Guide

This guide provides step-by-step instructions to configure, run, and deploy **NeuroNet-Mobile** on **Vercel Serverless Functions** with **Google Gemini**, **MongoDB Atlas**, and **Supabase**.

---

## 1. Prerequisites

- Python 3.12+ (or Python 3.14)
- Git
- Accounts on:
  - [Vercel](https://vercel.com)
  - [Google AI Studio](https://aistudio.google.com/)
  - [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
  - [Supabase](https://supabase.com)

---

## 2. Cloud Infrastructure Setup

### A. Google Gemini Multi-Key Pool (AIaaS)
NeuroNet-Mobile supports up to 5 pooled API keys for round-robin load distribution and automatic failover.
1. Visit [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Generate one or more API keys (up to 5).
3. Save the keys to configure as:
   - `GOOGLE_API_KEY_1`
   - `GOOGLE_API_KEY_2`
   - `GOOGLE_API_KEY_3`
   - `GOOGLE_API_KEY_4`
   - `GOOGLE_API_KEY_5`
   *(Or simply `GOOGLE_API_KEY` if using a single key).*

### B. MongoDB Atlas Setup (DBaaS & TTL Caches)
1. Log in to [MongoDB Atlas](https://cloud.mongodb.com) and create a free Shared Cluster (M0).
2. Under **Network Access**, add `0.0.0.0/0` (Allow access from anywhere, required for dynamic serverless IPs).
3. Under **Database Access**, create a database user and generate a secure password.
4. Click **Connect -> Drivers -> Python** and copy the connection string:
   ```
   mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```
5. Set this string as `MONGO_URI`.
*(Note: TTL indexes on `osint_cache` and `rate_limits` are created automatically by `core/cloud_cache.py` on first run).*

### C. Supabase Setup (BaaS & Cloud Object Storage)
1. Create a new project in [Supabase](https://app.supabase.com).
2. Navigate to **Project Settings -> API** and copy:
   - **Project URL** (`SUPABASE_URL`)
   - **anon / public key** or **service_role key** (`SUPABASE_KEY`)
3. Open the **SQL Editor** in Supabase and run the following schema to initialize all required tables:

```sql
-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    phone TEXT,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. User Activity Audit Trail
CREATE TABLE IF NOT EXISTS user_activity (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

-- 3. Honeypot Attack Logs
CREATE TABLE IF NOT EXISTS attack_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TEXT NOT NULL,
    ip TEXT NOT NULL,
    country TEXT DEFAULT 'LOCAL',
    city TEXT DEFAULT 'Localhost',
    vercel_region TEXT DEFAULT 'local-node',
    payload TEXT NOT NULL,
    wpm INTEGER DEFAULT 0,
    backspaces INTEGER DEFAULT 0,
    intent TEXT,
    profile TEXT,
    category TEXT,
    score NUMERIC DEFAULT 0,
    syscall_status TEXT DEFAULT 'CLEARED'
);
```

4. Create the Cloud Object Storage Bucket:
   - Navigate to **Storage** in the Supabase Dashboard.
   - Click **New Bucket**.
   - Set **Bucket Name** to: `stego-vault`
   - Set **Public bucket** to `OFF` (The application generates secure signed URLs with 1-hour expiration).
   - Click **Save**.

---

## 3. Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/sujay-237/NeuroNet-Mobile.git
   cd NeuroNet-Mobile
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure your `.env` file:**
   ```bash
   cp .env.example .env
   ```
   Fill in your actual API keys and connection strings in `.env`.

5. **Start the local Flask development server:**
   ```bash
   python main.py
   ```
   Access the application at `http://127.0.0.1:5000`.

---

## 4. Deploying to Vercel (Production)

1. **Push your code to GitHub:**
   ```bash
   git add .
   git commit -m "Production serverless build for Vercel"
   git push origin main
   ```

2. **Connect to Vercel:**
   - Log into [Vercel](https://vercel.com).
   - Click **Add New... -> Project**.
   - Select your GitHub repository: `sujay-237/NeuroNet-Mobile`.

3. **Configure Environment Variables in Vercel:**
   In the **Configure Project** screen under **Environment Variables**, add:
   - `GOOGLE_API_KEY_1` (and keys 2-5 if using pool)
   - `SUPABASE_URL`
   - `SUPABASE_KEY`
   - `MONGO_URI`
   - `FLASK_SECRET_KEY`

4. **Deploy:**
   - Click **Deploy**.
   - Vercel will install dependencies from `requirements.txt` and launch the application using `@vercel/python` routing from `vercel.json`.

---

## 5. Verification & Telemetry Inspection

After deployment, test and inspect your live services:

1. **Live Cloud Health Telemetry:**
   Visit `https://<your-vercel-domain>/api/cloud-health` to view the JSON telemetry report:
   - Verify `compute.runtime` shows `"Vercel Serverless"`.
   - Verify `compute.vercel_region` displays the active Edge region (e.g., `iad1`, `sfo1`).
   - Verify `aiaas.status` shows `"ONLINE"` with active pooled keys.
   - Verify `dbaas_cache.status` shows `"ONLINE"` with TTL indexes active.
   - Verify `baas_storage.status` shows `"ONLINE"`.

2. **Holographic Architecture Visualizer:**
   Navigate to `https://<your-vercel-domain>/architecture` to observe the 3D HUD telemetry badges update dynamically in real time.

3. **Stego Drive Test:**
   - Go to `/stego`.
   - Select **Image (.PNG)** -> **Injection**.
   - Upload any PNG, enter a secret message, and click **Initiate Injection**.
   - Verify that a Supabase Storage signed download URL is generated (or streams immediately if storage fallback triggers).
   - Select **Extraction**, upload the encoded file, and verify the secret message extracts cleanly.

4. **Hardened Sandbox Test:**
   - Go to `/sandbox`.
   - Run safe code:
     ```python
     import math, json
     print(json.dumps({"result": math.sqrt(256)}))
     ```
     *(Verifies standard execution output).*
   - Run restricted code:
     ```python
     import os
     print(os.environ)
     ```
     *(Verifies `[SECURITY BLOCKED] Import of 'os' is prohibited`)*.

---

## 6. Troubleshooting Common Issues

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **Stego returns MP3 error** | `ffmpeg` is not present in serverless container | Upload `.wav` files. Serverless functions cannot run system `ffmpeg` binaries. |
| **MongoDB shows FALLBACK** | IP not whitelisted or invalid URI | Ensure `0.0.0.0/0` is added in MongoDB Atlas Network Access. |
| **Supabase shows FALLBACK** | Missing URL or invalid service key | Check `SUPABASE_URL` and `SUPABASE_KEY` in Vercel Environment Variables. |
| **Gemini shows FALLBACK** | API key quota exhausted or missing | Verify key validity in Google AI Studio or add multiple keys (`GOOGLE_API_KEY_1`..`5`). |
| **504 Gateway Timeout** | Long code execution in sandbox | Sandbox enforces a strict timeout; loops taking >3.0s are automatically terminated. |
