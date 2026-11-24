# Technical Implementation & Serverless Architecture Deep-Dive

This document details the engineering changes, code structures, and security mechanisms implemented to transform NeuroNet-Mobile into a cloud-native application running on **Vercel Serverless Functions**.

---

## 1. Cloud-Hardened Stego Drive Engine

### Files: `core/security_modules.py`, `app/routes.py`

### Challenges on Serverless Functions:
1. **Read-Only Filesystem:** Vercel functions execute in an AWS Lambda microVM environment where only `/tmp` is writable (max 512 MB ephemeral storage). Writing to `app/static/` or the project root throws an `OSError: [Errno 30] Read-only file system`.
2. **Missing System Binaries:** Standard serverless runtimes do not package CLI utilities such as `ffmpeg`. Attempting to transcode `.mp3` audio files with `pydub` raises `FileNotFoundError` or unhandled 500 crashes.

### Engineering Solutions:
- **In-Memory & Ephemeral I/O:** `StegoDrive.encode()` and `StegoDrive.decode()` accept either file objects, `io.BytesIO` streams, or file paths. Encoded output can be returned directly as raw bytes without persisting to disk.
- **Safe `/tmp` Buffering with Guaranteed Cleanup:** For audio parsing where file handles are required by Python's built-in `wave` module, temporary files are allocated using `_get_temp_filepath()`:
  ```python
  def _get_temp_filepath(suffix=""):
      temp_dir = tempfile.gettempdir()
      return os.path.join(temp_dir, f"stego_{uuid.uuid4().hex}{suffix}")
  ```
  Every temporary file is registered in a `temp_files` list and purged inside a strict `finally` block:
  ```python
  finally:
      for tf in temp_files:
          try:
              if os.path.exists(tf):
                  os.remove(tf)
          except Exception:
              pass
  ```
- **Built-in Waveform LSB Steganography:** Uses Python's native `wave` library to read frames, inject binary payloads into the Least Significant Bit (LSB) of standard 16-bit PCM audio frames, and reconstruct clean `.wav` artifacts without external libraries.
- **Serverless MP3 Guard:** Checks if incoming audio is `.mp3`. If `ffmpeg` or `pydub` is missing, it immediately returns a structured guidance message prompting for standard lossless `.wav` input rather than crashing.
- **Supabase Cloud Storage Integration (`stego-vault`):**
  When encoded artifacts are generated, `upload_to_supabase_storage()` uploads the bytes directly to the `stego-vault` bucket:
  ```python
  def upload_to_supabase_storage(file_bytes, filename, mime_type):
      if not supabase:
          return None
      try:
          bucket_name = "stego-vault"
          storage = supabase.storage.from_(bucket_name)
          storage.upload(path=filename, file=file_bytes, file_options={"content-type": mime_type, "upsert": "true"})
          res = storage.create_signed_url(filename, 3600)
          if isinstance(res, dict):
              return res.get("signedURL") or res.get("signedUrl")
          return getattr(res, "signed_url", getattr(res, "signedURL", None))
      except Exception as e:
          print(f"[STORAGE WARNING] Supabase Storage upload failed: {e}")
          return None
  ```
- **Automatic Stream Fallback:** If Supabase Storage is not provisioned or fails, the endpoint automatically falls back to streaming directly via Flask:
  ```python
  return send_file(
      io.BytesIO(output_bytes),
      mimetype=mime,
      as_attachment=True,
      download_name=artifact_name
  )
  ```

---

## 2. Hardened Serverless Python Sandbox

### File: `core/sandbox_exec.py`

### Challenges on Serverless Functions:
1. **Unrestricted `exec()` Danger:** Unrestricted code execution in a serverless environment allows attackers to inspect `os.environ` (stealing API keys and database credentials), read `/proc/`, or exhaust memory and CPU limits.
2. **Infinite Loop Hanging:** Serverless functions have execution timeout limits. An infinite loop (`while True: pass`) hangs until Vercel forces a 504 Gateway Timeout.

### Engineering Solutions:
- **Static AST Pre-Validation:**
  Before bytecode compilation, the Python source is parsed into an AST (`ast.parse()`). The tree is traversed to inspect all imports, calls, and attribute accesses:
  ```python
  for node in ast.walk(tree):
      if isinstance(node, ast.Import):
          for alias in node.names:
              root = alias.name.split('.')[0]
              if root not in ALLOWED_MODULES:
                  return False, f"[SECURITY BLOCKED] Import of '{alias.name}' is prohibited."
      elif isinstance(node, ast.Attribute):
          if node.attr in FORBIDDEN_ATTRIBUTES:
              return False, f"[SECURITY BLOCKED] Access to private attribute '{node.attr}' is prohibited."
          if node.attr in FORBIDDEN_NAMES:
              return False, f"[SECURITY BLOCKED] Access to system attribute '{node.attr}' is prohibited."
      elif isinstance(node, ast.Name):
          if node.id in {"eval", "exec", "open", "compile", "input", "breakpoint", "exit", "quit"}:
              return False, f"[SECURITY BLOCKED] Call to '{node.id}' is prohibited in serverless sandbox."
  ```
- **Stripped `__builtins__` Dictionary:**
  Removes dangerous primitives (`open`, `eval`, `exec`, `compile`, `input`) and wires `__import__` to a safe hook allowing only:
  `{'math', 'random', 'json', 'datetime', 're', 'hashlib', 'base64', 'string', 'collections', 'itertools'}`.
- **Thread-Safe `SafeStream` Buffer:**
  Replaces standard `sys.stdout` mutation with a custom stream class that locks writes and silently ignores writes if the execution times out and terminates, preventing `ValueError: I/O operation on closed file`.
- **Synchronous Execution Timeout:**
  Executes the sandboxed code in a worker thread and joins with `worker_thread.join(timeout=self.timeout_seconds)`. If `worker_thread.is_alive()`, execution is aborted and a clean `[TIMEOUT ERROR]` message is returned.

---

## 3. Synchronous OS Kernel Simulation

### File: `core/os_sim.py`

### Challenges on Serverless Functions:
- Background threads instantiated without `.join()` (e.g. `threading.Thread(...).start()`) are frozen or terminated by the Vercel AWS Lambda container supervisor immediately upon sending the HTTP response.

### Engineering Solutions:
- Eliminated asynchronous unjoined threading. The payload analysis and syscall pattern matching check run synchronously in microsecond time:
  ```python
  def run_in_sandbox(self, payload):
      return self._process_safe(payload)

  def _process_safe(self, payload):
      suspicious_syscalls = ["/etc/passwd", "cmd.exe", "powershell", "/bin/sh", "rm -rf", "wget", "curl", "chmod", "iptables"]
      detected = [sc for sc in suspicious_syscalls if sc in str(payload).lower()]
      if detected:
          return {"status": "BLOCKED", "detected": detected, "message": f"[OS KERNEL] BLOCKED: Malicious syscall(s) detected: {', '.join(detected)}", "isolated": True}
      return {"status": "CLEARED", "detected": [], "message": "[OS KERNEL] Syscall trace cleared. Sandbox integrity intact.", "isolated": True}
  ```

---

## 4. Distributed Cloud Caching & Rate Limiting (MongoDB TTL)

### File: `core/cloud_cache.py`

### Engineering Solutions:
- **MongoDB Atlas Connection Management:** Initialized with connection pooling and a short `serverSelectionTimeoutMS=3000` to prevent serverless function cold-start stalls if database endpoints are unreachable.
- **24-Hour OSINT TTL Index:**
  ```python
  self.db.osint_cache.create_index([("created_at", ASCENDING)], expireAfterSeconds=86400, name="osint_cache_24h_ttl", background=True)
  self.db.osint_cache.create_index([("query_key", ASCENDING)], unique=True, name="osint_query_key_idx", background=True)
  ```
  When a user runs a Dark Web OSINT query, the cache is inspected. On cache hit, the intelligence is returned with `"cached": True` and `"cache_source": "MongoDB Atlas TTL Cache"`. On cache miss, Gemini is called and the result is stored with `created_at = datetime.datetime.utcnow()`.
- **1-Hour Distributed Rate Limiter TTL Index:**
  ```python
  self.db.rate_limits.create_index([("updated_at", ASCENDING)], expireAfterSeconds=3600, name="rate_limits_1h_ttl", background=True)
  self.db.rate_limits.create_index([("ip", ASCENDING)], unique=True, name="rate_limits_ip_idx", background=True)
  ```
  Every incoming login attempt updates the attacker IP's cumulative threat score and request count atomically via `$inc` and `$set`:
  ```python
  doc = self.db.rate_limits.find_one_and_update(
      {"ip": ip},
      {
          "$inc": {"request_count": 1, "cumulative_threat": float(threat_score)},
          "$set": {"updated_at": now},
          "$setOnInsert": {"first_seen": now}
      },
      upsert=True,
      return_document=True
  )
  ```
  If `request_count > 60` or `cumulative_threat >= 250`, the attacker is blocked and rerouted to the Ghost tarpit.

---

## 5. Multi-Key Round-Robin Gemini AIaaS Pool

### File: `core/ai_integrator.py`

### Engineering Solutions:
- **Multi-Key Pooling:** Reads `GOOGLE_API_KEY_1` through `GOOGLE_API_KEY_5`. Initializes distinct `genai.Client` instances.
- **v1beta Protocol Specification:** Configures `http_options=types.HttpOptions(api_version='v1beta')` to ensure JSON structured output mode (`response_mime_type="application/json"`) works reliably across all API keys.
- **Round-Robin Rotation with Instant Failover:**
  If a key encounters quota exhaustion (HTTP 429) or invalid argument errors, `_execute_with_round_robin()` automatically fails over to the next healthy client in the pool.
- **Telemetry Reporting:** Exposes `get_pool_status()` returning total configured keys, active clients, and rotation strategy.

---

## 6. Vercel Edge Geolocation & Health Telemetry

### File: `app/routes.py`

### Engineering Solutions:
- **Edge Header Extraction:**
  - Client IP: `request.headers.get("x-forwarded-for").split(",")[0].strip()`
  - Country: `request.headers.get("x-vercel-ip-country", "LOCAL")`
  - City: `request.headers.get("x-vercel-ip-city", "Localhost")`
  - Vercel Region: `os.getenv("VERCEL_REGION", "local-node")`
- **Telemetry Endpoint (`/api/cloud-health`):**
  Aggregates status across all 4 pillars of the cloud architecture:
  ```json
  {
    "compute": {
      "runtime": "Vercel Serverless",
      "serverless": true,
      "vercel_region": "iad1",
      "vercel_env": "production",
      "python_version": "3.12.0",
      "os": "linux"
    },
    "aiaas": {
      "status": "ONLINE",
      "active_clients_count": 5,
      "strategy": "Round-Robin with Automatic Multi-Key Failover",
      "model": "gemini-2.5-flash"
    },
    "dbaas_cache": {
      "status": "ONLINE",
      "connected": true,
      "ttl_indexes": true,
      "engine": "MongoDB Atlas Distributed TTL Cache",
      "collections": ["osint_cache (24h TTL)", "rate_limits (1h TTL)", "vault"]
    },
    "baas_storage": {
      "status": "ONLINE",
      "storage_bucket": "stego-vault",
      "storage_status": "ONLINE",
      "provider": "Supabase BaaS (Postgres + S3 Storage API)"
    }
  }
  ```
