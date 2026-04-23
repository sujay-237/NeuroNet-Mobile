from functools import wraps
from flask import Blueprint, render_template, request, jsonify, send_file, session, redirect
import datetime
import random
import os
import time
import requests
import json
import math
import re
import hashlib
import string
import secrets
import xml.etree.ElementTree as ET
import tempfile
from collections import Counter
from supabase import create_client, Client 
from pymongo import MongoClient

# CORE MODULE IMPORTS
from core.ai_integrator import NeuroAI
from core.os_sim import Sandbox
from core.security_modules import StegoDrive
from core.sandbox_exec import CodeSandbox
from werkzeug.security import generate_password_hash, check_password_hash

main_bp = Blueprint('main', __name__)

# --- SUPABASE CONFIGURATION (Dashboard, Users, Activity, Attacks) ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        print("[SYSTEM] Connected to Supabase Database (Core Logs & Users).")
    except Exception as e:
        print(f"[SYSTEM ERROR] Could not connect to Supabase: {e}")
else:
    print("[SYSTEM WARNING] Supabase Credentials not found. Database features disabled.")

# --- MONGODB CONFIGURATION (Secure Vault Only) ---
MONGO_URI = os.getenv("MONGO_URI")

mongo_client = None
mongo_db = None
if MONGO_URI:
    try:
        mongo_client = MongoClient(MONGO_URI)
        mongo_db = mongo_client['neuronet_db'] 
        print("[SYSTEM] Connected to MongoDB (Secure Vault).")
    except Exception as e:
        print(f"[SYSTEM ERROR] Could not connect to MongoDB: {e}")
else:
    print("[SYSTEM WARNING] MongoDB Credentials not found. Vault features disabled.")

# --- INSTANCE INITIALIZATION ---
ai_brain = NeuroAI()
sandbox_manager = Sandbox()
stego_engine = StegoDrive()
code_runner = CodeSandbox()

# --- GLOBAL STATE ---
SERVER_START_TIME = time.time()


# --- AUTHENTICATION DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session:
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function


# --- HELPER FUNCTIONS ---
def log_activity(email, action):
    """Logs user activity to Supabase"""
    if supabase:
        try:
            supabase.table('user_activity').insert({
                "email": email,
                "action": action,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }).execute()
        except Exception as e:
            print(f"[DB ERROR] Failed to log activity to Supabase: {e}")

def get_system_stats():
    """Calculates real-time server uptime, CPU load, and memory usage for the HUD."""
    uptime_seconds = int(time.time() - SERVER_START_TIME)
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_str = f"{hours:02}h {minutes:02}m {seconds:02}s"

    try:
        import psutil
        # Get accurate CPU and Memory data
        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        mem_percent = mem.percent
        memory_str = f"{mem.used // (1024*1024)} MB"
        
        # Simulate an active network load percentage between 1 and 15% for visual effect
        net_percent = random.randint(1, 15)

        return {
            "uptime": uptime_str, 
            "memory": memory_str,
            "cpu_percent": cpu_percent,
            "mem_percent": mem_percent,
            "net_percent": net_percent
        }
    except ImportError:
        return {
            "uptime": uptime_str, 
            "memory": "0 MB",
            "cpu_percent": 0,
            "mem_percent": 0,
            "net_percent": 0
        }

def quick_sort_attacks(data):
    """Sorts attack history by threat score (Descending)."""
    if not data or len(data) <= 1: return data
    pivot = data[len(data) // 2]
    def safe_score(item):
        try: return float(item.get('score', 0))
        except (ValueError, TypeError): return 0.0
    pivot_val = safe_score(pivot)
    left = [x for x in data if safe_score(x) > pivot_val]
    middle = [x for x in data if safe_score(x) == pivot_val]
    right = [x for x in data if safe_score(x) < pivot_val]
    return quick_sort_attacks(left) + middle + quick_sort_attacks(right)

def parse_ai_json(prompt):
    """Safely asks the AI for JSON and parses it, avoiding crashes."""
    if not ai_brain.is_active: return None
    try:
        raw = ai_brain.chat(prompt)
        cleaned = raw.replace("```json", "").replace("```", "").strip()
        return json.loads(cleaned)
    except Exception as e: return None

# ADVANCED FEATURE: NLP SOCIAL ENGINEERING & PHISHING ANALYZER
def analyze_psychology(text):
    """Uses LLM to detect sentiment, tactics, targeted traits, and phishing parameters in text."""
    prompt = f"""You are a cybersecurity threat intelligence analyst. Analyze the following text for social engineering manipulation, target profiling, AND phishing indicators.
    Respond ONLY with a valid JSON object in EXACTLY this format:
    {{
        "threat_score": <int 0-100 representing overall manipulation risk>,
        "phishing_probability": <int 0-100 likelihood this is a direct phishing/scam attempt>,
        "tactics": ["Specific tactics e.g., Manufactured Urgency, Authority Bias"],
        "phishing_flags": ["Specific red flags e.g., Suspicious Link, Unsolicited Attachment, Credential Request"],
        "sentiment": "Primary emotional tone",
        "vector": "Likely attack vector, e.g., Spear Phishing, CEO Fraud, Smishing",
        "personality": {{ "neuroticism": <int 0-100>, "openness": <int 0-100>, "agreeableness": <int 0-100> }}
    }}
    Text to analyze: {text}"""
    
    ai_result = parse_ai_json(prompt)
    if ai_result: return ai_result
    
    # Fallback if AI is offline
    return {
        "threat_score": 50, "phishing_probability": 50,
        "tactics": ["AI Offline - Keyword Analysis Defaulted"],
        "phishing_flags": ["System Offline - Cannot verify links"],
        "sentiment": "Neutral", "vector": "Unknown",
        "personality": {"neuroticism": 50, "openness": 50, "agreeableness": 50}
    }

def search_breach_data(email):
    """Queries XposedOrNot for Breaches AND Pastes."""
    url = f"https://api.xposedornot.com/v1/breach-analytics?email={email}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 404: return []
        if response.status_code != 200: return [{"Name": "API ERROR", "Description": f"Status: {response.status_code}", "DataClasses": ["Error"]}]
        try: data = response.json()
        except ValueError: return []
        if data is None: return []

        formatted_results = []
        exposed = data.get("ExposedBreaches")
        if exposed and isinstance(exposed, dict):
            breaches = exposed.get("breaches_details")
            if breaches and isinstance(breaches, list):
                for item in breaches:
                    if not item: continue
                    raw_data = item.get("xposed_data", "")
                    data_classes = str(raw_data).split(";") if raw_data else ["Identity Data"]
                    formatted_results.append({
                        "Name": item.get("breach", "Unknown Breach"),
                        "Domain": "Database Leak",
                        "BreachDate": str(item.get("breached_date", "Unknown")),
                        "Description": item.get("details", "Credential exposure detected."),
                        "DataClasses": data_classes
                    })
        pastes = data.get("Pastes")
        if pastes and isinstance(pastes, list):
             for item in pastes:
                if not item: continue
                formatted_results.append({
                    "Name": f"Paste: {item.get('pasteId', 'Unknown ID')}",
                    "Domain": "Public Text Dump",
                    "BreachDate": str(item.get('date', 'Unknown')),
                    "Description": "Data found in a public text file (Pastebin). High risk.",
                    "DataClasses": ["Raw Text", "Email"]
                })
        return formatted_results
    except Exception as e:
        return [{"Name": "SYSTEM ERROR", "Description": "Search process failed.", "DataClasses": ["Error"]}]

def check_pwned_passwords(password):
    """Checks the HIBP API safely using k-Anonymity via SHA-1 hashes."""
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix: return int(count)
    except Exception as e: pass
    return 0

def analyze_password_strength(password):
    """Enhanced Analytics for Password Prediction (Entropy + Logic)."""
    pool_size = 0
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 32

    length = len(password)
    entropy = length * math.log2(pool_size) if pool_size > 0 else 0

    # Penalties for predictable patterns
    if re.search(r'(.)\1{2,}', password): entropy -= 10 # Repeated chars (aaa)
    if re.search(r'(123|abc|qwerty|password|admin)', password.lower()): entropy -= 25 
    
    entropy = max(0, entropy)
    score = min(int((entropy / 120) * 100), 100) # 120+ bits is military grade

    crack_time = "INSTANT"
    verdict = "CRITICAL RISK"
    if entropy > 110: 
        crack_time = "CENTURIES"
        verdict = "MILITARY GRADE"
    elif entropy > 80: 
        crack_time = "DECADES"
        verdict = "STRONG"
    elif entropy > 50: 
        crack_time = "MONTHS"
        verdict = "MODERATE"
    elif entropy > 30:
        crack_time = "DAYS"
        verdict = "WEAK"

    leaks = check_pwned_passwords(password)
    if leaks > 0: 
        verdict = "COMPROMISED"
        score = max(0, score - 50)

    return {
        "entropy": round(entropy, 2), "score": score, 
        "crack_time": crack_time, "verdict": verdict, "leaks": leaks,
        "analytics": {
            "length": length, "has_lower": has_lower, 
            "has_upper": has_upper, "has_digit": has_digit, "has_symbol": has_symbol
        }
    }


# --- ROUTES ---

@main_bp.route('/')
def login(): 
    return render_template('login.html')

@main_bp.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@main_bp.route('/api/stats')
def api_stats(): return jsonify(get_system_stats())

# --- AUTHENTICATION ROUTES (SUPABASE INTEGRATED) ---

@main_bp.route('/register', methods=['POST'])
def register_user():
    data = request.json
    name, email = data.get('name'), data.get('email')
    password, phone = data.get('password'), data.get('phone')
    
    if not all([name, email, password, phone]):
        return jsonify({"status": "failed", "message": "All fields, including password, are required"})
    
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        return jsonify({"status": "failed", "message": "Invalid email format."})
    
    if supabase is None:
        return jsonify({"status": "failed", "message": "Supabase offline. Cannot register."})

    try:
        response = supabase.table('users').select('*').eq('email', email).execute()
        if response.data:
            return jsonify({"status": "failed", "message": "Email already registered"})
    except Exception as e:
        return jsonify({"status": "failed", "message": f"DB Error: {e}"})
        
    hashed_pw = generate_password_hash(password)
    
    try:
        supabase.table('users').insert({
            "name": name, "email": email, "password": hashed_pw, 
            "phone": phone, "status": "pending"
        }).execute()
    except Exception as e:
        return jsonify({"status": "failed", "message": f"Insert Error: {e}"})
    
    log_activity(email, "Registered Account")
    return jsonify({"status": "success", "message": "Account created. Pending Admin Approval."})

@main_bp.route('/login', methods=['POST'])
def handle_login():
    data = request.json
    login_type = data.get('type')
    payload = data.get('payload', '')
    password = data.get('password', '')
    behavior = data.get('behavior', {})
    
    if request.headers.getlist("X-Forwarded-For"):
        attacker_ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        attacker_ip = request.remote_addr

    if not password:
        return jsonify({"status": "failed", "message": "Password is required."})

    is_valid_email = True
    if login_type == 'user':
        is_valid_email = bool(re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", payload))

    # 1. ADMIN LOGIN LOGIC
    if login_type == 'admin':
        if payload == "Sujay" and password == "Boss@123":
            session['role'] = 'admin'
            session['user'] = 'Admin'
            return jsonify({"status": "success", "redirect": "/dashboard"})

    # 2. USER LOGIN LOGIC
    elif login_type == 'user':
        if is_valid_email and supabase is not None:
            try:
                response = supabase.table('users').select('*').eq('email', payload).execute()
                if response.data:
                    user = response.data[0]
                    if check_password_hash(user['password'], password):
                        if user['status'] != 'approved':
                            return jsonify({"status": "failed", "message": "Account pending Admin approval."})
                        
                        session['role'] = 'user'
                        session['user'] = payload
                        log_activity(payload, "Logged In")
                        return jsonify({"status": "success", "redirect": "/architecture"})
            except Exception as e:
                print(f"Login Check Error: {e}")

    # --- 3. DETERMINE IF SUSPICIOUS (ATTACK/SQLi) OR JUST INVALID ---
    sql_patterns = re.compile(r"(--|\bOR\b\s+.+?=|<script>|\bUNION\b|;\s*(DROP|SELECT|UPDATE|INSERT|DELETE)|['\"]\s*=\s*['\"])", re.IGNORECASE)
    
    is_suspicious = False
    if not is_valid_email and login_type == 'user':
        is_suspicious = True
    if sql_patterns.search(payload) or sql_patterns.search(password):
        is_suspicious = True

    if not is_suspicious:
        return jsonify({"status": "failed", "message": "Invalid login credentials."})

    # --- 4. MALICIOUS ATTACK LOGGING & TARPITTING ---
    combined_payload = f"ID: {payload} | Pass: {password}"
    
    keystrokes = behavior.get('keys', [])
    wpm = 0
    backspaces = sum(1 for k in keystrokes if k.get('key') == 'Backspace')
    
    if len(keystrokes) > 1:
        start_time = keystrokes[0].get('time')
        end_time = keystrokes[-1].get('time')
        if start_time is not None and end_time is not None:
            duration = (end_time - start_time) / 60000
            if duration > 0:
                wpm = int((len(payload) / 5) / duration)

    sandbox_manager.run_in_sandbox(combined_payload)
    analysis = ai_brain.analyze_attack(combined_payload, wpm, backspaces, [])
    
    try: score = float(analysis.get("threat_score", 0))
    except: score = 0.0

    log_entry = {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "ip": attacker_ip, 
        "payload": combined_payload, 
        "wpm": wpm, 
        "backspaces": backspaces,
        "intent": analysis.get("intent_analysis", "Unknown"),
        "profile": analysis.get("psychological_profile", "Unknown"),
        "category": analysis.get("offender_category", "Unknown"),
        "score": score
    }

    if supabase:
        try: supabase.table('attack_logs').insert(log_entry).execute()
        except Exception: pass

    # TRAP: Redirect to Ghost Dashboard if high threat score or abnormal typing
    if score >= 50 or wpm > 150: 
        session['role'] = 'ghost'
        session['ghost_ip'] = attacker_ip
        
        ident = payload if payload else attacker_ip
        log_activity(ident, f"MALICIOUS LOGIN BLOCKED - Routed to Tarpit (Score: {score})")
        
        return jsonify({"status": "success", "redirect": "/ghost"})
    else:
        return jsonify({"status": "failed", "message": "Invalid login credentials."})


# --- GHOST DASHBOARD (TARPIT MODULE) ---
@main_bp.route('/ghost')
def ghost_dashboard():
    if session.get('role') != 'ghost': 
        return redirect('/')
    return render_template('ghost.html')

@main_bp.route('/ghost/action', methods=['POST'])
def ghost_action():
    if session.get('role') != 'ghost': 
        return jsonify({"error": "unauthorized"}), 403
    
    action = request.json.get('action', 'Unknown')
    
    delay_seconds = random.randint(5, 10)
    time.sleep(delay_seconds)
    
    log_activity(f"GHOST ({session.get('ghost_ip')})", f"Tarpitted exploring {action} for {delay_seconds}s")
    
    if action == "Vault": 
        return jsonify({"status": "success", "data": "Accessing Hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"})
    
    return jsonify({"status": "denied", "message": "Privilege Escalation Required."})


# --- ADMIN DASHBOARD ---

@main_bp.route('/dashboard')
def dashboard():
    if session.get('role') != 'admin':
        return redirect('/')

    history_data = []
    users = []
    activities = []
    
    if supabase:
        try: 
            history_data = supabase.table('attack_logs').select("*").execute().data 
            users = supabase.table('users').select("name, email, phone, status").execute().data
            activities = supabase.table('user_activity').select("*").order("timestamp", desc=True).limit(50).execute().data
        except Exception as e: 
            print(f"[DB ERROR] Dashboard Supabase Fetch Failed: {e}")

    sorted_history = quick_sort_attacks(history_data)
    dominant_profile = "ANALYZING..."
    if history_data:
        categories = [attack.get('category', 'Unknown') for attack in history_data]
        if categories: dominant_profile = Counter(categories).most_common(1)[0][0].upper()

    return render_template('dashboard.html', attacks=sorted_history, dominant_profile=dominant_profile, users=users, activities=activities)

@main_bp.route('/admin/approve/<email>', methods=['POST'])
def approve_user(email):
    if session.get('role') != 'admin': return jsonify({"status": "failed"}), 403
    if supabase is not None:
        try:
            supabase.table('users').update({"status": "approved"}).eq("email", email).execute()
            log_activity(session.get('user', 'Admin'), f"Approved Account: {email}")
        except Exception as e:
            return jsonify({"status": "failed", "message": str(e)})
    return jsonify({"status": "success"})

@main_bp.route('/admin/delete/<email>', methods=['POST'])
def delete_user(email):
    if session.get('role') != 'admin': return jsonify({"status": "failed"}), 403
    
    if supabase is not None:
        try:
            supabase.table('users').delete().eq("email", email).execute()
            supabase.table('user_activity').delete().eq("email", email).execute()
            log_activity(session.get('user', 'Admin'), f"Purged Account: {email}")
        except Exception as e:
            print(f"Supabase delete failed: {e}")
            
    if mongo_db is not None:
        try: mongo_db.vault.delete_many({"email": email}) 
        except Exception as e: print(f"MongoDB cascade delete failed: {e}")
            
    return jsonify({"status": "success"})

@main_bp.route('/admin/edit_user/<email>', methods=['POST'])
def edit_user(email):
    if session.get('role') != 'admin': return jsonify({"status": "failed"}), 403
    data = request.json
    
    if supabase is not None:
        try:
            update_data = {}
            if 'name' in data: update_data['name'] = data['name']
            if 'phone' in data: update_data['phone'] = data['phone']
            if 'status' in data: update_data['status'] = data['status']
            
            if update_data:
                supabase.table('users').update(update_data).eq("email", email).execute()
                log_activity(session.get('user', 'Admin'), f"Modified data for {email}")
                
        except Exception as e:
            return jsonify({"status": "failed", "message": str(e)})
            
    return jsonify({"status": "success"})


# --- STANDARD ROUTES ---

@main_bp.route('/architecture')
@login_required
def architecture(): 
    return render_template('architecture.html')

@main_bp.route('/python-info')
@login_required
def python_info(): 
    return render_template('python_info.html')

@main_bp.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encryptor():
    result = ""
    if request.method == 'POST':
        text = request.form.get('text', '')
        key = request.form.get('key', 'NEURO')
        if text:
            validated_text = text + "||VALID"
            extended_key = key * (len(validated_text) // len(key) + 1)
            result = ''.join(f"{ord(c) ^ ord(k):02x}" for c, k in zip(validated_text, extended_key))
        else: result = "ERROR: NO INPUT"
    return render_template('encrypt.html', result=result)

@main_bp.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decryptor():
    result = ""
    status = "waiting"
    if request.method == 'POST':
        ciphertext = request.form.get('text', '').strip()
        key = request.form.get('key', 'NEURO')
        try:
            bytes_obj = bytes.fromhex(ciphertext)
            extended_key = key * (len(bytes_obj) // len(key) + 1)
            decrypted_chars = [chr(b ^ ord(k)) for b, k in zip(bytes_obj, extended_key)]
            decrypted_raw = "".join(decrypted_chars)
            
            if decrypted_raw.endswith("||VALID"):
                result = decrypted_raw[:-7]
                status = "success"
            else:
                result = "ACCESS DENIED: INCORRECT KEY"
                status = "error"
        except Exception:
            result = "DATA CORRUPTION DETECTED"
            status = "error"
    return render_template('decrypt.html', result=result, status=status)

@main_bp.route('/darkweb', methods=['GET', 'POST'])
@login_required
def darkweb():
    breaches = None
    query = ""
    logs = []
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        logs = [
            f"[OPSEC] Secure Connection Established...",
            f"[NETWORK] Routing via node {random.randint(10,99)}.x.x.x...",
            f"[API] Querying Threat Intelligence...",
            f"[TARGET] {query}"
        ]
        if "@" in query and "." in query:
            breaches = search_breach_data(query)
            if not breaches:
                if len(breaches) == 1 and breaches[0]['Name'] in ["API ERROR", "SYSTEM ERROR"]:
                     logs.append(f"[ERROR] {breaches[0]['Description']}")
                else: logs.append("[RESULT] CLEAN: No compromised records found.")
            else: logs.append(f"[RESULT] ALERT: {len(breaches)} Exposure Events Identified.")
        else: logs.append("[ERROR] Invalid Email Syntax.")
    return render_template('darkweb.html', breaches=breaches, query=query, logs=logs)

@main_bp.route('/chatbot', methods=['GET', 'POST'])
@login_required
def chatbot():
    response = ""
    user_input = ""
    if request.method == 'POST':
        user_input = request.form.get('message')
        response = ai_brain.chat(user_input)
    return render_template('chatbot.html', response=response, last_msg=user_input)

@main_bp.route('/stego', methods=['GET', 'POST'])
@login_required
def stego():
    message = ""
    mode = "encode"
    show_download = False
    download_type = "image"
    
    # Use the system's temporary directory instead of the static folder
    temp_dir = tempfile.gettempdir()
    current_user = session.get('user', 'Unknown User')
    
    if request.method == 'POST':
        mode = request.form.get('mode')
        stego_type = request.form.get('stego_type', 'image') 
        file = request.files.get('carrier_file') 
        
        if file:
            if mode == 'encode':
                text = request.form.get('secret_text')
                if not text: 
                    message = "Error: No secret text provided."
                else:
                    if stego_type == 'image':
                        # Save to /tmp
                        filepath = os.path.join(temp_dir, 'stego_result.png')
                        file.save(filepath)
                        success, msg = stego_engine.encode(filepath, text, filepath)
                        message = msg
                        if success:
                            show_download = True
                            download_type = 'image'
                            log_activity(current_user, "Stego Drive: Encoded Image Payload")
                            
                    elif stego_type == 'audio':
                        ext = '.mp3' if file.filename.lower().endswith('.mp3') else '.wav'
                        filepath = os.path.join(temp_dir, f'stego_audio_input{ext}')
                        outpath = os.path.join(temp_dir, 'stego_audio_result.wav') 
                        
                        file.save(filepath)
                        success, msg = stego_engine.encode_audio(filepath, text, outpath)
                        message = msg
                        if success:
                            show_download = True
                            download_type = 'audio'
                            log_activity(current_user, f"Stego Drive: Encoded Audio Payload ({ext.upper()})")
                            
            elif mode == 'decode':
                if stego_type == 'image':
                    filepath = os.path.join(temp_dir, 'stego_upload.png')
                    file.save(filepath)
                    message = stego_engine.decode(filepath)
                    log_activity(current_user, "Stego Drive: Extracted Image Payload")
                    
                elif stego_type == 'audio':
                    ext = '.mp3' if file.filename.lower().endswith('.mp3') else '.wav'
                    filepath = os.path.join(temp_dir, f'stego_audio_upload{ext}')
                    file.save(filepath)
                    message = stego_engine.decode_audio(filepath)
                    log_activity(current_user, f"Stego Drive: Extracted Audio Payload ({ext.upper()})")
        else: 
            message = "Error: Please upload a valid carrier file."
            
    return render_template('stego.html', message=message, show_download=show_download, download_type=download_type)

@main_bp.route('/download_stego')
@login_required
def download_stego():
    temp_dir = tempfile.gettempdir()
    filepath = os.path.join(temp_dir, 'stego_result.png')
    
    try: 
        return send_file(filepath, as_attachment=True, download_name='encrypted_image.png')
    except FileNotFoundError: 
        return "File not found or expired.", 404

@main_bp.route('/download_stego_audio')
@login_required
def download_stego_audio():
    temp_dir = tempfile.gettempdir()
    filepath = os.path.join(temp_dir, 'stego_audio_result.wav')
    
    try: 
        return send_file(filepath, as_attachment=True, download_name='encrypted_audio.wav')
    except FileNotFoundError: 
        return "File not found or expired.", 404

@main_bp.route('/sandbox', methods=['GET', 'POST'])
@login_required
def sandbox():
    output = ""
    code = ""
    if request.method == 'POST':
        code = request.form.get('code', '')
        output = code_runner.execute(code)
    return render_template('sandbox.html', output=output, code=code)


# --- NEW MODULE ROUTES (AI, Vault, Feed) ---

@main_bp.route('/password-ai', methods=['GET', 'POST'])
@login_required
def password_ai():
    analysis = None
    pwd_input = ""
    suggested_pwd = ""
    if request.method == 'POST':
        action = request.form.get('action')
        if action == "analyze":
            pwd_input = request.form.get('password', '')
            if pwd_input: analysis = analyze_password_strength(pwd_input)
        elif action == "suggest":
            custom_word = request.form.get('custom_word', '')
            requested_length = int(request.form.get('length', 16))
            
            target_length = max(requested_length, len(custom_word) + 4)
            uppers = string.ascii_uppercase
            lowers = string.ascii_lowercase
            digits = string.digits
            symbols = "!@#$%^&*()-_=+"
            all_chars = uppers + lowers + digits + symbols
            
            filler_chars = [
                secrets.choice(uppers),
                secrets.choice(lowers),
                secrets.choice(digits),
                secrets.choice(symbols)
            ]
            
            remaining_length = target_length - len(custom_word) - len(filler_chars)
            for _ in range(max(0, remaining_length)):
                filler_chars.append(secrets.choice(all_chars))
                
            secure_random = random.SystemRandom()
            secure_random.shuffle(filler_chars)
            
            insert_pos = secure_random.randint(0, len(filler_chars))
            filler_chars.insert(insert_pos, custom_word)
            
            suggested_pwd = ''.join(filler_chars)
            
    return render_template('password.html', analysis=analysis, pwd_input=pwd_input, suggested_pwd=suggested_pwd)

@main_bp.route('/profiler', methods=['GET', 'POST'])
@login_required
def profiler():
    profile = None
    text_input = ""
    if request.method == 'POST':
        text_input = request.form.get('bio_text', '')
        if text_input: profile = analyze_psychology(text_input)
    return render_template('profiler.html', profile=profile, text_input=text_input)

# --- MONGODB VAULT IMPLEMENTATION ---
@main_bp.route('/vault', methods=['GET', 'POST'])
@login_required
def password_vault():
    if 'user' not in session or session.get('role') != 'user':
        return redirect('/') 
        
    current_email = session['user']
    message = ""
    saved_passwords = []

    if request.method == 'POST':
        service = request.form.get('service')
        username = request.form.get('username')
        password = request.form.get('password')
        
        encryption_key = "NEURO_VAULT_KEY"
        extended_key = encryption_key * (len(password) // len(encryption_key) + 1)
        encrypted_pwd = ''.join(f"{ord(c) ^ ord(k):02x}" for c, k in zip(password, extended_key))

        if mongo_db is not None:
            try:
                mongo_db.vault.insert_one({
                    "email": current_email,
                    "service": service,
                    "username": username,
                    "encrypted_password": encrypted_pwd
                })
                message = "CREDENTIALS SECURED IN MONGODB."
                log_activity(current_email, f"Added Vault Entry: {service}")
            except Exception as e:
                message = f"VAULT ERROR: {e}"

    if mongo_db is not None:
        try:
            cursor = mongo_db.vault.find({"email": current_email}, {"_id": 0})
            saved_passwords = list(cursor)
            
            encryption_key = "NEURO_VAULT_KEY"
            for item in saved_passwords:
                enc_hex = item.get("encrypted_password", "")
                try:
                    bytes_obj = bytes.fromhex(enc_hex)
                    extended_key = encryption_key * (len(bytes_obj) // len(encryption_key) + 1)
                    item["decrypted_password"] = "".join([chr(b ^ ord(k)) for b, k in zip(bytes_obj, extended_key)])
                except Exception:
                    item["decrypted_password"] = "DECRYPTION_ERROR"
                    
        except Exception as e: print(f"[DB ERROR] Vault Fetch Failed: {e}")

    return render_template('vault.html', message=message, vault_data=saved_passwords)


# --- LIVE CYBER DATA API (AJAX FETCH FOR CYBER FEED) ---
@main_bp.route('/api/cyber-data/<category>')
@login_required
def cyber_data_api(category):
    if category == 'news':
        try:
            url = "https://thehackernews.com/feeds/posts/default?alt=rss"
            resp = requests.get(url, timeout=5)
            root = ET.fromstring(resp.content)
            news = []
            for item in root.findall('./channel/item')[:4]:
                title = item.find('title').text
                date = item.find('pubDate').text[:16] 
                desc = re.sub('<[^<]+>', '', item.find('description').text) 
                news.append({"title": title, "date": date, "details": desc})
            return jsonify(news)
        except Exception as e:
            return jsonify([{"title": "Live News Feed Offline", "date": "Now", "details": f"Failed to fetch RSS. Reason: {e}"}])
            
    elif category == 'attacks':
        prompt = """Identify 3 real, major cyber attacks or critical CVEs from recent history. Return ONLY a valid JSON array. Format: [{"title": "Attack Name", "severity": "CRITICAL", "details": "Explanation"}]"""
        data = parse_ai_json(prompt)
        if data: return jsonify(data)
        return jsonify([{"title": "Log4Shell", "severity": "CRITICAL", "details": "A zero-day vulnerability in Log4j. Ensure the AI Link is active."}])
            
    elif category == 'encyclopedia':
        prompt = """Select 3 distinct, common cyber attack methodologies. Return ONLY a valid JSON array. Format: [{"title": "Attack Methodology", "severity": "High", "details": "A deep dive into how attackers execute this"}]"""
        data = parse_ai_json(prompt)
        if data: return jsonify(data)
        return jsonify([{"title": "Phishing", "severity": "High", "details": "Fraudulent attempt to obtain sensitive data. AI offline."}])
            
    elif category == 'learning':
        prompt = """Select 3 essential cybersecurity concepts or tools for a student to learn right now. Return ONLY a valid JSON array. Format: [{"title": "Topic Name", "difficulty": "Intermediate", "details": "Detailed explanation"}]"""
        data = parse_ai_json(prompt)
        if data: return jsonify(data)
        return jsonify([{"title": "Buffer Overflow", "difficulty": "Advanced", "details": "Occurs when a program overwrites adjacent memory locations. AI offline."}])
            
    return jsonify([])

@main_bp.route('/cyber-feed', methods=['GET', 'POST'])
@login_required
def cyber_feed():
    agent_response = ""
    user_query = ""
    if request.method == 'POST':
        user_query = request.form.get('agent_query')
        if user_query:
            prompt = f"Act as a highly specialized Cyber Threat Intelligence AI. Answer this query precisely and technically: {user_query}"
            agent_response = ai_brain.chat(prompt) 
    return render_template('cyber_feed.html', agent_response=agent_response, last_query=user_query)
