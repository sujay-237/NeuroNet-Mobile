from google import genai
from google.genai import types
import json
import time
import os

class NeuroAI:
    def __init__(self):
        self.active_clients = []
        self.current_client_idx = 0
        self.is_active = False
        
        # Load up to 5 keys from the environment variables
        api_keys = []
        for i in range(1, 6):
            key = os.getenv(f"GOOGLE_API_KEY_{i}")
            if key:
                api_keys.append(key)
        
        # Fallback to the original single key if none of the numbered ones exist
        if not api_keys:
            single_key = os.getenv("GOOGLE_API_KEY")
            if single_key:
                api_keys.append(single_key)

        if not api_keys:
            print("[AI WARNING] No GOOGLE_API_KEYs found in environment variables.")
            print("[AI SYSTEM] Defaulting to Local Simulation Mode.")
            self.is_active = False
            return

        # Initialize a GenAI client for each valid key
        for idx, key in enumerate(api_keys):
            try:
                client = genai.Client(api_key=key)
                self.active_clients.append(client)
            except Exception as e:
                print(f"[AI WARNING] Failed to initialize client for key {idx+1}: {e}")

        if self.active_clients:
            self.is_active = True
            print(f"[AI SYSTEM] Connected to Google Gemini with {len(self.active_clients)} active keys.")
        else:
            print("[AI SYSTEM] Defaulting to Local Simulation Mode.")

    def _execute_with_round_robin(self, api_call_func):
        """
        Attempts to execute the API call using active clients in a round-robin fashion.
        If a client fails, it catches the error and tries the next available client.
        """
        if not self.is_active or not self.active_clients:
            raise Exception("AI System is offline or has no active clients.")

        num_clients = len(self.active_clients)
        start_idx = self.current_client_idx

        # Loop through all clients starting from the current index
        for attempt in range(num_clients):
            idx = (start_idx + attempt) % num_clients
            client = self.active_clients[idx]
            
            try:
                result = api_call_func(client)
                
                # On success, advance the starting index for the NEXT request (Round-Robin)
                self.current_client_idx = (idx + 1) % num_clients
                return result
                
            except Exception as e:
                print(f"[AI WARNING] Key {idx+1} failed ({e}). Attempting failover to next key...")
        
        # If the loop finishes without returning, all keys failed
        raise Exception("All Gemini API keys exhausted or failed.")

    def analyze_attack(self, payload, wpm, backspaces, path_taken):
        """
        Main function called by routes.py for the Login Honeypot.
        """
        if not self.is_active:
            return self._local_simulation(payload, wpm, backspaces)

        try:
            return self._query_google_ai(payload, wpm, backspaces)
        except Exception as e:
            # This catch triggers if ALL 5 keys fail during _query_google_ai
            print(f"[AI ERROR] API Failed completely ({e}). Switching to Simulation...")
            return self._local_simulation(payload, wpm, backspaces)

    def osint_scan(self, query):
        if not self.is_active:
            return {
                "risk_level": "UNKNOWN",
                "summary": "AI Neural Link Offline. Cannot retrieve live intelligence.",
                "breaches": ["System Offline"],
                "recommendation": "Check API Key configuration."
            }

        prompt = f"""
        Act as a Dark Web Threat Analyst. The user is searching for intelligence on: "{query}".
        
        1. If the query is a domain/company: Summarize known data breaches, reputational history, and security posture.
        2. If the query is an email/user: Explain general risks associated with this format or domain (DO NOT generate fake PII or fake passwords).
        3. If the query is generic: Define the term from a cybersecurity perspective.
        
        Return a strict JSON object with this format:
        {{
            "risk_level": "LOW", "MEDIUM", or "HIGH",
            "summary": "A 2-sentence executive summary of the target's threat landscape.",
            "breaches": [
                {{"source": "Name of Breach/Incident", "data": "Type of data exposed (e.g. Emails, Passwords)", "date": "YYYY-MM-DD"}},
                {{"source": "Related Risk", "data": "Description of potential impact", "date": "Current"}}
            ]
        }}
        """

        def api_call(client):
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )
            return json.loads(response.text)

        try:
            return self._execute_with_round_robin(api_call)
        except Exception as e:
            return {
                "risk_level": "ERROR",
                "summary": "Connection to Threat Intel Database interrupted.",
                "breaches": [{"source": "API Error", "data": str(e), "date": "NOW"}]
            }
    
    def chat(self, user_input):
        if not self.is_active:
            return "[SIMULATION] Neural Link Offline. Unable to reach Gemini Core."

        prompt = f"Act as 'NeuroNet', a sophisticated cybersecurity AI. Keep responses concise, technical, and cool. User says: {user_input}"
        
        def api_call(client):
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            return response.text

        try:
            return self._execute_with_round_robin(api_call)
        except Exception as e:
            return f"[SYSTEM ERROR] Connection interrupted across all keys: {e}"

    def _query_google_ai(self, payload, wpm, backspaces):
        prompt = f"""
        Act as a Cybersecurity Expert. Analyze this honeypot log:
        Code: "{payload}"
        Metrics: {wpm} WPM, {backspaces} Backspaces.

        Return valid JSON only (no markdown):
        {{
            "intent_analysis": "Explain code intent",
            "psychological_profile": "Profile the attacker",
            "offender_category": "Category",
            "threat_score": 0 to 100
        }}
        """
        
        def api_call(client):
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )
            return json.loads(response.text)
            
        return self._execute_with_round_robin(api_call)

    def _local_simulation(self, payload, wpm, backspaces):
        print("[SYSTEM] Engaged Local Behavioral Analysis Engine (Simulation)...")
        time.sleep(0.5) 

        payload_lower = payload.lower()
        if "union" in payload_lower:
            intent = "SQL Injection (Data Extraction)"
            base_score = 80
        elif "drop" in payload_lower or "delete" in payload_lower:
            intent = "SQL Injection (Destructive)"
            base_score = 95
        elif "alert" in payload_lower:
            intent = "XSS (Cross-Site Scripting)"
            base_score = 60
        else:
            intent = "Suspicious Probing / Auth Bypass"
            base_score = 40

        if wpm > 150:
            profile = "Inhuman typing speed. Likely an automated script."
            category = "AUTOMATED BOT"
            score = 99
        elif wpm < 30 or backspaces > 4:
            profile = "High hesitation and error rate. Likely a novice."
            category = "NOVICE / SCRIPT KIDDIE"
            score = base_score - 10
        else:
            profile = "Calculated, steady input. Likely a professional."
            category = "SOPHISTICATED ACTOR"
            score = base_score + 10

        return {
            "intent_analysis": f"[SIMULATED] {intent}",
            "psychological_profile": profile,
            "offender_category": category,
            "threat_score": min(100, max(0, score))
        }