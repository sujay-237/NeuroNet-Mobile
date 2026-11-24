import datetime
import os
from pymongo import MongoClient, ASCENDING

class CloudCacheManager:
    """
    Distributed Cloud Caching and Distributed Rate Limiting using MongoDB Atlas TTL Indexes.
    Provides automatic fallback to in-memory/no-op when MongoDB is unavailable.
    """
    def __init__(self, mongo_uri=None, db_name="neuronet_db"):
        self.mongo_uri = mongo_uri or os.getenv("MONGO_URI")
        self.db_name = db_name
        self.client = None
        self.db = None
        self.is_connected = False
        self.ttl_indexes_ready = False
        self._init_connection()

    def _init_connection(self):
        if not self.mongo_uri:
            print("[CLOUD CACHE] No MONGO_URI provided. Cache operating in local fallback mode.")
            return

        try:
            self.client = MongoClient(self.mongo_uri, serverSelectionTimeoutMS=3000)
            # Verify connectivity
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            self.is_connected = True
            print("[CLOUD CACHE] Successfully connected to MongoDB Atlas.")
            self._ensure_ttl_indexes()
        except Exception as e:
            print(f"[CLOUD CACHE WARNING] MongoDB connection failed ({e}). Fallback active.")
            self.is_connected = False

    def _ensure_ttl_indexes(self):
        """Creates automatic TTL expiration indexes for OSINT cache and rate limiting."""
        if not self.is_connected or self.db is None:
            return

        try:
            # 1. AI OSINT Cache: 24-hour expiration (86400 seconds)
            self.db.osint_cache.create_index(
                [("created_at", ASCENDING)],
                expireAfterSeconds=86400,
                name="osint_cache_24h_ttl",
                background=True
            )
            # Query lookup index
            self.db.osint_cache.create_index(
                [("query_key", ASCENDING)],
                unique=True,
                name="osint_query_key_idx",
                background=True
            )

            # 2. Distributed Rate Limits: 1-hour expiration (3600 seconds)
            self.db.rate_limits.create_index(
                [("updated_at", ASCENDING)],
                expireAfterSeconds=3600,
                name="rate_limits_1h_ttl",
                background=True
            )
            self.db.rate_limits.create_index(
                [("ip", ASCENDING)],
                unique=True,
                name="rate_limits_ip_idx",
                background=True
            )
            self.ttl_indexes_ready = True
            print("[CLOUD CACHE] MongoDB TTL Indexes verified (osint_cache: 24h, rate_limits: 1h).")
        except Exception as e:
            print(f"[CLOUD CACHE WARNING] TTL index configuration failed: {e}")
            self.ttl_indexes_ready = False

    # --- AI OSINT RESPONSE CACHE (24h TTL) ---
    def get_osint_cache(self, query):
        """Retrieves cached AI intelligence if present and not expired."""
        if not self.is_connected or self.db is None:
            return None

        try:
            key = str(query).strip().lower()
            record = self.db.osint_cache.find_one({"query_key": key})
            if record and "data" in record:
                cached_data = dict(record["data"])
                cached_data["cached"] = True
                cached_data["cache_source"] = "MongoDB Atlas TTL Cache"
                cached_data["cached_at"] = record.get("created_at", "").isoformat() if hasattr(record.get("created_at", ""), "isoformat") else str(record.get("created_at", ""))
                return cached_data
        except Exception as e:
            print(f"[CLOUD CACHE ERROR] Read error for '{query}': {e}")
        return None

    def set_osint_cache(self, query, data):
        """Stores AI intelligence with a 24-hour automatic TTL timestamp."""
        if not self.is_connected or self.db is None or not data:
            return False

        try:
            key = str(query).strip().lower()
            now = datetime.datetime.utcnow()
            # Clean data copy
            clean_data = dict(data)
            clean_data.pop("cached", None)
            clean_data.pop("cache_source", None)
            clean_data.pop("cached_at", None)

            self.db.osint_cache.update_one(
                {"query_key": key},
                {
                    "$set": {
                        "query_key": key,
                        "data": clean_data,
                        "created_at": now
                    }
                },
                upsert=True
            )
            return True
        except Exception as e:
            print(f"[CLOUD CACHE ERROR] Write error for '{query}': {e}")
            return False

    # --- DISTRIBUTED RATE LIMITER (1h TTL) ---
    def track_and_rate_limit(self, ip, threat_score=0, max_requests=60, max_threat_score=250):
        """
        Tracks IP threat history and request frequency across stateless serverless instances.
        Returns: {
            "allowed": bool,
            "ip": str,
            "request_count": int,
            "threat_score": float,
            "is_blocked": bool,
            "reason": str
        }
        """
        if not self.is_connected or self.db is None:
            # Fallback allow with basic logging
            return {
                "allowed": True,
                "ip": ip,
                "request_count": 1,
                "threat_score": float(threat_score),
                "is_blocked": False,
                "reason": "MongoDB offline (local bypass)"
            }

        try:
            now = datetime.datetime.utcnow()
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

            req_count = doc.get("request_count", 1)
            total_threat = doc.get("cumulative_threat", 0.0)

            # Evaluate thresholds
            if req_count > max_requests:
                return {
                    "allowed": False,
                    "ip": ip,
                    "request_count": req_count,
                    "threat_score": total_threat,
                    "is_blocked": True,
                    "reason": f"Request rate limit exceeded ({req_count}/{max_requests} per hour)."
                }

            if total_threat >= max_threat_score:
                return {
                    "allowed": False,
                    "ip": ip,
                    "request_count": req_count,
                    "threat_score": total_threat,
                    "is_blocked": True,
                    "reason": f"Cumulative threat score exceeded safe threshold ({total_threat}/{max_threat_score})."
                }

            return {
                "allowed": True,
                "ip": ip,
                "request_count": req_count,
                "threat_score": total_threat,
                "is_blocked": False,
                "reason": "OK"
            }
        except Exception as e:
            print(f"[RATE LIMIT ERROR] Tracking failed for {ip}: {e}")
            return {
                "allowed": True,
                "ip": ip,
                "request_count": 1,
                "threat_score": float(threat_score),
                "is_blocked": False,
                "reason": f"Rate limiter error: {e}"
            }

    # --- CLOUD TELEMETRY STATUS ---
    def get_status(self):
        """Returns health status of the MongoDB distributed cache and TTL indexes."""
        if not self.is_connected or self.db is None:
            return {
                "status": "FALLBACK",
                "connected": False,
                "ttl_indexes": False,
                "engine": "Local In-Memory / No-Op"
            }
        return {
            "status": "ONLINE",
            "connected": True,
            "ttl_indexes": self.ttl_indexes_ready,
            "engine": "MongoDB Atlas Distributed TTL Cache",
            "collections": ["osint_cache (24h TTL)", "rate_limits (1h TTL)", "vault"]
        }
