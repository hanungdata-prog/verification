import os
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from httpx import AsyncClient  # IMPORT INI YANG PENTING
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class SupabaseClient:
    """Simple Supabase client for database operations"""

    def __init__(self):
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.supabase_key = os.getenv("SUPABASE_KEY")

        logger.info(f"Supabase URL: {self.supabase_url}")
        logger.info(f"Supabase Key configured: {'Yes' if self.supabase_key else 'No'}")

        if not self.supabase_url:
            logger.error("❌ SUPABASE_URL not configured")
            raise ValueError("SUPABASE_URL must be set in environment variables")

        if not self.supabase_key:
            logger.error("❌ SUPABASE_KEY not configured")
            raise ValueError("SUPABASE_KEY must be set in environment variables")

        self.headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        }

        logger.info("✅ Supabase client initialized successfully")

    async def check_existing_verification(self, discord_id: str) -> Optional[Dict[str, Any]]:
        """
        Check if user already has a verification in the database
        Returns the existing verification data if found, None otherwise
        """
        try:
            logger.info(f"🔍 CHECKING EXISTING VERIFICATION - Discord ID: {discord_id}")

            # Query for existing verification
            url = f"{self.supabase_url}/rest/v1/verifications"
            params = {
                "discord_id": f"eq.{discord_id}",
                "limit": 1,
                "order": "created_at.desc"
            }

            # FIXED: Added debug logging for query parameters
            logger.info(f"🔍 DATABASE QUERY - URL: {url}")
            logger.info(f"🔍 DATABASE QUERY - Params: {params}")

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    url,
                    headers=self.headers,
                    params=params
                )

            # FIXED: Enhanced debug logging
            logger.info(f"📋 DATABASE RESPONSE - Status: {response.status_code}")
            logger.info(f"📋 DATABASE RESPONSE - Headers: {dict(response.headers)}")
            logger.info(f"📋 DATABASE RESPONSE - Content-Type: {response.headers.get('content-type')}")

            if response.status_code == 200:
                data = response.json()
                logger.info(f"📊 DATABASE RESPONSE - Data length: {len(data) if data else 0}")
                logger.info(f"📊 DATABASE RESPONSE - Raw data: {data}")

                if data and len(data) > 0:
                    existing_verification = data[0]
                    # FIXED: Added comprehensive logging for existing user
                    logger.info(f"✅ EXISTING USER FOUND - Discord ID: {discord_id}")
                    logger.info(f"✅ EXISTING USER DATA - Username: {existing_verification.get('discord_username')}")
                    logger.info(f"✅ EXISTING USER DATA - Verification ID: {existing_verification.get('verification_id')}")
                    logger.info(f"✅ EXISTING USER DATA - Created At: {existing_verification.get('created_at')}")
                    logger.info(f"✅ EXISTING USER DATA - Full record: {existing_verification}")
                    return existing_verification
                else:
                    # FIXED: Clear logging for new user case
                    logger.info(f"✅ NEW USER DETECTED - No existing verification for Discord ID: {discord_id}")
                    logger.info(f"✅ NEW USER - Safe to proceed with verification")
                    return None
            else:
                # FIXED: Enhanced error logging
                logger.error(f"❌ DATABASE ERROR - Failed to check existing verification")
                logger.error(f"❌ DATABASE ERROR - Status: {response.status_code}")
                logger.error(f"❌ DATABASE ERROR - Response text: {response.text}")
                logger.error(f"❌ DATABASE ERROR - Response headers: {dict(response.headers)}")
                return None

        except Exception as e:
            # FIXED: Enhanced exception logging
            logger.error(f"❌ CRITICAL ERROR - Checking existing verification failed")
            logger.error(f"❌ CRITICAL ERROR - Discord ID: {discord_id}")
            logger.error(f"❌ CRITICAL ERROR - Exception: {str(e)}")
            logger.error(f"❌ CRITICAL ERROR - Exception type: {type(e).__name__}")
            import traceback
            logger.error(f"❌ CRITICAL ERROR - Traceback: {traceback.format_exc()}")
            return None

    async def check_ip_verification_count(self, ip_address: str, time_window_hours: int = 24) -> int:
        """
        Check how many verifications have been done from this IP in the last X hours
        Returns the count of verifications
        """
        try:
            logger.info(f"🔍 Checking verification count for IP: {ip_address}")

            # Calculate time threshold
            from datetime import datetime, timedelta
            time_threshold = (datetime.utcnow() - timedelta(hours=time_window_hours)).isoformat()

            # Query for verifications from this IP in the time window
            url = f"{self.supabase_url}/rest/v1/verifications"
            params = {
                "ip_address": f"eq.{ip_address}",
                "created_at": f"gte.{time_threshold}",
                "select": "count"
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    url,
                    headers=self.headers,
                    params=params
                )

            logger.info(f"📋 IP count check status: {response.status_code}")

            if response.status_code == 200:
                # Get count from response headers or content
                content_range = response.headers.get("content-range", "")
                if content_range:
                    # Format: "0-0/1" where last number is the total count
                    count = int(content_range.split("/")[-1])
                else:
                    # Fallback: parse response if it's a count
                    try:
                        data = response.json()
                        count = len(data) if isinstance(data, list) else 0
                    except:
                        count = 0

                logger.info(f"✅ Found {count} verifications from IP {ip_address} in last {time_window_hours} hours")
                return count
            else:
                logger.error(f"❌ Failed to check IP verification count. Status: {response.status_code}")
                return 0

        except Exception as e:
            logger.error(f"❌ Error checking IP verification count: {str(e)}", exc_info=True)
            return 0

    async def insert_verification(self, verification_data: Dict[str, Any]) -> bool:
        """
        Insert verification data into Supabase database
        """
        try:
            logger.info("🔄 Starting Supabase insertion process")

            # Validate required fields - accept both 'id' and 'verification_id'
            verification_id = verification_data.get("verification_id") or verification_data.get("id")
            if not verification_id:
                logger.error("❌ Missing required field: verification_id or id")
                return False

            required_fields = ["discord_id", "discord_username", "ip_address"]
            for field in required_fields:
                if field not in verification_data:
                    logger.error(f"❌ Missing required field: {field}")
                    return False

            # Prepare the data for Supabase
            supabase_data = {
                "verification_id": verification_id,
                "discord_id": verification_data["discord_id"],
                "discord_username": verification_data["discord_username"],
                "ip_address": verification_data["ip_address"],
                "user_agent": verification_data.get("user_agent", ""),
                "method": verification_data.get("method", "captcha"),
                "extra_data": verification_data.get("extra_data", {}),
            }

            logger.info(f"📊 Prepared data for Supabase: {supabase_data}")

            url = f"{self.supabase_url}/rest/v1/verifications"

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    url,
                    headers=self.headers,
                    json=supabase_data
                )

            logger.info(f"📋 Response status: {response.status_code}")
            logger.info(f"📋 Response body: {response.text}")

            if response.status_code in [200, 201, 204]:
                logger.info(f"✅ Successfully saved verification to Supabase")
                return True
            else:
                logger.error(f"❌ FAILED to save verification. Status: {response.status_code}")
                logger.error(f"❌ Response: {response.text}")
                return False

        except Exception as e:
            logger.error(f"❌ Unexpected Error during Supabase insertion: {str(e)}", exc_info=True)
            return False

# Global instance
_supabase_client = None

def get_supabase_client() -> SupabaseClient:
    """Get or create Supabase client instance"""
    global _supabase_client
    if _supabase_client is None:
        try:
            _supabase_client = SupabaseClient()
        except Exception as e:
            logger.error(f"Failed to initialize Supabase client: {str(e)}")
            return None
    return _supabase_client