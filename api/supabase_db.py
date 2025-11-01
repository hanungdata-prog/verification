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

    async def insert_verification(self, verification_data: Dict[str, Any]) -> bool:
        """
        Insert verification data into Supabase database
        """
        try:
            logger.info("🔄 Starting Supabase insertion process")
            
            # Validate required fields
            required_fields = ["discord_id", "discord_username", "ip_address"]
            for field in required_fields:
                if field not in verification_data:
                    logger.error(f"❌ Missing required field: {field}")
                    return False

            # Prepare the data for Supabase
            supabase_data = {
                "discord_id": verification_data["discord_id"],
                "discord_username": verification_data["discord_username"],
                "ip_address": verification_data["ip_address"],
                "user_agent": verification_data.get("user_agent", ""),
                "method": verification_data.get("method", "captcha"),
                "extra_data": verification_data.get("extra_data", {}),
            }

            logger.info(f"📊 Prepared data for Supabase: {supabase_data}")

            url = f"{self.supabase_url}/rest/v1/verifications"
            
            async with AsyncClient(timeout=30.0) as client:
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