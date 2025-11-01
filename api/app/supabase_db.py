import os
import logging
from typing import Optional, Dict, Any
from datetime import datetime
import httpx
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

        Args:
            verification_data: Dictionary containing verification information

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info("🔄 Starting Supabase insertion process")
            logger.info(f"📥 Input verification_data: {verification_data}")

            # Validate required fields
            required_fields = ["discord_id", "discord_username", "ip_address"]
            for field in required_fields:
                if field not in verification_data:
                    logger.error(f"❌ Missing required field: {field}")
                    return False

            # Prepare the data for Supabase to match your schema
            supabase_data = {
                "discord_id": verification_data["discord_id"],
                "discord_username": verification_data["discord_username"],
                "ip_address": verification_data["ip_address"],  # Plain IP address (not encrypted)
                "user_agent": verification_data.get("user_agent", ""),
                "method": verification_data.get("method", "captcha"),
                "extra_data": verification_data.get("extra_data", {}),
            }

            logger.info(f"📊 Prepared data for Supabase: {supabase_data}")

            url = f"{self.supabase_url}/rest/v1/verifications"
            logger.info(f"🌐 Sending POST request to: {url}")
            logger.info(f"🔑 Headers: {self.headers}")

            async with AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    url,
                    headers=self.headers,
                    json=supabase_data
                )

            logger.info(f"📋 Response status: {response.status_code}")
            logger.info(f"📋 Response headers: {dict(response.headers)}")
            logger.info(f"📋 Response body: {response.text}")

            if response.status_code in [200, 201]:
                logger.info(f"✅ Successfully saved verification to Supabase for Discord ID: {verification_data['discord_id']}")
                return True
            else:
                logger.error(f"❌ FAILED to save verification to Supabase")
                logger.error(f"❌ HTTP Status: {response.status_code}")
                logger.error(f"❌ Response Text: {response.text}")

                # Try to parse error response for more details
                try:
                    error_data = response.json()
                    logger.error(f"❌ Parsed Error Details: {error_data}")
                except:
                    logger.error(f"❌ Could not parse error response as JSON")

                return False

        except httpx.RequestError as e:
            logger.error(f"❌ HTTP Request Error during Supabase insertion: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected Error during Supabase insertion: {str(e)}", exc_info=True)
            return False

    async def check_existing_verification(self, discord_id: str) -> Optional[Dict[str, Any]]:
        """
        Check if user already has a verification record

        Args:
            discord_id: Discord user ID

        Returns:
            Dict if verification exists, None otherwise
        """
        try:
            url = f"{self.supabase_url}/rest/v1/verifications"
            params = {
                "discord_id": f"eq.{discord_id}",
                "select": "*",
                "limit": 1,
                "order": "created_at.desc"
            }

            headers = self.headers.copy()
            headers.pop("Prefer", None)  # Remove Prefer header for GET requests

            async with AsyncClient() as client:
                response = await client.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=30.0
                )

                if response.status_code == 200:
                    data = response.json()
                    if data:
                        logger.info(f"Found existing verification for Discord ID: {discord_id}")
                        return data[0]
                    return None
                else:
                    logger.error(f"Failed to check existing verification: {response.status_code} - {response.text}")
                    return None

        except Exception as e:
            logger.error(f"Error checking existing verification in Supabase: {str(e)}")
            return None

# Global instance
supabase_client = None

def get_supabase_client() -> SupabaseClient:
    """Get or create Supabase client instance"""
    global supabase_client
    if supabase_client is None:
        try:
            supabase_client = SupabaseClient()
        except ValueError as e:
            logger.error(f"Failed to initialize Supabase client: {str(e)}")
            raise
    return supabase_client