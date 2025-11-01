import os
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from httpx import AsyncClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class SupabaseClient:
    """Simple Supabase client for database operations"""

    def __init__(self):
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.supabase_key = os.getenv("SUPABASE_KEY")

        if not self.supabase_url or not self.supabase_key:
            raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")

        self.headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        }

    async def insert_verification(self, verification_data: Dict[str, Any]) -> bool:
        """
        Insert verification data into Supabase database

        Args:
            verification_data: Dictionary containing verification information

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Prepare the data for Supabase to match your schema
            supabase_data = {
                "discord_id": verification_data["discord_id"],
                "discord_username": verification_data["discord_username"],
                "ip_address": verification_data["ip_address"],  # Already encrypted
                "user_agent": verification_data.get("user_agent", ""),
                "method": verification_data.get("method", "captcha"),
                "extra_data": verification_data.get("extra_data", {}),
                # Don't include id - let Supabase auto-generate UUID
                # Don't include created_at/verified_at - let Supabase use defaults
            }

            url = f"{self.supabase_url}/rest/v1/verifications"

            async with AsyncClient() as client:
                response = await client.post(
                    url,
                    headers=self.headers,
                    json=supabase_data,
                    timeout=30.0
                )

                if response.status_code in [200, 201]:
                    logger.info(f"Successfully saved verification to Supabase: {verification_data['discord_id']}")
                    logger.info(f"Supabase response: {response.text}")
                    return True
                else:
                    logger.error(f"Failed to save verification to Supabase: {response.status_code} - {response.text}")
                    return False

        except Exception as e:
            logger.error(f"Error inserting verification into Supabase: {str(e)}")
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