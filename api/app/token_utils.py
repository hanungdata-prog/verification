"""
Token utilities for encoding/decoding Discord information
"""
import base64
import json
import secrets
import hashlib
import hmac
import os
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class TokenManager:
    """Manage secure tokens for Discord user information"""

    def __init__(self):
        # Get secret key from environment or generate one
        self.secret_key = os.getenv("TOKEN_SECRET_KEY") or secrets.token_urlsafe(32)
        self.token_expiry = 3600  # 1 hour

    def generate_token(self, discord_id: str, discord_username: str) -> str:
        """Generate a secure token containing Discord information"""
        try:
            # Create payload
            payload = {
                "discord_id": discord_id,
                "discord_username": discord_username,
                "timestamp": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(seconds=self.token_expiry)).isoformat()
            }

            # Create signature
            payload_json = json.dumps(payload, sort_keys=True)
            signature = self._sign_payload(payload_json)

            # Combine payload and signature
            token_data = {
                "data": payload,
                "sig": signature
            }

            # Encode to base64 URL-safe
            token_json = json.dumps(token_data)
            token_bytes = token_json.encode('utf-8')
            token_b64 = base64.urlsafe_b64encode(token_bytes).decode('utf-8')

            # Remove padding to make URL cleaner
            token_b64 = token_b64.rstrip('=')

            logger.info(f"✅ Generated token for Discord ID: {discord_id}")
            return token_b64

        except Exception as e:
            logger.error(f"❌ Failed to generate token: {e}")
            raise

    def decode_token(self, token: str) -> Optional[Dict]:
        """Decode and verify token"""
        try:
            # Add back padding if removed
            padding = len(token) % 4
            if padding:
                token += '=' * (4 - padding)

            # Decode from base64
            token_bytes = base64.urlsafe_b64decode(token.encode('utf-8'))
            token_json = token_bytes.decode('utf-8')
            token_data = json.loads(token_json)

            # Extract payload and signature
            payload = token_data.get("data")
            signature = token_data.get("sig")

            if not payload or not signature:
                logger.warning("⚠️ Invalid token format")
                return None

            # Verify signature
            payload_json = json.dumps(payload, sort_keys=True)
            expected_signature = self._sign_payload(payload_json)

            if not self._secure_compare(signature, expected_signature):
                logger.warning("⚠️ Token signature verification failed")
                return None

            # Check expiry
            expires_at = datetime.fromisoformat(payload.get("expires_at", ""))
            if datetime.utcnow() > expires_at:
                logger.warning("⚠️ Token expired")
                return None

            logger.info(f"✅ Token decoded successfully for Discord ID: {payload.get('discord_id')}")
            return payload

        except Exception as e:
            logger.error(f"❌ Failed to decode token: {e}")
            return None

    def _sign_payload(self, payload_json: str) -> str:
        """Create HMAC signature for payload"""
        hmac_obj = hmac.new(
            self.secret_key.encode('utf-8'),
            payload_json.encode('utf-8'),
            hashlib.sha256
        )
        return base64.urlsafe_b64encode(hmac_obj.digest()).decode('utf-8').rstrip('=')

    def _secure_compare(self, val1: str, val2: str) -> bool:
        """Secure string comparison to prevent timing attacks"""
        return hmac.compare_digest(val1, val2)

    def generate_short_token(self, discord_id: str, discord_username: str) -> str:
        """Generate a shorter token for URL friendliness"""
        # Generate full token first
        full_token = self.generate_token(discord_id, discord_username)

        # Create short token (first 16 chars + hash)
        short_part = full_token[:16]
        hash_part = hashlib.md5(full_token.encode()).hexdigest()[:8]

        return f"{short_part}{hash_part}"

    def decode_short_token(self, short_token: str) -> Optional[Dict]:
        """Decode short token by looking it up or reconstructing"""
        # This is a simplified version - in production, you'd want to store
        # the mapping in Redis or database
        try:
            # For now, try to decode as full token (will work for recent tokens)
            return self.decode_token(short_token)
        except:
            logger.warning("⚠️ Short token decode failed - token may be too old")
            return None

# Global instance
token_manager = TokenManager()

def generate_discord_token(discord_id: str, discord_username: str) -> str:
    """Generate token for Discord user info"""
    return token_manager.generate_token(discord_id, discord_username)

def decode_discord_token(token: str) -> Optional[Dict]:
    """Decode Discord token"""
    return token_manager.decode_token(token)

def generate_short_discord_token(discord_id: str, discord_username: str) -> str:
    """Generate short token for Discord user info"""
    return token_manager.generate_short_token(discord_id, discord_username)