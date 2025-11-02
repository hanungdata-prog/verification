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

            # Encode to base64 URL-safe with proper UTF-8 handling
            token_json = json.dumps(token_data, ensure_ascii=False, separators=(',', ':'))
            token_bytes = token_json.encode('utf-8')
            token_b64 = base64.urlsafe_b64encode(token_bytes).decode('utf-8')

            # Remove padding to make URL cleaner (but ensure it's still decodeable)
            token_b64 = token_b64.rstrip('=')

            logger.info(f"✅ Generated token for Discord ID: {discord_id}")
            return token_b64

        except Exception as e:
            logger.error(f"❌ Failed to generate token: {e}")
            raise

    def decode_token(self, token: str) -> Optional[Dict]:
        """Decode and verify token"""
        try:
            if not token:
                logger.warning("⚠️ Empty token provided")
                return None

            logger.info(f"🔍 Decoding token: {token[:20]}...")

            # Clean token - remove any URL encoding artifacts
            clean_token = token.strip()

            # Add back padding if removed (calculate required padding)
            padding_needed = (4 - len(clean_token) % 4) % 4
            if padding_needed:
                clean_token += '=' * padding_needed
                logger.info(f"📝 Added {padding_needed} characters of padding")

            try:
                # Decode from base64
                token_bytes = base64.urlsafe_b64decode(clean_token.encode('utf-8'))
                token_json = token_bytes.decode('utf-8')
                logger.info(f"📝 Token JSON length: {len(token_json)} characters")

                token_data = json.loads(token_json)
                logger.info(f"📝 Token data keys: {list(token_data.keys())}")

            except Exception as decode_error:
                logger.error(f"❌ Base64 decode error: {decode_error}")
                logger.error(f"❌ Token that failed: {clean_token}")
                return None

            # Extract payload and signature
            payload = token_data.get("data")
            signature = token_data.get("sig")

            if not payload or not signature:
                logger.warning("⚠️ Invalid token format - missing data or signature")
                logger.warning(f"Token data: {token_data}")
                return None

            # Verify signature
            payload_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
            expected_signature = self._sign_payload(payload_json)

            if not self._secure_compare(signature, expected_signature):
                logger.warning("⚠️ Token signature verification failed")
                logger.warning(f"Expected: {expected_signature[:20]}...")
                logger.warning(f"Received: {signature[:20]}...")
                return None

            # Check expiry
            try:
                expires_at_str = payload.get("expires_at", "")
                if not expires_at_str:
                    logger.warning("⚠️ No expiry date in token")
                    return None

                expires_at = datetime.fromisoformat(expires_at_str)
                if datetime.utcnow() > expires_at:
                    logger.warning(f"⚠️ Token expired. Expired at: {expires_at}, Current: {datetime.utcnow()}")
                    return None
            except Exception as expiry_error:
                logger.error(f"❌ Expiry check error: {expiry_error}")
                return None

            logger.info(f"✅ Token decoded successfully for Discord ID: {payload.get('discord_id')}")
            return payload

        except Exception as e:
            logger.error(f"❌ Failed to decode token: {e}")
            logger.error(f"❌ Token that failed: {token[:50] if token else 'None'}...")
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
        # Create a simpler token structure for short tokens
        try:
            # Create minimal payload
            payload = {
                "discord_id": discord_id,
                "discord_username": discord_username,
                "timestamp": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(seconds=self.token_expiry)).isoformat()
            }

            # Create signature
            payload_json = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
            signature = self._sign_payload(payload_json)

            # Create short token data
            short_token_data = {
                "data": payload,
                "sig": signature
            }

            # Encode with better UTF-8 handling
            token_json = json.dumps(short_token_data, ensure_ascii=False, separators=(',', ':'))
            token_bytes = token_json.encode('utf-8')
            token_b64 = base64.urlsafe_b64encode(token_bytes).decode('utf-8')

            # Remove padding for cleaner URL
            token_b64 = token_b64.rstrip('=')

            logger.info(f"✅ Generated short token for Discord ID: {discord_id}")
            return token_b64

        except Exception as e:
            logger.error(f"❌ Failed to generate short token: {e}")
            # Fallback to full token
            return self.generate_token(discord_id, discord_username)

    def decode_short_token(self, short_token: str) -> Optional[Dict]:
        """Decode short token"""
        # Short tokens use the same format as full tokens now
        return self.decode_token(short_token)

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