import re
import hashlib
import hmac
import secrets
import os
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, unquote
import logging

from fastapi import HTTPException, Query
from pydantic import BaseModel, validator

logger = logging.getLogger(__name__)

class QueryValidator:
    """Validates and sanitizes query parameters"""

    # Discord ID pattern: 17-19 digit snowflake ID
    DISCORD_ID_PATTERN = re.compile(r'^\d{17,19}$')

    # Discord username pattern: username#discriminator or username
    DISCORD_USERNAME_PATTERN = re.compile(r'^[\w]{2,32}#\d{4}$|^[\w]{2,32}$')

    # Safe characters for parameter values
    SAFE_CHARS = re.compile(r'^[a-zA-Z0-9\-_\.~!$&\'()*+,;=:@/%]+$')

    # Maximum lengths for parameters
    MAX_DISCORD_ID_LENGTH = 19
    MAX_DISCORD_USERNAME_LENGTH = 37  # username#discriminator
    MAX_TOKEN_LENGTH = 2048
    MAX_NONCE_LENGTH = 128

    @staticmethod
    def validate_discord_id(discord_id: str) -> bool:
        """Validate Discord ID format"""
        if not discord_id:
            return False

        if len(discord_id) > QueryValidator.MAX_DISCORD_ID_LENGTH:
            return False

        return bool(QueryValidator.DISCORD_ID_PATTERN.match(discord_id))

    @staticmethod
    def validate_discord_username(username: str) -> bool:
        """Validate Discord username format"""
        if not username:
            return False

        # Decode URL encoded characters
        username = unquote(username)

        if len(username) > QueryValidator.MAX_DISCORD_USERNAME_LENGTH:
            return False

        return bool(QueryValidator.DISCORD_USERNAME_PATTERN.match(username))

    @staticmethod
    def validate_token(token: str) -> bool:
        """Validate CAPTCHA token format"""
        if not token:
            return False

        if len(token) > QueryValidator.MAX_TOKEN_LENGTH:
            return False

        # Check for safe characters only
        return bool(QueryValidator.SAFE_CHARS.match(token))

    @staticmethod
    def validate_nonce(nonce: str) -> bool:
        """Validate CSRF nonce format"""
        if not nonce:
            return False

        if len(nonce) > QueryValidator.MAX_NONCE_LENGTH:
            return False

        # Check for safe characters only
        return bool(QueryValidator.SAFE_CHARS.match(nonce))

    @staticmethod
    def sanitize_query_params(params: Dict[str, str]) -> Dict[str, str]:
        """Sanitize query parameters"""
        sanitized = {}

        for key, value in params.items():
            if not key or not value:
                continue

            # Only allow known parameter names
            allowed_params = {
                'discord_id', 'discord_username', 'captcha_token',
                'csrf_nonce', 'session_id', 'redirect_url'
            }

            if key not in allowed_params:
                logger.warning(f"Unexpected query parameter: {key}")
                continue

            # Decode and validate values
            decoded_value = unquote(str(value))

            if key == 'discord_id' and QueryValidator.validate_discord_id(decoded_value):
                sanitized[key] = decoded_value
            elif key == 'discord_username' and QueryValidator.validate_discord_username(decoded_value):
                sanitized[key] = decoded_value
            elif key == 'captcha_token' and QueryValidator.validate_token(decoded_value):
                sanitized[key] = decoded_value
            elif key == 'csrf_nonce' and QueryValidator.validate_nonce(decoded_value):
                sanitized[key] = decoded_value
            elif key in ['session_id', 'redirect_url']:
                # Additional validation for these parameters
                if len(decoded_value) <= 2048 and QueryValidator.SAFE_CHARS.match(decoded_value):
                    sanitized[key] = decoded_value

        return sanitized

    @staticmethod
    def validate_url_parameters(discord_id: str = None, discord_username: str = None,
                              captcha_token: str = None, csrf_nonce: str = None) -> Dict[str, Any]:
        """Validate URL parameters for verification endpoints"""
        errors = []

        # Validate Discord ID
        if discord_id:
            if not QueryValidator.validate_discord_id(discord_id):
                errors.append("Invalid Discord ID format")

        # Validate Discord username
        if discord_username:
            if not QueryValidator.validate_discord_username(discord_username):
                errors.append("Invalid Discord username format")

        # Validate CAPTCHA token
        if captcha_token:
            if not QueryValidator.validate_token(captcha_token):
                errors.append("Invalid CAPTCHA token format")

        # Validate CSRF nonce
        if csrf_nonce:
            if not QueryValidator.validate_nonce(csrf_nonce):
                errors.append("Invalid CSRF nonce format")

        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

class SecureQueryString:
    """Generates and validates secure query strings"""

    @staticmethod
    def generate_secure_params(params: Dict[str, str]) -> Dict[str, str]:
        """Generate secure query parameters with signature"""
        # Create timestamp for freshness
        timestamp = str(int(time.time()))

        # Add timestamp to params
        secure_params = params.copy()
        secure_params['timestamp'] = timestamp

        # Create signature
        signature = SecureQueryString._sign_params(secure_params)
        secure_params['sig'] = signature

        return secure_params

    @staticmethod
    def verify_signed_params(params: Dict[str, str], max_age: int = 300) -> bool:
        """Verify signed query parameters"""
        if 'sig' not in params or 'timestamp' not in params:
            return False

        # Extract signature
        signature = params.pop('sig')

        # Check timestamp (prevent replay attacks)
        try:
            timestamp = int(params['timestamp'])
            current_time = int(time.time())

            if current_time - timestamp > max_age:
                logger.warning(f"Expired query parameters: {timestamp} vs {current_time}")
                return False
        except (ValueError, KeyError):
            return False

        # Verify signature
        expected_signature = SecureQueryString._sign_params(params)
        return hmac.compare_digest(signature, expected_signature)

    @staticmethod
    def _sign_params(params: Dict[str, str]) -> str:
        """Create HMAC signature for parameters"""
        # Get secret key from environment
        secret_key = os.getenv('QUERY_SIGNATURE_SECRET', secrets.token_urlsafe(32))

        # Sort parameters for consistent signature
        sorted_params = sorted(params.items())

        # Create string to sign
        param_string = '&'.join([f"{k}={v}" for k, v in sorted_params])

        # Create signature
        return hmac.new(
            secret_key.encode(),
            param_string.encode(),
            hashlib.sha256
        ).hexdigest()

class VerificationRequest(BaseModel):
    """Secure verification request model"""
    discord_id: str
    discord_username: str
    captcha_token: str
    csrf_nonce: str
    metadata: dict = {}

    @validator('discord_id')
    def validate_discord_id(cls, v):
        if not QueryValidator.validate_discord_id(v):
            raise ValueError('Invalid Discord ID format')
        return v

    @validator('discord_username')
    def validate_discord_username(cls, v):
        if not QueryValidator.validate_discord_username(v):
            raise ValueError('Invalid Discord username format')
        return v

    @validator('captcha_token')
    def validate_captcha_token(cls, v):
        if not QueryValidator.validate_token(v):
            raise ValueError('Invalid CAPTCHA token format')
        return v

    @validator('csrf_nonce')
    def validate_csrf_nonce(cls, v):
        if not QueryValidator.validate_nonce(v):
            raise ValueError('Invalid CSRF nonce format')
        return v

    @validator('metadata')
    def validate_metadata(cls, v):
        # Limit metadata size
        metadata_str = str(v)
        if len(metadata_str) > 2048:
            raise ValueError('Metadata too large')
        return v

class SuspiciousActivityLog(BaseModel):
    """Model for logging suspicious activities"""
    activity: str
    timestamp: int
    user_agent: str
    domain: str
    ip_address: Optional[str] = None
    session_id: Optional[str] = None
    additional_data: dict = {}

    @validator('activity')
    def validate_activity(cls, v):
        # Limit activity description length
        if len(v) > 500:
            raise ValueError('Activity description too long')
        return v

    @validator('user_agent')
    def validate_user_agent(cls, v):
        # Limit user agent length
        if len(v) > 500:
            raise ValueError('User agent too long')
        return v

    @validator('domain')
    def validate_domain(cls, v):
        # Basic domain validation
        if not v or len(v) > 253:
            raise ValueError('Invalid domain')
        return v

def validate_verification_params(
    discord_id: str = Query(..., description="Discord user ID"),
    discord_username: str = Query(..., description="Discord username"),
    captcha_token: str = Query(..., description="CAPTCHA verification token"),
    csrf_nonce: str = Query(..., description="CSRF protection nonce")
) -> Dict[str, Any]:
    """FastAPI dependency for validating verification parameters"""
    validation_result = QueryValidator.validate_url_parameters(
        discord_id=discord_id,
        discord_username=discord_username,
        captcha_token=captcha_token,
        csrf_nonce=csrf_nonce
    )

    if not validation_result["valid"]:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid parameters",
                "details": validation_result["errors"]
            }
        )

    return {
        "discord_id": discord_id,
        "discord_username": discord_username,
        "captcha_token": captcha_token,
        "csrf_nonce": csrf_nonce
    }

def extract_and_validate_query_params(request_url: str) -> Dict[str, str]:
    """Extract and validate query parameters from URL"""
    try:
        parsed_url = urlparse(request_url)
        query_params = parse_qs(parsed_url.query)

        # Convert single values to strings
        params = {}
        for key, values in query_params.items():
            if values:
                params[key] = values[0]

        # Sanitize parameters
        return QueryValidator.sanitize_query_params(params)

    except Exception as e:
        logger.error(f"Error parsing query parameters: {e}")
        return {}