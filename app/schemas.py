from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class VerifyRequest(BaseModel):
    """Schema for the verify endpoint request"""
    discord_id: str
    discord_username: str
    captcha_token: str
    metadata: dict = {}


class VerificationResponse(BaseModel):
    """Schema for the verify endpoint response"""
    success: bool
    message: str
    verification_id: Optional[str] = None
    redirect_url: Optional[str] = None


class WebhookPayload(BaseModel):
    """Schema for Discord webhook payload"""
    success: bool
    discord_id: str
    discord_username: str
    timestamp: datetime
    ip_address_encrypted: bool = True  # Indicate that IP is encrypted
    method: str = "captcha"
    metadata: dict = {}


class VerificationBase(BaseModel):
    """Schema for verification base fields"""
    discord_id: str
    discord_username: str
    ip_address: str  # This will be encrypted
    user_agent: Optional[str] = None
    method: str = "captcha"
    extra_data: dict = {}