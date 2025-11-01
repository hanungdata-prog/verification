import re
from typing import Optional
from fastapi import Request


def validate_discord_id(discord_id: str) -> bool:
    """
    Validate Discord ID format
    Discord IDs are typically 17-20 digit numbers
    """
    if not discord_id:
        return False
    
    # Discord IDs are numeric and typically 17-20 digits long
    pattern = r"^\d{17,20}$"
    return bool(re.match(pattern, discord_id))


def validate_discord_username(username: str) -> bool:
    """
    Validate Discord username format
    Discord usernames can contain letters, numbers, underscores, and hyphens
    """
    if not username:
        return False
    
    # Discord usernames are typically 2-32 characters
    if len(username) < 2 or len(username) > 32:
        return False
    
    # Check for valid characters (letters, numbers, underscores, hyphens)
    pattern = r"^[a-zA-Z0-9_-]+$"
    return bool(re.match(pattern, username))


def get_user_agent(request: Request) -> Optional[str]:
    """
    Extract user agent from request
    """
    return request.headers.get("user-agent")


def get_client_ip(request: Request) -> str:
    """
    Get the real client IP address, considering proxy headers
    """
    # Check for X-Forwarded-For header (most common)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first one
        return forwarded_for.split(",")[0].strip()
    
    # Check for X-Real-IP header
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    
    # Check for X-Client-IP header (used by some proxies)
    client_ip = request.headers.get("x-client-ip")
    if client_ip:
        return client_ip.strip()
    
    # Check for CF-Connecting-IP (Cloudflare)
    cf_connecting_ip = request.headers.get("cf-connecting-ip")
    if cf_connecting_ip:
        return cf_connecting_ip.strip()
    
    # Check for True-Client-IP (Akamai, CloudFlare)
    true_client_ip = request.headers.get("true-client-ip")
    if true_client_ip:
        return true_client_ip.strip()
    
    # Fallback to request.client.host
    return request.client.host


def format_timestamp(timestamp: str) -> str:
    """
    Format timestamp for display
    """
    from datetime import datetime
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return timestamp