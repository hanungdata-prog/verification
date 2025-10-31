import os
import httpx
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get CAPTCHA provider settings
CAPTCHA_PROVIDER = os.getenv("CAPTCHA_PROVIDER", "recaptcha")  # 'recaptcha' or 'hcaptcha'
CAPTCHA_SECRET = os.getenv("CAPTCHA_SECRET")

async def validate_captcha(token: str, remote_ip: Optional[str] = None) -> bool:
    """
    Validate CAPTCHA token with the provider's API
    Supports both Google reCAPTCHA and hCaptcha
    """
    if not token or not CAPTCHA_SECRET:
        return False
    
    if CAPTCHA_PROVIDER.lower() == "hcaptcha":
        return await _validate_hcaptcha(token, remote_ip)
    else:  # Default to reCAPTCHA
        return await _validate_recaptcha(token, remote_ip)

async def _validate_recaptcha(token: str, remote_ip: Optional[str] = None) -> bool:
    """
    Validate Google reCAPTCHA token
    """
    url = "https://www.google.com/recaptcha/api/siteverify"
    
    data = {
        "secret": CAPTCHA_SECRET,
        "response": token,
    }
    
    if remote_ip:
        data["remoteip"] = remote_ip
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, data=data, timeout=5.0)
            result = response.json()
            
            return result.get("success", False)
    except Exception as e:
        print(f"Error validating reCAPTCHA: {str(e)}")
        return False

async def _validate_hcaptcha(token: str, remote_ip: Optional[str] = None) -> bool:
    """
    Validate hCaptcha token
    """
    url = "https://api.hcaptcha.com/siteverify"
    
    data = {
        "secret": CAPTCHA_SECRET,
        "response": token,
    }
    
    if remote_ip:
        data["remoteip"] = remote_ip
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, data=data, timeout=5.0)
            result = response.json()
            
            return result.get("success", False)
    except Exception as e:
        print(f"Error validating hCaptcha: {str(e)}")
        return False