# Vercel entry point for AuthGateway
import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(__file__))

# Import dependencies directly to avoid module issues
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import AsyncGenerator, Optional
import asyncio
import logging
import os
import sys
import secrets
import json
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
import httpx
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
import uvicorn
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

def create_db_and_tables():
    # Initialize Supabase connection
    try:
        # Try multiple import paths for serverless compatibility
        try:
            from app.supabase_db import get_supabase_client
        except ImportError:
            try:
                from .supabase_db import get_supabase_client
            except ImportError:
                import sys
                import os
                sys.path.append(os.path.dirname(__file__))
                from app.supabase_db import get_supabase_client

        supabase_client = get_supabase_client()
        if supabase_client:
            logger.info("Supabase verification system initialized")
            return True
        else:
            logger.error("Supabase client initialization returned None")
            return False
    except Exception as e:
        logger.error(f"Failed to initialize Supabase: {str(e)}")
        # Fallback to JSON storage if Supabase is not available
        logger.warning("Falling back to JSON storage")
        return False

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Startup
    create_db_and_tables()
    logger.info("Verification system initialized")
    yield
    # Shutdown

# Create FastAPI app
app = FastAPI(
    title="AuthGateway",
    description="Discord OAuth verification service",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Import internal modules
try:
    from app.schemas import VerificationResponse
    from app.auth import encrypt_ip, decrypt_ip
    from app.captcha import validate_captcha
    from app.webhooks import send_webhook
    from app.utils import validate_discord_id, get_user_agent, get_client_ip
    from app.supabase_db import get_supabase_client
    logger.info("Successfully imported all modules")
except ImportError as e:
    logger.error(f"Failed to import modules: {e}")
    # Define minimal classes if import fails
    class VerificationResponse(BaseModel):
        success: bool
        message: str
        verification_id: Optional[str] = None
        redirect_url: Optional[str] = None

    def validate_discord_id(discord_id: str) -> bool:
        return discord_id and discord_id.isdigit() and len(discord_id) >= 17

    def get_client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def get_user_agent(request: Request) -> Optional[str]:
        return request.headers.get("user-agent", "")

    # Create robust fallback get_supabase_client function
    def get_supabase_client():
        """Fallback Supabase client when import fails"""
        try:
            # Try to create a working Supabase client directly
            import os
            import httpx
            from typing import Optional, Dict, Any

            supabase_url = os.getenv("SUPABASE_URL")
            supabase_key = os.getenv("SUPABASE_KEY")

            if not supabase_url or not supabase_key:
                logger.error("Missing SUPABASE_URL or SUPABASE_KEY environment variables")
                return None

            class FallbackSupabaseClient:
                def __init__(self, url, key):
                    self.supabase_url = url
                    self.supabase_key = key
                    self.headers = {
                        "apikey": key,
                        "Authorization": f"Bearer {key}",
                        "Content-Type": "application/json",
                        "Prefer": "return=minimal"
                    }

                async def check_existing_verification(self, discord_id: str) -> Optional[Dict[str, Any]]:
                    try:
                        url = f"{self.supabase_url}/rest/v1/verifications"
                        params = {
                            "discord_id": f"eq.{discord_id}",
                            "limit": 1,
                            "order": "created_at.desc"
                        }
                        async with httpx.AsyncClient(timeout=30.0) as client:
                            response = await client.get(url, headers=self.headers, params=params)
                            if response.status_code == 200:
                                data = response.json()
                                return data[0] if data else None
                            return None
                    except Exception as e:
                        logger.error(f"Error checking existing verification: {e}")
                        return None

                async def insert_verification(self, verification_data: Dict[str, Any]) -> bool:
                    try:
                        url = f"{self.supabase_url}/rest/v1/verifications"
                        async with httpx.AsyncClient(timeout=30.0) as client:
                            response = await client.post(url, headers=self.headers, json=verification_data)
                            return response.status_code in [200, 201, 204]
                    except Exception as e:
                        logger.error(f"Error inserting verification: {e}")
                        return False

                async def check_ip_verification_count(self, ip_address: str, time_window_hours: int = 24) -> int:
                    try:
                        from datetime import datetime, timedelta
                        time_threshold = (datetime.utcnow() - timedelta(hours=time_window_hours)).isoformat()

                        url = f"{self.supabase_url}/rest/v1/verifications"
                        params = {
                            "ip_address": f"eq.{ip_address}",
                            "created_at": f"gte.{time_threshold}",
                            "select": "count"
                        }
                        async with httpx.AsyncClient(timeout=30.0) as client:
                            response = await client.get(url, headers=self.headers, params=params)
                            if response.status_code == 200:
                                content_range = response.headers.get("content-range", "")
                                if content_range:
                                    return int(content_range.split("/")[-1])
                                else:
                                    data = response.json()
                                    return len(data) if isinstance(data, list) else 0
                            return 0
                    except:
                        return 0

            logger.info("✅ Created fallback Supabase client")
            return FallbackSupabaseClient(supabase_url, supabase_key)

        except Exception as e:
            logger.error(f"Failed to create fallback Supabase client: {e}")
            return None

class VerifyRequest(BaseModel):
    discord_id: str
    discord_username: str
    captcha_token: str
    metadata: dict = {}

@app.get("/discord/login")
async def discord_login():
    """Redirect user to Discord OAuth2 login page"""
    client_id = os.getenv("DISCORD_CLIENT_ID")
    redirect_uri = os.getenv("DISCORD_REDIRECT_URI")
    scopes = "identify"

    if not client_id:
        raise HTTPException(status_code=500, detail="Discord client ID not configured")

    discord_auth_url = (
        f"https://discord.com/api/oauth2/authorize?"
        f"client_id={client_id}&"
        f"redirect_uri={redirect_uri}&"
        f"response_type=code&"
        f"scope={scopes}"
    )

    return RedirectResponse(url=discord_auth_url)

@app.get("/discord/callback")
async def discord_callback(request: Request, code: str = Query(None), error: str = None, error_description: str = None):
    """Handle Discord OAuth2 callback and redirect to verification page"""
    logger.info(f"Discord callback received - Code: {code[:20] if code else 'None'}..., Error: {error}")

    if error:
        logger.error(f"Discord OAuth2 error: {error} - {error_description}")
        return HTMLResponse(content=f"""
        <html>
        <body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1 style="color: red;">❌ Authorization Failed</h1>
            <p>Discord authorization was cancelled or failed: {error_description or error}</p>
            <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
        </body>
        </html>
        """)

    if not code:
        logger.error("No authorization code received from Discord")
        return HTMLResponse(content=f"""
        <html>
        <body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1 style="color: red;">❌ Authorization Failed</h1>
            <p>No authorization code received from Discord.</p>
            <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
        </body>
        </html>
        """)

    # Get environment variables
    client_id = os.getenv("DISCORD_CLIENT_ID")
    client_secret = os.getenv("DISCORD_CLIENT_SECRET")
    redirect_uri = os.getenv("DISCORD_REDIRECT_URI")

    logger.info(f"Discord credentials - Client ID: {client_id}, Redirect URI: {redirect_uri}")

    if not client_id:
        logger.error("DISCORD_CLIENT_ID not configured")
        return HTMLResponse(content="""
        <html>
        <body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1 style="color: red;">❌ Configuration Error</h1>
            <p>Discord client ID not configured.</p>
        </body>
        </html>
        """)

    if not client_secret:
        logger.error("DISCORD_CLIENT_SECRET not configured")
        return HTMLResponse(content="""
        <html>
        <body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1 style="color: red;">❌ Configuration Error</h1>
            <p>Discord client secret not configured.</p>
        </body>
        </html>
        """)

    if not redirect_uri:
        logger.error("DISCORD_REDIRECT_URI not configured")
        return HTMLResponse(content="""
        <html>
        <body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1 style="color: red;">❌ Configuration Error</h1>
            <p>Discord redirect URI not configured.</p>
        </body>
        </html>
        """)

    # Exchange code for access token
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }

    try:
        logger.info("Exchanging authorization code for access token...")

        async with httpx.AsyncClient(timeout=30.0) as client:
            token_response = await client.post(
                "https://discord.com/api/oauth2/token",
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            logger.info(f"Token response status: {token_response.status_code}")
            logger.info(f"Token response: {token_response.text[:200]}...")

            if token_response.status_code != 200:
                error_msg = f"Failed to get access token from Discord: {token_response.text}"
                logger.error(error_msg)
                return HTMLResponse(content=f"""
                <html>
                <body style="font-family: Arial; text-align: center; margin: 50px;">
                    <h1 style="color: red;">❌ Token Exchange Failed</h1>
                    <p>Failed to get access token from Discord.</p>
                    <p><small>Status: {token_response.status_code}</small></p>
                    <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
                </body>
                </html>
                """)

            try:
                token_json = token_response.json()
            except Exception as e:
                logger.error(f"Failed to parse token response JSON: {e}")
                return HTMLResponse(content=f"""
                <html>
                <body style="font-family: Arial; text-align: center; margin: 50px;">
                    <h1 style="color: red;">❌ Token Response Error</h1>
                    <p>Invalid response from Discord token endpoint.</p>
                    <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
                </body>
                </html>
                """)

            access_token = token_json.get("access_token")

            if not access_token:
                logger.error(f"No access token in response: {token_json}")
                return HTMLResponse(content=f"""
                <html>
                <body style="font-family: Arial; text-align: center; margin: 50px;">
                    <h1 style="color: red;">❌ Token Missing</h1>
                    <p>No access token received from Discord.</p>
                    <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
                </body>
                </html>
                """)

            logger.info("Successfully obtained access token")

            # Get user info
            logger.info("Fetching user information from Discord...")
            user_response = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )

            logger.info(f"User response status: {user_response.status_code}")
            logger.info(f"User response: {user_response.text[:200]}...")

            if user_response.status_code != 200:
                error_msg = f"Failed to get user info from Discord: {user_response.text}"
                logger.error(error_msg)
                return HTMLResponse(content=f"""
                <html>
                <body style="font-family: Arial; text-align: center; margin: 50px;">
                    <h1 style="color: red;">❌ User Info Failed</h1>
                    <p>Failed to get user information from Discord.</p>
                    <p><small>Status: {user_response.status_code}</small></p>
                    <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
                </body>
                </html>
                """)

            try:
                user_data = user_response.json()
            except Exception as e:
                logger.error(f"Failed to parse user response JSON: {e}")
                return HTMLResponse(content=f"""
                <html>
                <body style="font-family: Arial; text-align: center; margin: 50px;">
                    <h1 style="color: red;">❌ User Response Error</h1>
                    <p>Invalid response from Discord user endpoint.</p>
                    <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
                </body>
                </html>
                """)

            logger.info(f"Successfully retrieved user data: {user_data}")

            # Prepare user data
            discord_user = {
                "id": user_data.get("id", ""),
                "username": user_data.get("username", ""),
                "discriminator": user_data.get("discriminator", ""),
                "avatar": user_data.get("avatar"),
                "full_username": f"{user_data.get('username', '')}#{user_data.get('discriminator', '')}"
            }

            # Validate required fields
            if not discord_user["id"] or not discord_user["username"]:
                logger.error(f"Invalid user data received: {discord_user}")
                return HTMLResponse(content=f"""
                <html>
                <body style="font-family: Arial; text-align: center; margin: 50px;">
                    <h1 style="color: red;">❌ Invalid User Data</h1>
                    <p>Received invalid user data from Discord.</p>
                    <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
                </body>
                </html>
                """)

            # Create secure token instead of passing Discord info in URL
            try:
                from app.token_utils import generate_short_discord_token
                discord_token = generate_short_discord_token(discord_user['id'], discord_user['full_username'])

                # Redirect to auto-verification page with token
                redirect_url = f"/verify-auto.html?token={discord_token}"
                logger.info(f"Successfully authenticated user {discord_user['full_username']}, redirecting with token to: {redirect_url}")
                return RedirectResponse(url=redirect_url)
            except ImportError as e:
                logger.warning(f"⚠️ Token utils not available, falling back to direct parameters: {e}")
                # Fallback to direct parameters if token utils not available
                redirect_url = f"/verify-auto.html?discord_id={discord_user['id']}&discord_username={discord_user['full_username']}"
                return RedirectResponse(url=redirect_url)
            except Exception as e:
                logger.error(f"❌ Failed to generate token: {e}")
                # Fallback to direct parameters on error
                redirect_url = f"/verify-auto.html?discord_id={discord_user['id']}&discord_username={discord_user['full_username']}"
                return RedirectResponse(url=redirect_url)

    except httpx.RequestError as e:
        logger.error(f"HTTP request error during Discord OAuth2: {str(e)}")
        return HTMLResponse(content=f"""
        <html>
        <body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1 style="color: red;">❌ Network Error</h1>
            <p>Network error during Discord authentication: {str(e)}</p>
            <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
        </body>
        </html>
        """)
    except Exception as e:
        logger.error(f"Unexpected error during Discord OAuth2: {str(e)}", exc_info=True)
        return HTMLResponse(content=f"""
        <html>
        <body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1 style="color: red;">❌ Unexpected Error</h1>
            <p>An unexpected error occurred: {str(e)}</p>
            <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
        </body>
        </html>
        """)

@app.post("/verify", response_model=VerificationResponse)
@limiter.limit("5 per 10 minutes")
async def verify_user(request: Request, verify_request: VerifyRequest):
    """Main verification endpoint with VPN detection"""
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    logger.info(f"🔄 Verification attempt from IP: {client_ip}")
    logger.info(f"👤 Discord ID: {verify_request.discord_id}, Username: {verify_request.discord_username}")

    # VPN/Proxy Detection using ProxyCheck.io
    try:
        logger.info(f"🔍 Starting VPN detection for IP: {client_ip}")

        # Import security module
        from app.security import VPN_Detector
        vpn_detector = VPN_Detector()

        # Check for VPN/Proxy
        is_vpn, vpn_info = await vpn_detector.detect_vpn(client_ip)

        if is_vpn:
            logger.warning(f"🚫 VPN/Proxy detected from {client_ip}: {vpn_info}")
            return JSONResponse(
                status_code=403,
                content={
                    "success": False,
                    "message": "VPN/Proxy usage is not allowed for verification",
                    "error_code": "VPN_DETECTED",
                    "vpn_info": vpn_info,
                    "redirect_url": f"/security-error.html?reason=vpn&message=VPN or proxy detected. Please disable VPN and try again."
                }
            )
        else:
            logger.info(f"✅ No VPN/Proxy detected for {client_ip}")

    except ImportError as e:
        logger.warning(f"⚠️ Security module not available: {e}")
        logger.info("🔄 Continuing without VPN detection...")
    except Exception as e:
        logger.error(f"❌ VPN detection failed: {e}")
        logger.info("🔄 Continuing verification despite VPN detection failure...")

    # Check for existing verification (prevent double verification)
    try:
        logger.info(f"🔍 Checking for existing verification for Discord ID: {verify_request.discord_id}")

        supabase_client = get_supabase_client()
        if supabase_client:
            existing_verification = await supabase_client.check_existing_verification(verify_request.discord_id)

            if existing_verification:
                logger.warning(f"🚫 User {verify_request.discord_username} already verified at {existing_verification.get('created_at', 'unknown time')}")

                # Calculate time since last verification
                from datetime import datetime
                if 'created_at' in existing_verification:
                    try:
                        created_time = datetime.fromisoformat(existing_verification['created_at'].replace('Z', '+00:00'))
                        time_diff = datetime.utcnow().replace(tzinfo=created_time.tzinfo) - created_time
                        hours_ago = time_diff.total_seconds() / 3600
                        time_info = f"{hours_ago:.1f} hours ago"
                    except:
                        time_info = "some time ago"
                else:
                    time_info = "previously"

                return JSONResponse(
                    status_code=409,  # Conflict status code
                    content={
                        "success": False,
                        "message": "You have already been verified",
                        "error_code": "ALREADY_VERIFIED",
                        "details": {
                            "discord_id": existing_verification.get("discord_id"),
                            "discord_username": existing_verification.get("discord_username"),
                            "verification_date": existing_verification.get("created_at"),
                            "time_ago": time_info,
                            "ip_address": existing_verification.get("ip_address"),
                            "method": existing_verification.get("method", "unknown")
                        },
                        "redirect_url": f"/security-error.html?reason=already_verified&message=You have already been verified {time_info}. Each Discord account can only be verified once."
                    }
                )
            else:
                logger.info(f"✅ No existing verification found for {verify_request.discord_id}")
        else:
            logger.warning("⚠️ Supabase client not available, skipping duplicate check")

    except Exception as e:
        logger.error(f"❌ Error checking existing verification: {e}")
        logger.info("🔄 Continuing verification despite duplicate check failure...")

    # Check IP verification rate limiting
    try:
        logger.info(f"🔍 Checking IP verification rate for: {client_ip}")

        if supabase_client:
            ip_count_24h = await supabase_client.check_ip_verification_count(client_ip, 24)
            ip_count_1h = await supabase_client.check_ip_verification_count(client_ip, 1)

            logger.info(f"📊 IP {client_ip} has {ip_count_1h} verifications in last hour, {ip_count_24h} in last 24 hours")

            # Block if too many verifications from same IP
            if ip_count_1h >= 3:  # Max 3 per hour
                logger.warning(f"🚫 IP {client_ip} exceeded hourly limit ({ip_count_1h} >= 3)")
                return JSONResponse(
                    status_code=429,  # Too Many Requests
                    content={
                        "success": False,
                        "message": "Too many verification attempts from your network",
                        "error_code": "IP_RATE_LIMIT_EXCEEDED",
                        "details": {
                            "ip_address": client_ip,
                            "count_1h": ip_count_1h,
                            "count_24h": ip_count_24h,
                            "limit_1h": 3,
                            "limit_24h": 10
                        },
                        "redirect_url": f"/security-error.html?reason=rate_limit&message=Too many verification attempts from your network. Please wait before trying again."
                    }
                )
            elif ip_count_24h >= 10:  # Max 10 per day
                logger.warning(f"🚫 IP {client_ip} exceeded daily limit ({ip_count_24h} >= 10)")
                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "message": "Daily verification limit reached for your network",
                        "error_code": "IP_DAILY_LIMIT_EXCEEDED",
                        "details": {
                            "ip_address": client_ip,
                            "count_24h": ip_count_24h,
                            "limit_24h": 10
                        },
                        "redirect_url": f"/security-error.html?reason=daily_limit&message=Daily verification limit reached for your network. Please try again tomorrow."
                    }
                )
            else:
                logger.info(f"✅ IP {client_ip} rate limits are acceptable")
        else:
            logger.warning("⚠️ Supabase client not available, skipping IP rate limiting")

    except Exception as e:
        logger.error(f"❌ Error checking IP rate limits: {e}")
        logger.info("🔄 Continuing verification despite rate limit check failure...")

    # Log environment variables (safely)
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    logger.info(f"🔧 Supabase URL configured: {'Yes' if supabase_url else 'NO'}")
    logger.info(f"🔑 Supabase Key configured: {'Yes' if supabase_key else 'NO'}")
    if supabase_url:
        logger.info(f"🌐 Supabase URL: {supabase_url[:30]}...")

    # Validate Discord ID format
    if not validate_discord_id(verify_request.discord_id):
        logger.warning(f"Invalid Discord ID format: {verify_request.discord_id}")
        raise HTTPException(status_code=400, detail="Invalid Discord ID format")

    # For now, skip captcha validation and just log the request
    logger.info(f"CAPTCHA token received: {verify_request.captcha_token[:20]}...")

    # Use plain IP address (no encryption as requested)
    ip_address = client_ip
    logger.info(f"🔍 Using plain IP address: {ip_address}")

    # Prepare verification data for Supabase (matching your schema)
    verification_data = {
        "verification_id": secrets.token_urlsafe(16),  # Add required verification_id field
        "discord_id": verify_request.discord_id,
        "discord_username": verify_request.discord_username,
        "ip_address": ip_address,  # Plain IP address (not encrypted)
        "user_agent": user_agent,
        "method": "captcha",
        "extra_data": verify_request.metadata
    }

    logger.info(f"📝 Prepared verification data: {verification_data}")

    # DIRECT Supabase insertion without using the client
    supabase_success = False
    try:
        logger.info("🚀 Attempting DIRECT Supabase insertion...")

        if not supabase_url or not supabase_key:
            logger.error("❌ CRITICAL: Missing Supabase environment variables")
            raise Exception("Missing Supabase configuration")

        # Direct HTTP POST to Supabase
        url = f"{supabase_url}/rest/v1/verifications"
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        }

        logger.info(f"🌐 Sending POST to: {url}")
        logger.info(f"🔑 Headers: {headers}")
        logger.info(f"📦 Data: {verification_data}")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                headers=headers,
                json=verification_data
            )

        logger.info(f"📋 Response status: {response.status_code}")
        logger.info(f"📋 Response body: {response.text}")

        if response.status_code in [200, 201]:
            logger.info(f"✅ SUCCESS: Direct Supabase insertion successful for Discord ID: {verify_request.discord_id}")
            supabase_success = True
        else:
            logger.error(f"❌ FAILED: Direct Supabase insertion failed")
            logger.error(f"❌ Status: {response.status_code}")
            logger.error(f"❌ Response: {response.text}")

            # Try to parse error
            try:
                error_data = response.json()
                logger.error(f"❌ Error details: {error_data}")
            except:
                logger.error(f"❌ Could not parse error response")

    except Exception as e:
        logger.error(f"❌ EXCEPTION during direct Supabase insertion: {str(e)}", exc_info=True)

    # Fallback: Try using client if direct method fails
    if not supabase_success:
        try:
            logger.info("🔄 Attempting fallback with Supabase client...")
            supabase_client = get_supabase_client()
            if supabase_client:
                logger.info("✅ Supabase client obtained, attempting to save...")
                success = await supabase_client.insert_verification(verification_data)
                if success:
                    logger.info(f"✅ SUCCESS: Verification saved to Supabase via client for Discord ID: {verify_request.discord_id}")
                    supabase_success = True
                else:
                    logger.error(f"❌ FAILED: Could not save verification via Supabase client")
            else:
                logger.error("❌ CRITICAL: Supabase client is None")
        except Exception as e:
            logger.error(f"❌ EXCEPTION: Supabase client error - {str(e)}", exc_info=True)

    if not supabase_success:
        logger.error("❌ FINAL: Verification was NOT saved to Supabase by any method")
        # Still return success but indicate database issue
        return VerificationResponse(
            success=True,
            message="Verification successful! (Note: Database save failed)",
            verification_id="local_only",
            redirect_url="https://discord.gg/6sBPEhN6YU"
        )

    logger.info(f"✅ FINAL: Successfully verified and saved user: {verify_request.discord_id}")

    # Return success
    return VerificationResponse(
        success=True,
        message="Verification successful! Data saved to database.",
        verification_id="saved_to_supabase",
        redirect_url="https://discord.gg/9ZmvQFsP"
    )

@app.get("/")
async def root():
    return {"message": "AuthGateway is running", "status": "serverless"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/test-supabase")
async def test_supabase():
    """Test Supabase connection and debugging"""
    try:
        logger.info("🧪 Starting Supabase connection test")

        # Check environment variables
        supabase_url = os.getenv("SUPABASE_URL")
        supabase_key = os.getenv("SUPABASE_KEY")

        result = {
            "env_vars": {
                "SUPABASE_URL": f"{supabase_url[:20]}..." if supabase_url else "NOT_SET",
                "SUPABASE_KEY": f"{'Yes' if supabase_key else 'NOT_SET'}"
            }
        }

        supabase_client = get_supabase_client()
        if not supabase_client:
            result["status"] = "error"
            result["message"] = "Supabase client not initialized"
            logger.error("❌ Supabase client is None")
            return result

        logger.info("✅ Supabase client initialized successfully")

        # Test data
        test_data = {
            "verification_id": "test_" + secrets.token_urlsafe(16),
            "discord_id": "123456789012345678",
            "discord_username": "TestUser#1234",
            "ip_address": "test_ip_address",  # Plain IP
            "user_agent": "test_user_agent",
            "method": "test",
            "extra_data": {"test": True, "timestamp": datetime.utcnow().isoformat()}
        }

        logger.info(f"🧪 Test data prepared: {test_data}")

        success = await supabase_client.insert_verification(test_data)

        result["insert_success"] = success
        result["test_data"] = test_data

        if success:
            result["status"] = "success"
            result["message"] = "✅ Test data inserted to Supabase successfully"
            logger.info("✅ Supabase test successful")
        else:
            result["status"] = "error"
            result["message"] = "❌ Failed to insert test data to Supabase"
            logger.error("❌ Supabase test failed")

        return result

    except Exception as e:
        logger.error(f"❌ Supabase test exception: {str(e)}", exc_info=True)
        return {
            "status": "error",
            "message": f"Supabase test failed: {str(e)}",
            "error_type": type(e).__name__
        }

@app.get("/direct-test")
async def direct_test():
    """Direct test of Supabase connection"""
    try:
        logger.info("🚀 Starting DIRECT Supabase test")

        supabase_url = os.getenv("SUPABASE_URL")
        supabase_key = os.getenv("SUPABASE_KEY")

        if not supabase_url or not supabase_key:
            return {
                "status": "error",
                "message": "Missing Supabase environment variables",
                "supabase_url_set": supabase_url is not None,
                "supabase_key_set": supabase_key is not None
            }

        # Test direct connection
        test_data = {
            "verification_id": "direct_" + secrets.token_urlsafe(16),
            "discord_id": "888888888888888888",
            "discord_username": "DirectTest#9999",
            "ip_address": "direct_test_ip",
            "user_agent": "direct_test_ua",
            "method": "direct_test",
            "extra_data": {"test": True, "method": "direct"}
        }

        url = f"{supabase_url}/rest/v1/verifications"
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        }

        logger.info(f"🌐 Direct test POST to: {url}")
        logger.info(f"📦 Direct test data: {test_data}")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                headers=headers,
                json=test_data
            )

        logger.info(f"📋 Direct test response status: {response.status_code}")
        logger.info(f"📋 Direct test response body: {response.text}")

        return {
            "status": "success" if response.status_code in [200, 201] else "error",
            "response_status": response.status_code,
            "response_body": response.text,
            "test_data": test_data,
            "url": url,
            "success": response.status_code in [200, 201]
        }

    except Exception as e:
        logger.error(f"❌ Direct test exception: {str(e)}", exc_info=True)
        return {
            "status": "error",
            "message": f"Direct test failed: {str(e)}",
            "error_type": type(e).__name__
        }

@app.get("/debug-supabase")
async def debug_supabase():
    """Debug Supabase connection in detail"""
    try:
        logger.info("🔍 Starting detailed Supabase debugging")

        # Check all environment variables
        supabase_url = os.getenv("SUPABASE_URL")
        supabase_key = os.getenv("SUPABASE_KEY")

        debug_info = {
            "environment": {
                "SUPABASE_URL": {
                    "set": supabase_url is not None,
                    "value": supabase_url[:50] + "..." if supabase_url and len(supabase_url) > 50 else supabase_url,
                    "length": len(supabase_url) if supabase_url else 0
                },
                "SUPABASE_KEY": {
                    "set": supabase_key is not None,
                    "length": len(supabase_key) if supabase_key else 0,
                    "starts_with": supabase_key[:20] + "..." if supabase_key and len(supabase_key) > 20 else supabase_key
                }
            }
        }

        if not supabase_url or not supabase_key:
            debug_info["status"] = "error"
            debug_info["message"] = "Missing environment variables"
            return debug_info

        # Try to initialize client
        try:
            supabase_client = get_supabase_client()
            debug_info["client_init"] = "success"
        except Exception as e:
            debug_info["client_init"] = "failed"
            debug_info["client_error"] = str(e)
            return debug_info

        # Test basic connection to Supabase REST API
        try:
            import httpx
            test_url = f"{supabase_url}/rest/v1/"
            headers = {
                "apikey": supabase_key,
                "Authorization": f"Bearer {supabase_key}"
            }

            async with httpx.AsyncClient() as client:
                response = await client.get(test_url, headers=headers, timeout=10.0)

            debug_info["basic_connection"] = {
                "status": response.status_code,
                "success": response.status_code == 200
            }
        except Exception as e:
            debug_info["basic_connection"] = {
                "error": str(e),
                "success": False
            }

        # Test table existence
        try:
            import httpx
            table_url = f"{supabase_url}/rest/v1/verifications?limit=1"
            headers = {
                "apikey": supabase_key,
                "Authorization": f"Bearer {supabase_key}"
            }

            async with httpx.AsyncClient() as client:
                response = await client.get(table_url, headers=headers, timeout=10.0)

            debug_info["table_check"] = {
                "status": response.status_code,
                "success": response.status_code == 200,
                "response_preview": response.text[:200] + "..." if len(response.text) > 200 else response.text
            }
        except Exception as e:
            debug_info["table_check"] = {
                "error": str(e),
                "success": False
            }

        # Test actual insert
        try:
            test_data = {
                "verification_id": "debug_" + secrets.token_urlsafe(16),
                "discord_id": "999999999999999999",
                "discord_username": "DebugUser#0001",
                "ip_address": "127.0.0.1",
                "user_agent": "debug_test",
                "method": "debug",
                "extra_data": {"debug": True, "timestamp": datetime.utcnow().isoformat()}
            }

            success = await supabase_client.insert_verification(test_data)
            debug_info["insert_test"] = {
                "success": success,
                "test_data": test_data
            }
        except Exception as e:
            debug_info["insert_test"] = {
                "error": str(e),
                "success": False
            }

        debug_info["status"] = "completed"
        return debug_info

    except Exception as e:
        logger.error(f"❌ Debug Supabase exception: {str(e)}", exc_info=True)
        return {
            "status": "error",
            "message": f"Debug failed: {str(e)}",
            "error_type": type(e).__name__
        }

@app.get("/check-db")
async def check_db():
    """Check database connection and table structure"""
    try:
        supabase_client = get_supabase_client()
        if not supabase_client:
            return {"status": "error", "message": "Supabase client not initialized"}

        # Test simple GET request to check table exists
        url = f"{supabase_client.supabase_url}/rest/v1/verifications?limit=1"

        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers={
                    "apikey": supabase_client.supabase_key,
                    "Authorization": f"Bearer {supabase_client.supabase_key}"
                }
            )

        return {
            "status": "success",
            "table_exists": response.status_code == 200,
            "response_status": response.status_code,
            "response_headers": dict(response.headers),
            "response_body": response.text[:200] + "..." if len(response.text) > 200 else response.text
        }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Database check failed: {str(e)}",
            "error_type": type(e).__name__
        }

@app.get("/api/csrf-nonce")
async def get_csrf_nonce(request: Request):
    """Generate CSRF nonce for security"""
    try:
        # Get session ID from cookie or generate new one
        session_id = request.cookies.get("session_id") or secrets.token_urlsafe(16)

        # Generate nonce
        nonce = secrets.token_urlsafe(32)

        # Store in Redis or memory (for now, just return it)
        # In production, you'd want to store this server-side

        return JSONResponse({
            "nonce": nonce,
            "session_id": session_id,
            "expires_in": 3600  # 1 hour
        })

    except Exception as e:
        logger.error(f"CSRF nonce generation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate security token")

@app.get("/security-error.html")
async def security_error_page(request: Request, reason: str = None, message: str = None):
    """Serve security error page"""
    try:
        logger.info(f"🔍 Serving security error page - reason: {reason}, message: {message}")

        # Try multiple possible file paths
        possible_paths = [
            "public/security-error.html",
            "../public/security-error.html",
            "security-error.html",
            "/var/task/public/security-error.html"
        ]

        html_content = None
        file_path_used = None

        for path in possible_paths:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    html_content = f.read()
                    file_path_used = path
                    logger.info(f"✅ Found security error file at: {path}")
                    break
            except FileNotFoundError:
                continue
            except Exception as e:
                logger.warning(f"⚠️ Error reading file {path}: {e}")
                continue

        if not html_content:
            logger.warning("⚠️ Security error HTML file not found, using inline fallback")
            # Create a simple inline HTML response
            html_content = generate_security_error_html(reason, message)
        else:
            # Replace placeholders if needed
            if reason:
                html_content = html_content.replace("{{reason}}", reason)
            if message:
                html_content = html_content.replace("{{message}}", message)

        return HTMLResponse(content=html_content)

    except Exception as e:
        logger.error(f"❌ Critical error serving security page: {e}", exc_info=True)
        # Last resort - return minimal HTML response
        return HTMLResponse(content=generate_security_error_html(reason, message))

def generate_security_error_html(reason: str = None, message: str = None) -> str:
    """Generate security error HTML inline"""
    # Map reasons to user-friendly messages
    reason_messages = {
        'domain': 'Invalid Domain Access',
        'vpn': 'VPN or Proxy Detected',
        'rate_limit': 'Rate Limit Exceeded',
        'daily_limit': 'Daily Limit Reached',
        'already_verified': 'Already Verified',
        'suspicious': 'Suspicious Activity Detected',
        'blocked': 'Access Blocked',
        'csrf': 'Security Token Invalid'
    }

    display_reason = reason_messages.get(reason, 'Security Error')
    display_message = message or 'Access has been blocked due to security restrictions.'

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Error - AuthGateway</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                color: #333;
            }}

            .error-container {{
                background: white;
                padding: 3rem;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                max-width: 500px;
                width: 90%;
                text-align: center;
            }}

            .error-icon {{
                font-size: 4rem;
                margin-bottom: 1rem;
                animation: pulse 2s infinite;
            }}

            @keyframes pulse {{
                0% {{ transform: scale(1); }}
                50% {{ transform: scale(1.1); }}
                100% {{ transform: scale(1); }}
            }}

            .error-title {{
                font-size: 2rem;
                font-weight: 700;
                color: #e74c3c;
                margin-bottom: 1rem;
            }}

            .error-message {{
                font-size: 1.1rem;
                color: #666;
                margin-bottom: 2rem;
                line-height: 1.6;
            }}

            .back-button {{
                display: inline-block;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 1rem 2rem;
                text-decoration: none;
                border-radius: 50px;
                font-weight: 600;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            }}

            .back-button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
            }}

            .timestamp {{
                margin-top: 2rem;
                font-size: 0.8rem;
                color: #999;
            }}
        </style>
    </head>
    <body>
        <div class="error-container">
            <div class="error-icon">🛡️</div>
            <h1 class="error-title">{display_reason}</h1>
            <div class="error-message">{display_message}</div>
            <a href="/verify.html" class="back-button">Return to Verification</a>
            <div class="timestamp">Error occurred at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
        </div>
    </body>
    </html>
    """

@app.get("/test-security-error")
async def test_security_error_page(request: Request):
    """Test endpoint for security error page"""
    test_reasons = ['domain', 'vpn', 'rate_limit', 'already_verified', 'suspicious']
    import random
    test_reason = random.choice(test_reasons)
    test_message = f"This is a test security error for: {test_reason}"

    return await security_error_page(
        request=request,
        reason=test_reason,
        message=test_message
    )

@app.get("/test-token")
async def test_token_generation():
    """Test endpoint for token generation"""
    try:
        from app.token_utils import generate_short_discord_token

        # Generate test token
        test_discord_id = "692037233644929075"
        test_discord_username = "TestUser#1234"

        token = generate_short_discord_token(test_discord_id, test_discord_username)

        return JSONResponse({
            "status": "success",
            "token": token,
            "discord_id": test_discord_id,
            "discord_username": test_discord_username,
            "test_url": f"/verify-auto.html?token={token}",
            "decode_url": f"/api/decode-token/{token}"
        })

    except ImportError as e:
        return JSONResponse({
            "status": "error",
            "message": f"Token utils not available: {e}"
        }, status_code=500)
    except Exception as e:
        logger.error(f"Test token generation failed: {e}")
        return JSONResponse({
            "status": "error",
            "message": f"Failed to generate test token: {e}"
        }, status_code=500)

@app.post("/debug-token")
async def debug_token_decode(request: Request):
    """Debug endpoint for token decoding with detailed information"""
    try:
        request_data = await request.json()
        token = request_data.get("token")

        if not token:
            return JSONResponse({
                "status": "error",
                "message": "Token is required"
            }, status_code=400)

        from app.token_utils import TokenManager
        token_manager = TokenManager()

        # Step-by-step debugging
        debug_info = {
            "token": token,
            "token_length": len(token),
            "steps": []
        }

        # Step 1: Clean token and add padding
        clean_token = token.strip()
        padding_needed = (4 - len(clean_token) % 4) % 4
        if padding_needed:
            clean_token += '=' * padding_needed

        debug_info["steps"].append({
            "step": "clean_and_pad",
            "original": token,
            "cleaned": clean_token,
            "padding_added": padding_needed
        })

        # Step 2: Base64 decode
        try:
            import base64
            token_bytes = base64.urlsafe_b64decode(clean_token.encode('utf-8'))
            debug_info["steps"].append({
                "step": "base64_decode",
                "success": True,
                "bytes_length": len(token_bytes)
            })
        except Exception as e:
            debug_info["steps"].append({
                "step": "base64_decode",
                "success": False,
                "error": str(e)
            })
            return JSONResponse({
                "status": "error",
                "message": "Base64 decode failed",
                "debug": debug_info
            })

        # Step 3: JSON decode
        try:
            token_json = token_bytes.decode('utf-8')
            import json
            token_data = json.loads(token_json)
            debug_info["steps"].append({
                "step": "json_decode",
                "success": True,
                "json_keys": list(token_data.keys())
            })
        except Exception as e:
            debug_info["steps"].append({
                "step": "json_decode",
                "success": False,
                "error": str(e)
            })
            return JSONResponse({
                "status": "error",
                "message": "JSON decode failed",
                "debug": debug_info
            })

        # Step 4: Extract payload and signature
        payload = token_data.get("data")
        signature = token_data.get("sig")

        if not payload or not signature:
            debug_info["steps"].append({
                "step": "extract_components",
                "success": False,
                "payload": bool(payload),
                "signature": bool(signature)
            })
            return JSONResponse({
                "status": "error",
                "message": "Invalid token format",
                "debug": debug_info
            })

        debug_info["steps"].append({
            "step": "extract_components",
            "success": True,
            "payload_keys": list(payload.keys()) if payload else None
        })

        # Step 5: Signature verification
        try:
            # Create expected signature
            payload_json = token_manager._serialize_payload(payload)
            expected_signature = token_manager._sign_payload(payload_json)

            debug_info["steps"].append({
                "step": "signature_verification",
                "payload_json": payload_json,
                "expected_signature": expected_signature[:20] + "...",
                "received_signature": signature[:20] + "...",
                "signatures_match": expected_signature == signature
            })

            if expected_signature != signature:
                return JSONResponse({
                    "status": "error",
                    "message": "Signature verification failed",
                    "debug": debug_info
                })

        except Exception as e:
            debug_info["steps"].append({
                "step": "signature_verification",
                "success": False,
                "error": str(e)
            })
            return JSONResponse({
                "status": "error",
                "message": "Signature verification error",
                "debug": debug_info
            })

        # Step 6: Expiry check
        try:
            from datetime import datetime
            expires_at = datetime.fromisoformat(payload.get("expires_at", ""))
            is_expired = datetime.utcnow() > expires_at

            debug_info["steps"].append({
                "step": "expiry_check",
                "expires_at": payload.get("expires_at"),
                "is_expired": is_expired,
                "current_utc": datetime.utcnow().isoformat()
            })

            if is_expired:
                return JSONResponse({
                    "status": "error",
                    "message": "Token expired",
                    "debug": debug_info
                })

        except Exception as e:
            debug_info["steps"].append({
                "step": "expiry_check",
                "success": False,
                "error": str(e)
            })

        # If all steps passed, token is valid
        return JSONResponse({
            "status": "success",
            "message": "Token is valid",
            "debug": debug_info,
            "decoded_data": {
                "discord_id": payload.get("discord_id"),
                "discord_username": payload.get("discord_username"),
                "expires_at": payload.get("expires_at")
            }
        })

    except Exception as e:
        logger.error(f"Debug token decode failed: {e}")
        return JSONResponse({
            "status": "error",
            "message": f"Debug failed: {str(e)}",
            "error_type": type(e).__name__
        })

@app.get("/check-vpn/{ip}")
async def check_vpn_status(ip: str):
    """Check if IP is using VPN/proxy using ProxyCheck.io"""
    try:
        # Use ProxyCheck.io API (free tier)
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(f"https://proxycheck.io/v2/{ip}")

            if response.status_code == 200:
                data = response.json()

                # Extract VPN/proxy information
                proxy_info = data.get("proxy", "no")
                is_vpn = proxy_info == "yes"

                # Get additional info if available
                country = data.get("country", "unknown")
                provider = data.get("provider", "unknown")

                return {
                    "ip": ip,
                    "is_vpn": is_vpn,
                    "is_proxy": is_vpn,  # ProxyCheck.io doesn't distinguish these
                    "country": country,
                    "provider": provider,
                    "api_used": "proxycheck.io",
                    "confidence": 0.9 if is_vpn else 0.1
                }
            else:
                logger.error(f"ProxyCheck.io API error: {response.status_code}")
                return {
                    "ip": ip,
                    "error": "Failed to check VPN status",
                    "api_status": response.status_code
                }

    except Exception as e:
        logger.error(f"VPN check failed: {e}")
        return {
            "ip": ip,
            "error": str(e),
            "is_vpn": False,
            "confidence": 0.0
        }

@app.post("/api/check-security")
async def check_security_status(request: Request):
    """Comprehensive security check including VPN detection"""
    try:
        client_ip = get_client_ip(request)

        # Get VPN status
        vpn_result = await check_vpn_status(client_ip)

        # Get additional security info
        security_info = {
            "ip": client_ip,
            "user_agent": get_user_agent(request),
            "timestamp": datetime.utcnow().isoformat(),
            "vpn_status": vpn_result,
            "security_headers": {
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "x-xss-protection": "1; mode=block"
            }
        }

        return JSONResponse(security_info)

    except Exception as e:
        logger.error(f"Security check failed: {e}")
        return JSONResponse({
            "error": str(e),
            "ip": client_ip if 'client_ip' in locals() else "unknown"
        }, status_code=500)

@app.get("/api/check-verification/{discord_id}")
async def check_user_verification(discord_id: str):
    """Check if a Discord user is already verified"""
    try:
        logger.info(f"🔍 Checking verification status for Discord ID: {discord_id}")

        # Validate Discord ID format
        if not validate_discord_id(discord_id):
            raise HTTPException(status_code=400, detail="Invalid Discord ID format")

        # Get Supabase client (fallback function handles import issues)
        supabase_client = get_supabase_client()
        if not supabase_client:
            return {
                "status": "error",
                "message": "Database not available",
                "is_verified": False
            }

        # Check for existing verification
        existing_verification = await supabase_client.check_existing_verification(discord_id)

        if existing_verification:
            # Calculate time since verification
            from datetime import datetime
            time_info = "unknown time ago"
            if 'created_at' in existing_verification:
                try:
                    created_time = datetime.fromisoformat(existing_verification['created_at'].replace('Z', '+00:00'))
                    time_diff = datetime.utcnow().replace(tzinfo=created_time.tzinfo) - created_time
                    hours_ago = time_diff.total_seconds() / 3600
                    if hours_ago < 1:
                        time_info = f"{int(hours_ago * 60)} minutes ago"
                    elif hours_ago < 24:
                        time_info = f"{hours_ago:.1f} hours ago"
                    else:
                        days_ago = hours_ago / 24
                        time_info = f"{days_ago:.1f} days ago"
                except:
                    time_info = "some time ago"

            return {
                "status": "success",
                "is_verified": True,
                "verification_data": {
                    "discord_id": existing_verification.get("discord_id"),
                    "discord_username": existing_verification.get("discord_username"),
                    "verification_date": existing_verification.get("created_at"),
                    "time_ago": time_info,
                    "ip_address": existing_verification.get("ip_address"),
                    "method": existing_verification.get("method", "unknown")
                },
                "message": f"User was verified {time_info}"
            }
        else:
            return {
                "status": "success",
                "is_verified": False,
                "message": "User has not been verified yet"
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking verification status: {e}")
        return {
            "status": "error",
            "message": f"Failed to check verification status: {str(e)}",
            "is_verified": False
        }

@app.post("/api/check-user-verification")
async def check_user_verification_post(request: Request):
    """Check verification status via POST (more secure)"""
    try:
        # Get request data
        request_data = await request.json()
        discord_id = request_data.get("discord_id")

        if not discord_id:
            raise HTTPException(status_code=400, detail="Discord ID is required")

        # Call the GET endpoint logic
        return await check_user_verification(discord_id)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in POST verification check: {e}")
        raise HTTPException(status_code=500, detail="Failed to check verification status")

@app.get("/api/decode-token/{token}")
async def decode_discord_token(token: str):
    """Decode Discord token to get user information"""
    try:
        from app.token_utils import decode_discord_token

        logger.info(f"🔍 Decoding token: {token[:20]}...")

        decoded_data = decode_discord_token(token)

        if not decoded_data:
            return {
                "status": "error",
                "message": "Invalid or expired token",
                "valid": False
            }

        # Return decoded Discord info
        return {
            "status": "success",
            "valid": True,
            "discord_id": decoded_data.get("discord_id"),
            "discord_username": decoded_data.get("discord_username"),
            "expires_at": decoded_data.get("expires_at"),
            "message": "Token decoded successfully"
        }

    except ImportError as e:
        logger.error(f"❌ Token utils not available: {e}")
        return {
            "status": "error",
            "message": "Token decoding service not available",
            "valid": False
        }
    except Exception as e:
        logger.error(f"❌ Error decoding token: {e}")
        return {
            "status": "error",
            "message": f"Failed to decode token: {str(e)}",
            "valid": False
        }

@app.post("/api/decode-token")
async def decode_discord_token_post(request: Request):
    """Decode Discord token via POST (more secure)"""
    try:
        request_data = await request.json()
        token = request_data.get("token")

        if not token:
            raise HTTPException(status_code=400, detail="Token is required")

        # Call GET endpoint logic
        return await decode_discord_token(token)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in POST token decode: {e}")
        raise HTTPException(status_code=500, detail="Failed to decode token")

@app.get("/api/verification-stats")
async def get_verification_stats():
    """Get general verification statistics (public, safe info)"""
    try:
        logger.info("📊 Fetching verification statistics")

        supabase_client = get_supabase_client()
        if not supabase_client:
            return {
                "status": "error",
                "message": "Database not available",
                "stats": {}
            }

        # Get total verification count
        url = f"{supabase_client.supabase_url}/rest/v1/verifications?select=count"
        headers = {
            "apikey": supabase_client.supabase_key,
            "Authorization": f"Bearer {supabase_client.supabase_key}",
            "Prefer": "count=exact"
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)

        if response.status_code == 200:
            content_range = response.headers.get("content-range", "")
            total_count = int(content_range.split("/")[-1]) if content_range else 0

            # Get recent verifications (last 24 hours)
            from datetime import datetime, timedelta
            yesterday = (datetime.utcnow() - timedelta(hours=24)).isoformat()

            recent_url = f"{supabase_client.supabase_url}/rest/v1/verifications?created_at=gte.{yesterday}&select=count"
            recent_response = await client.get(recent_url, headers=headers)

            recent_count = 0
            if recent_response.status_code == 200:
                recent_content_range = recent_response.headers.get("content-range", "")
                recent_count = int(recent_content_range.split("/")[-1]) if recent_content_range else 0

            return {
                "status": "success",
                "stats": {
                    "total_verifications": total_count,
                    "verifications_last_24h": recent_count,
                    "database_available": True
                }
            }
        else:
            logger.error(f"Failed to get stats: {response.status_code}")
            return {
                "status": "error",
                "message": "Failed to fetch statistics",
                "stats": {}
            }

    except Exception as e:
        logger.error(f"Error fetching verification stats: {e}")
        return {
            "status": "error",
            "message": f"Failed to fetch statistics: {str(e)}",
            "stats": {}
        }

print("AuthGateway FastAPI app loaded successfully")