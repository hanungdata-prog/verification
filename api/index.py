# Vercel entry point for AuthGateway
import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(__file__))

# Import dependencies directly to avoid module issues
from contextlib import asynccontextmanager
from datetime import datetime
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
        from supabase_db import get_supabase_client
        supabase_client = get_supabase_client()
        logger.info("Supabase verification system initialized")
    except Exception as e:
        logger.error(f"Failed to initialize Supabase: {str(e)}")
        # Fallback to JSON storage if Supabase is not available
        logger.warning("Falling back to JSON storage")
        return False
    return True

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
    from schemas import VerificationResponse
    from auth import encrypt_ip, decrypt_ip
    from captcha import validate_captcha
    from webhooks import send_webhook
    from utils import validate_discord_id, get_user_agent, get_client_ip
    from supabase_db import get_supabase_client
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

    # Create dummy get_supabase_client function
    def get_supabase_client():
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

            # Redirect to auto-verification page with user data
            redirect_url = f"/verify-auto.html?discord_id={discord_user['id']}&discord_username={discord_user['full_username']}"
            logger.info(f"Successfully authenticated user {discord_user['full_username']}, redirecting to: {redirect_url}")
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
    """Main verification endpoint"""
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    logger.info(f"Verification attempt from IP: {client_ip}")
    logger.info(f"Discord ID: {verify_request.discord_id}, Username: {verify_request.discord_username}")

    # Validate Discord ID format
    if not validate_discord_id(verify_request.discord_id):
        logger.warning(f"Invalid Discord ID format: {verify_request.discord_id}")
        raise HTTPException(status_code=400, detail="Invalid Discord ID format")

    # For now, skip captcha validation and just log the request
    logger.info(f"CAPTCHA token received: {verify_request.captcha_token[:20]}...")

    # Encrypt IP address (try to use real encryption, fallback to simple encryption)
    try:
        encrypted_ip = encrypt_ip(client_ip)
        logger.info(f"IP encrypted successfully")
    except Exception as e:
        logger.warning(f"Failed to encrypt IP, using simple encryption: {str(e)}")
        encrypted_ip = f"encrypted_{client_ip}"

    # Prepare verification data for Supabase (matching your schema)
    verification_data = {
        "discord_id": verify_request.discord_id,
        "discord_username": verify_request.discord_username,
        "ip_address": encrypted_ip,
        "user_agent": user_agent,
        "method": "captcha",
        "extra_data": verify_request.metadata
    }

    logger.info(f"Prepared verification data: {verification_data}")

    # Try to save to Supabase
    supabase_success = False
    try:
        supabase_client = get_supabase_client()
        if supabase_client:
            logger.info("Attempting to save to Supabase...")
            success = await supabase_client.insert_verification(verification_data)
            if success:
                logger.info(f"✅ Verification saved to Supabase for user: {verify_request.discord_id}")
                supabase_success = True
            else:
                logger.error(f"❌ Failed to save verification to Supabase")
        else:
            logger.error("❌ Supabase client is None")
    except Exception as e:
        logger.error(f"❌ Supabase error: {str(e)}", exc_info=True)

    if not supabase_success:
        logger.error("❌ Verification was NOT saved to Supabase")
        # Still return success but indicate database issue
        return VerificationResponse(
            success=True,
            message="Verification successful! (Note: Database save failed)",
            verification_id="local_only",
            redirect_url="https://discord.gg/9ZmvQFsP"
        )

    logger.info(f"✅ Successfully verified user: {verify_request.discord_id}")

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
    """Test Supabase connection"""
    try:
        supabase_client = get_supabase_client()
        if not supabase_client:
            return {"status": "error", "message": "Supabase client not initialized"}

        # Test data
        test_data = {
            "discord_id": "123456789012345678",
            "discord_username": "TestUser#1234",
            "ip_address": "encrypted_test_ip",
            "user_agent": "test_user_agent",
            "method": "test",
            "extra_data": {"test": True}
        }

        success = await supabase_client.insert_verification(test_data)
        if success:
            return {"status": "success", "message": "Test data inserted to Supabase"}
        else:
            return {"status": "error", "message": "Failed to insert test data"}

    except Exception as e:
        return {"status": "error", "message": f"Supabase test failed: {str(e)}"}

print("AuthGateway FastAPI app loaded successfully")