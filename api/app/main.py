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
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
import httpx
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
import uvicorn
from dotenv import load_dotenv

from .schemas import VerificationResponse
from .auth import encrypt_ip, decrypt_ip
from .captcha import validate_captcha
from .webhooks import send_webhook
from .utils import validate_discord_id, get_user_agent, get_client_ip
from .supabase_db import get_supabase_client

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
    logger.info("Verification system initialized with JSON storage")
    yield
    # Shutdown - nothing special needed for JSON storage

# Create FastAPI app
app = FastAPI(
    title="Exotic Roleplay Gateway",
    description="A lightweight user-gating and verification service for Discord roleplay servers",
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

# Static files are served by Vercel routing, no need to mount here

class VerifyRequest(BaseModel):
    discord_id: str
    discord_username: str
    captcha_token: str
    metadata: dict = {}

@app.post("/verify", response_model=VerificationResponse)
@limiter.limit("5 per 10 minutes")  # Rate limit: 5 attempts per 10 minutes per IP
async def verify_user(request: Request, verify_request: VerifyRequest):
    """
    Main verification endpoint that validates CAPTCHA, encrypts IP, stores data,
    and sends webhook to Discord.
    """
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    logger.info(f"Verification attempt from IP: {client_ip}")
    
    # Validate Discord ID format
    if not validate_discord_id(verify_request.discord_id):
        logger.warning(f"Invalid Discord ID format: {verify_request.discord_id}")
        raise HTTPException(status_code=400, detail="Invalid Discord ID format")
    
    # Validate CAPTCHA
    try:
        captcha_valid = await validate_captcha(verify_request.captcha_token, client_ip)
        if not captcha_valid:
            logger.warning(f"CAPTCHA validation failed for IP: {client_ip}")
            raise HTTPException(status_code=400, detail="CAPTCHA validation failed")
    except Exception as e:
        logger.error(f"Error during CAPTCHA validation: {str(e)}")
        raise HTTPException(status_code=500, detail="CAPTCHA validation service error")
    
    # Encrypt IP address
    try:
        encrypted_ip = encrypt_ip(client_ip)
    except Exception as e:
        logger.error(f"Error encrypting IP address: {str(e)}")
        raise HTTPException(status_code=500, detail="IP encryption error")
    
    # Prepare verification data
    verification_data = {
        "id": secrets.token_urlsafe(16),  # Generate a unique ID
        "discord_id": verify_request.discord_id,
        "discord_username": verify_request.discord_username,
        "ip_address": encrypted_ip,  # This will be encrypted
        "user_agent": user_agent,
        "method": "captcha",
        "extra_data": verify_request.metadata,
        "verified_at": datetime.utcnow().isoformat(),
        "created_at": datetime.utcnow().isoformat()
    }
    
    # Save to Supabase database
    try:
        supabase_client = get_supabase_client()
        success = await supabase_client.insert_verification(verification_data)
        if not success:
            logger.error(f"Failed to save verification to Supabase for user: {verify_request.discord_id}")
            raise HTTPException(status_code=500, detail="Error saving verification to database")
        logger.info(f"Verification saved to Supabase for user: {verify_request.discord_id}")
    except Exception as e:
        logger.error(f"Error saving verification to Supabase: {str(e)}")
        raise HTTPException(status_code=500, detail="Error saving verification to database")
    
    # Send webhook to Discord bot
    try:
        await send_webhook(
            success=True,
            discord_id=verify_request.discord_id,
            discord_username=verify_request.discord_username,
            ip_address=encrypted_ip,  # This is encrypted
            verification_id=verification_data["id"]
        )
    except Exception as e:
        logger.error(f"Webhook delivery failed: {str(e)}")
        # Don't fail the verification if webhook fails, but log it
    
    logger.info(f"Successfully verified user: {verify_request.discord_id}")
    
    # Return success with redirect instruction
    return VerificationResponse(
        success=True,
        message="Verification successful!",
        verification_id=verification_data["id"],
        redirect_url="https://discord.gg/9ZmvQFsP"  # Redirect to Discord after verification
    )

@app.get("/", response_class=HTMLResponse)
async def get_verify_page():
    """
    Serve the verification page (Discord OAuth only)
    """
    with open("static/verify.html", "r") as file:
        content = file.read()
    return HTMLResponse(content=content)

@app.get("/privacy")
async def privacy_policy():
    """
    Privacy policy page explaining data collection and usage
    """
    privacy_content = """
    <html>
        <head>
            <title>Privacy Policy</title>
        </head>
        <body>
            <h1>Privacy Policy</h1>
            <p>This service collects the following information for verification purposes:</p>
            <ul>
                <li>Discord ID and username</li>
                <li>IP address (encrypted and stored securely)</li>
                <li>User agent information</li>
                <li>Verification timestamp</li>
            </ul>
            <p>Your IP address is encrypted using AES-128 encryption and stored securely. 
            We do not share or sell your personal data to third parties.</p>
        </body>
    </html>
    """
    return HTMLResponse(content=privacy_content)

@app.get("/discord/login")
async def discord_login():
    """
    Redirect user to Discord OAuth2 login page
    """
    client_id = os.getenv("DISCORD_CLIENT_ID")
    redirect_uri = os.getenv("DISCORD_REDIRECT_URI", f"{os.getenv('BASE_URL', 'http://localhost:8000')}/discord/callback")
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
async def discord_callback(code: str = Query(...), error: str = None, error_description: str = None):
    """
    Handle Discord OAuth2 callback and get user info
    """
    if error:
        logger.error(f"Discord OAuth2 error: {error} - {error_description}")
        raise HTTPException(status_code=400, detail=f"Discord OAuth2 error: {error_description or error}")
    
    client_id = os.getenv("DISCORD_CLIENT_ID")
    client_secret = os.getenv("DISCORD_CLIENT_SECRET")
    redirect_uri = os.getenv("DISCORD_REDIRECT_URI", f"{os.getenv('BASE_URL', 'http://localhost:8000')}/discord/callback")
    
    if not client_id or not client_secret:
        raise HTTPException(status_code=500, detail="Discord credentials not configured")
    
    # Exchange code for access token
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }
    
    try:
        async with httpx.AsyncClient() as client:
            token_response = await client.post("https://discord.com/api/oauth2/token", data=token_data)
            
            if token_response.status_code != 200:
                logger.error(f"Failed to get access token from Discord: {token_response.text}")
                raise HTTPException(status_code=400, detail="Failed to get access token from Discord")
            
            token_json = token_response.json()
            access_token = token_json.get("access_token")
            
            if not access_token:
                raise HTTPException(status_code=400, detail="No access token received from Discord")
            
            # Get user info
            user_response = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if user_response.status_code != 200:
                logger.error(f"Failed to get user info from Discord: {user_response.text}")
                raise HTTPException(status_code=400, detail="Failed to get user info from Discord")
            
            user_data = user_response.json()
            
            # Prepare user data
            discord_user = {
                "id": user_data["id"],
                "username": user_data["username"],
                "discriminator": user_data["discriminator"],
                "avatar": user_data.get("avatar"),
                "full_username": f"{user_data['username']}#{user_data['discriminator']}"
            }
            
            # Redirect to auto-verification page with user data
            redirect_url = f"/verify-auto?discord_id={discord_user['id']}&discord_username={discord_user['full_username']}"
            return RedirectResponse(url=redirect_url)
            
    except httpx.RequestError as e:
        logger.error(f"HTTP request error during Discord OAuth2: {str(e)}")
        raise HTTPException(status_code=500, detail="Network error during Discord authentication")
    except Exception as e:
        logger.error(f"Unexpected error during Discord OAuth2: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during Discord authentication")

@app.get("/verify-auto")
async def auto_verify_page(request: Request, discord_id: str, discord_username: str):
    """
    Auto-verification page that pre-fills Discord user info
    """
    with open("static/verify-auto.html", "r") as file:
        content = file.read()
        # Replace placeholders with actual values
        content = content.replace("{{discord_id}}", discord_id)
        content = content.replace("{{discord_username}}", discord_username)
    return HTMLResponse(content=content)

@app.get("/admin/verifications")
async def get_verifications(username: str, password: str):
    """
    Admin endpoint to list successful verifications
    Basic authentication required
    """
    # Basic authentication check
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if username != admin_username or password != admin_password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Fetch verifications from Supabase
    try:
        supabase_client = get_supabase_client()
        url = f"{supabase_client.supabase_url}/rest/v1/verifications"
        params = {
            "select": "*",
            "order": "created_at.desc",
            "limit": 100  # Limit to last 100 verifications
        }

        headers = supabase_client.headers.copy()
        headers.pop("Prefer", None)  # Remove Prefer header for GET requests

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params)

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to fetch verifications from Supabase: {response.status_code} - {response.text}")
                raise HTTPException(status_code=500, detail="Error reading verification data")

    except Exception as e:
        logger.error(f"Error reading verifications from Supabase: {str(e)}")
        raise HTTPException(status_code=500, detail="Error reading verification data")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)