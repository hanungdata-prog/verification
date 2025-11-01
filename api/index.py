#!/usr/bin/env python3
"""
Vercel FastAPI application for AuthGateway
"""
import sys
import os
from pathlib import Path

# Add the app directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Set environment variables for serverless
os.environ.setdefault('PYTHONPATH', str(current_dir))
os.environ.setdefault('PYTHONUNBUFFERED', '1')

# Set BASE_URL for deployment
if not os.getenv('BASE_URL'):
    deployment_url = os.getenv('URL') or os.getenv('VERCEL_URL') or os.getenv('NETLIFY_URL') or 'https://apinode1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2-7gx2dt5eq.vercel.app'
    if deployment_url and not deployment_url.startswith('http'):
        deployment_url = f"https://{deployment_url}"
    os.environ.setdefault('BASE_URL', deployment_url)
    print(f"🌐 Setting BASE_URL to: {deployment_url}")

# Set Discord redirect URI if not already set
if not os.getenv('DISCORD_REDIRECT_URI'):
    base_url = os.getenv('BASE_URL', 'https://apinode1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2-7gx2dt5eq.vercel.app')
    discord_redirect_uri = f"{base_url}/discord/callback"
    os.environ.setdefault('DISCORD_REDIRECT_URI', discord_redirect_uri)
    print(f"🔗 Setting DISCORD_REDIRECT_URI to: {discord_redirect_uri}")

# Import FastAPI and create app instance
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse

# Create FastAPI app instance - THIS IS WHAT VERCEL EXPECTS
app = FastAPI(
    title="AuthGateway API",
    description="Discord verification service",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Basic API routes
@app.get("/")
async def root():
    return {
        "message": "AuthGateway is running",
        "status": "serverless mode",
        "base_url": os.getenv('BASE_URL', 'Unknown'),
        "timestamp": "2025-11-02",
        "service": "Discord Verification Gateway"
    }

@app.get("/api/health")
async def health():
    return {"status": "healthy", "service": "AuthGateway"}

@app.get("/api/info")
async def info():
    return {
        "title": "AuthGateway",
        "description": "Discord verification service",
        "version": "1.0.0",
        "endpoints": [
            "/",
            "/api/health",
            "/api/info",
            "/verify",
            "/verify.html",
            "/admin"
        ]
    }

# Verification routes
@app.get("/verify")
async def verify_redirect():
    return {
        "message": "Verification endpoint",
        "redirect_to": "/verify.html",
        "base_url": os.getenv('BASE_URL')
    }

@app.get("/verify.html", response_class=HTMLResponse)
async def verify_page():
    """Serve verify.html page"""
    try:
        # Try to read from public directory
        verify_path = Path(__file__).parent.parent / "public" / "verify.html"
        if verify_path.exists():
            with open(verify_path, 'r', encoding='utf-8') as f:
                return f.read()
        else:
            # Fallback HTML
            return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Discord Verification</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                    .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    h1 { color: #7289DA; }
                    .btn { background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🔐 Discord Verification</h1>
                    <p>Welcome to the Discord verification service.</p>
                    <p>Click the button below to verify your account:</p>
                    <br>
                    <a href="#" class="btn">Verify with Discord</a>
                    <br><br>
                    <p><small>Service is running in serverless mode</small></p>
                </div>
            </body>
            </html>
            """
    except Exception as e:
        return f"""
        <!DOCTYPE html>
        <html><body>
            <h1>Error</h1>
            <p>Could not load verification page: {str(e)}</p>
        </body></html>
        """

@app.get("/admin")
async def admin_info():
    return {
        "message": "Admin endpoint",
        "status": "requires authentication",
        "base_url": os.getenv('BASE_URL')
    }

# Handle favicon requests
@app.get("/favicon.ico")
@app.get("/favicon.png")
async def favicon():
    return JSONResponse({"status": "no favicon"}, status_code=204)

# Discord OAuth placeholder routes
@app.get("/discord/auth")
async def discord_auth():
    return {"message": "Discord OAuth endpoint", "status": "not configured"}

@app.get("/discord/callback")
async def discord_callback():
    return {"message": "Discord OAuth callback", "status": "not configured"}

# Local testing
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)