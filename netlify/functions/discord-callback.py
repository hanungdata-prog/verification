#!/usr/bin/env python3
"""
Netlify serverless function for Discord OAuth callback
"""
import sys
import os
import json
from pathlib import Path

# Add the app directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Set environment variables for serverless
os.environ.setdefault('PYTHONPATH', str(current_dir))
os.environ.setdefault('PYTHONUNBUFFERED', '1')

# Set BASE_URL for Netlify deployment
if not os.getenv('BASE_URL'):
    netlify_url = os.getenv('URL') or os.getenv('NETLIFY_URL') or 'https://verification-gateway-joblow.netlify.app'
    os.environ.setdefault('BASE_URL', netlify_url)

# Set Discord redirect URI if not already set
if not os.getenv('DISCORD_REDIRECT_URI'):
    base_url = os.getenv('BASE_URL', 'https://verification-gateway-joblow.netlify.app')
    discord_redirect_uri = f"{base_url}/discord/callback"
    os.environ.setdefault('DISCORD_REDIRECT_URI', discord_redirect_uri)

# Import the FastAPI app
try:
    from app.main import app
    from mangum import Mangum

    # Create a handler that specifically handles the Discord callback path
    def handler(event, context):
        # Override the path to /discord/callback
        event['path'] = '/discord/callback'

        # Use Mangum to handle FastAPI app
        mangum_handler = Mangum(app)
        return mangum_handler(event, context)

    # Export for Netlify
    lambda_handler = handler

except ImportError as e:
    # Fallback response
    def handler(event, context):
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                "error": "Serverless function not properly configured",
                "message": str(e)
            })
        }

    lambda_handler = handler
