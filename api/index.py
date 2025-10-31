#!/usr/bin/env python3
"""
Serverless entry point for Vercel/Netlify deployment
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

# Import the FastAPI app
try:
    from app.main import app
    print("✅ FastAPI app imported successfully")
except ImportError as e:
    print(f"❌ Failed to import FastAPI app: {e}")

    # Create fallback app
    from fastapi import FastAPI
    app = FastAPI(title="AuthGateway")

    @app.get("/")
    async def root():
        return {"message": "AuthGateway is running", "status": "fallback mode"}

# Vercel entry point
def handler(request):
    """
    Vercel serverless function handler
    """
    return app

# Alternative handler for other platforms
def lambda_handler(event, context):
    """
    AWS Lambda / Netlify Functions handler
    """
    try:
        # Parse the event for AWS Lambda format
        from mangum import Mangum
        handler = Mangum(app)
        return handler(event, context)
    except ImportError:
        # Fallback without mangum
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                "message": "AuthGateway is running",
                "status": "serverless mode"
            })
        }

# Export for different platforms
if __name__ == "__main__":
    # For local testing
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
else:
    # For serverless deployment
    export_app = app