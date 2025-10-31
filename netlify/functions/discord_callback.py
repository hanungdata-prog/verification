#!/usr/bin/env python3
"""
Netlify serverless function for Discord OAuth callback
"""
import sys
import os
import json
import httpx
from pathlib import Path

# Add the app directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Set environment variables for serverless
os.environ.setdefault('PYTHONPATH', str(current_dir))
os.environ.setdefault('PYTHONUNBUFFERED', '1')

async def handler(event, context):
    """
    Handle Discord OAuth callback
    """
    try:
        # Extract query parameters
        query_params = event.get('queryStringParameters', {}) or {}
        code = query_params.get('code')
        error = query_params.get('error')
        error_description = query_params.get('error_description')

        if error:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'error': error,
                    'error_description': error_description
                })
            }

        if not code:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'error': 'No authorization code provided'
                })
            }

        # Discord OAuth configuration
        client_id = os.getenv("DISCORD_CLIENT_ID")
        client_secret = os.getenv("DISCORD_CLIENT_SECRET")
        redirect_uri = os.getenv("DISCORD_REDIRECT_URI", f"{os.getenv('BASE_URL', 'https://verification-gateway-joblow.netlify.app')}/discord/callback")

        if not client_id or not client_secret:
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'error': 'Discord credentials not configured'
                })
            }

        # Exchange code for access token
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        }

        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post("https://discord.com/api/oauth2/token", data=token_data)

            if token_response.status_code != 200:
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({
                        'error': 'Failed to get access token from Discord'
                    })
                }

            token_json = token_response.json()
            access_token = token_json.get("access_token")

            if not access_token:
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({
                        'error': 'No access token received from Discord'
                    })
                }

            # Get user info
            user_response = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )

            if user_response.status_code != 200:
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({
                        'error': 'Failed to get user info from Discord'
                    })
                }

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

            return {
                'statusCode': 302,
                'headers': {
                    'Location': redirect_url,
                    'Access-Control-Allow-Origin': '*'
                }
            }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }

# AWS Lambda handler
def lambda_handler(event, context):
    import asyncio
    return asyncio.run(handler(event, context))