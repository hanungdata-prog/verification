"""
Discord Webhook Proxy Module
Forwards webhooks from AuthGateway to local Discord bot
"""

import os
import httpx
import logging
from fastapi import APIRouter, HTTPException, Request
from typing import Dict, Any, Optional
from pydantic import BaseModel
import json

logger = logging.getLogger(__name__)

# Create router for webhook proxy
router = APIRouter(prefix="/webhook-proxy", tags=["webhook-proxy"])

class WebhookForwardRequest(BaseModel):
    """Request model for webhook forwarding"""
    bot_endpoint: str  # Local Discord bot endpoint (e.g., http://localhost:3000/webhook/verification)
    payload: Dict[str, Any]  # Webhook payload to forward
    timeout: Optional[int] = 10  # Request timeout in seconds

class WebhookForwardResponse(BaseModel):
    """Response model for webhook forwarding"""
    success: bool
    message: str
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    error: Optional[str] = None

@router.post("/forward", response_model=WebhookForwardResponse)
async def forward_webhook(request: WebhookForwardRequest):
    """
    Forward webhook payload to Discord bot

    This endpoint acts as a proxy between AuthGateway and your local Discord bot.
    Your Discord bot can call this endpoint to forward webhooks from AuthGateway
    to your local bot instance.
    """
    try:
        logger.info(f"📡 Forwarding webhook to: {request.bot_endpoint}")
        logger.debug(f"📦 Webhook payload: {json.dumps(request.payload, indent=2)}")

        # Forward the webhook to the local Discord bot
        async with httpx.AsyncClient(timeout=request.timeout) as client:
            response = await client.post(
                request.bot_endpoint,
                json=request.payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "AuthGateway-Webhook-Proxy/1.0",
                    "X-Forwarded-By": "AuthGateway"
                }
            )

            success = response.status_code in [200, 201, 204]

            # Try to get response body
            try:
                response_body = response.text
            except:
                response_body = None

            return WebhookForwardResponse(
                success=success,
                message=f"Webhook forwarded with status {response.status_code}",
                status_code=response.status_code,
                response_body=response_body
            )

    except httpx.ConnectError as e:
        logger.error(f"❌ Connection error forwarding webhook: {str(e)}")
        return WebhookForwardResponse(
            success=False,
            message="Failed to connect to Discord bot",
            error=f"Connection error: {str(e)}"
        )

    except httpx.TimeoutException as e:
        logger.error(f"❌ Timeout forwarding webhook: {str(e)}")
        return WebhookForwardResponse(
            success=False,
            message="Discord bot timeout",
            error=f"Timeout error: {str(e)}"
        )

    except Exception as e:
        logger.error(f"❌ Error forwarding webhook: {str(e)}")
        return WebhookForwardResponse(
            success=False,
            message="Unexpected error forwarding webhook",
            error=str(e)
        )

@router.get("/health")
async def webhook_proxy_health():
    """Health check endpoint for webhook proxy"""
    return {
        "status": "healthy",
        "service": "AuthGateway Webhook Proxy",
        "description": "Proxy service for forwarding webhooks to local Discord bots"
    }

@router.post("/direct-to-discord")
async def direct_discord_webhook(
    request: Request,
    discord_bot_url: str = None,  # Optional override for bot URL
    timeout: int = 10
):
    """
    Direct endpoint that AuthGateway can call to send webhooks to Discord bots

    Usage:
    POST /webhook-proxy/direct-to-discord?discord_bot_url=http://localhost:3000/webhook/verification
    """
    try:
        # Get the webhook payload from the request
        webhook_payload = await request.json()

        # Use provided URL or default to environment variable
        bot_url = discord_bot_url or os.getenv("DISCORD_BOT_LOCAL_URL", "http://localhost:3000/webhook/verification")

        logger.info(f"📡 Forwarding direct webhook to: {bot_url}")
        logger.debug(f"📦 Webhook payload: {json.dumps(webhook_payload, indent=2)}")

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                bot_url,
                json=webhook_payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "AuthGateway-Direct-Proxy/1.0",
                    "X-Forwarded-By": "AuthGateway"
                }
            )

            success = response.status_code in [200, 201, 204]

            return {
                "success": success,
                "message": f"Webhook forwarded with status {response.status_code}",
                "status_code": response.status_code,
                "forwarded_to": bot_url,
                "response_body": response.text if response.text else None
            }

    except Exception as e:
        logger.error(f"❌ Error in direct webhook forwarding: {str(e)}")
        return {
            "success": False,
            "message": "Failed to forward webhook",
            "error": str(e)
        }