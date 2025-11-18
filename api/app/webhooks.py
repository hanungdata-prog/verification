import os
import httpx
import logging
from datetime import datetime
from typing import Dict, Any
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

async def send_webhook(
    success: bool,
    discord_id: str,
    discord_username: str,
    ip_address: str,  # This is encrypted
    verification_id: str = None
) -> bool:
    """
    Send a webhook to Discord bot with verification result
    This uses AuthGateway website as proxy to reach local Discord bot
    """
    # Get AuthGateway base URL
    authgateway_url = os.getenv("AUTH_GATEWAY_URL", "https://apinode1a2b3c4d5e6f7g8h9i0j1k2l3m4n.vercel.app")

    # Get local Discord bot URL
    local_bot_url = os.getenv("DISCORD_BOT_LOCAL_URL", "http://localhost:3000/webhook/verification")

    logger.info(f"Attempting to send webhook via AuthGateway proxy for user {discord_username} ({discord_id})")
    logger.info(f"AuthGateway URL: {authgateway_url}")
    logger.info(f"Target Discord Bot: {local_bot_url}")

    # Use AuthGateway as proxy to reach local Discord bot
    webhook_url = f"{authgateway_url}/webhook-proxy/direct-to-discord?discord_bot_url={local_bot_url}"

    logger.info(f"Proxy webhook URL: {webhook_url}")

    # Prepare verification data for bot
    verification_data = {
        "success": success,
        "discord_id": discord_id,
        "discord_username": discord_username,
        "verification_id": verification_id,
        "ip_address": ip_address,  # Include IP address for bot reference
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "verification_completed" if success else "verification_failed",
        "message": f"User {discord_username} ({discord_id}) verification {'completed successfully' if success else 'failed'}"
    }

    try:
        logger.info(f"Sending webhook to bot for {discord_username} ({discord_id})")
        logger.debug(f"Webhook URL: {webhook_url}")
        logger.debug(f"Webhook data: {verification_data}")

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                webhook_url,
                json=verification_data,
                timeout=10.0  # 10 second timeout
            )

            # Return True if the request was successful
            success_status = response.status_code in [200, 201, 204]
            if success_status:
                logger.info(f"✅ Webhook sent to bot successfully for {discord_username}")
                logger.debug(f"Bot response status: {response.status_code}")
            else:
                logger.error(f"❌ Webhook to bot failed with status {response.status_code}")
                logger.error(f"Bot response: {response.text}")

            return success_status
    except Exception as e:
        logger.error(f"Error sending webhook to bot: {str(e)}")
        return False  # Return False to indicate failure