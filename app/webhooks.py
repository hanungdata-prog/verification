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
    This sends data to the bot's webhook listener instead of Discord channel webhook
    """
    # Get webhook URL from environment
    webhook_url = os.getenv("DISCORD_BOT_WEBHOOK_URL")
    if not webhook_url:
        logger.warning("No DISCORD_BOT_WEBHOOK_URL set, skipping webhook to bot")
        # Fallback to original Discord webhook if available
        webhook_url = DISCORD_WEBHOOK_URL

    if not webhook_url:
        logger.warning("No webhook URL configured, skipping webhook")
        return True  # Don't fail if webhook URL is not configured

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