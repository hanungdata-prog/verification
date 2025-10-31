import os
import httpx
from datetime import datetime
from typing import Dict, Any
from dotenv import load_dotenv

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
        print("Warning: No DISCORD_BOT_WEBHOOK_URL set, skipping webhook to bot")
        # Fallback to original Discord webhook if available
        webhook_url = DISCORD_WEBHOOK_URL

    if not webhook_url:
        print("Warning: No webhook URL configured, skipping webhook")
        return True  # Don't fail if webhook URL is not configured

    # Prepare verification data for bot
    verification_data = {
        "success": success,
        "discord_id": discord_id,
        "discord_username": discord_username,
        "verification_id": verification_id,
        "timestamp": datetime.utcnow().isoformat()
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook_url,
                json=verification_data,
                timeout=10.0  # 10 second timeout
            )

            # Return True if the request was successful
            success_status = response.status_code in [200, 204]
            if success_status:
                print(f"✅ Webhook sent to bot successfully for {discord_username}")
            else:
                print(f"❌ Webhook to bot failed with status {response.status_code}")

            return success_status
    except Exception as e:
        print(f"Error sending webhook to bot: {str(e)}")
        return False  # Return False to indicate failure