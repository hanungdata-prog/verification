import pytest
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from sqlmodel import SQLModel, create_engine
from sqlmodel.pool import StaticPool
from app.models import Verification
from unittest.mock import patch, AsyncMock

# Create a test client
client = TestClient(app)

def test_root_endpoint():
    """Test the root endpoint serves the verification page"""
    response = client.get("/")
    assert response.status_code == 200
    assert "Discord Verification" in response.text

def test_privacy_endpoint():
    """Test the privacy policy endpoint"""
    response = client.get("/privacy")
    assert response.status_code == 200
    assert "Privacy Policy" in response.text

@patch('app.captcha.validate_captcha')
@patch('app.webhooks.send_webhook')
def test_verify_endpoint_success(mock_webhook, mock_captcha):
    """Test successful verification"""
    # Mock CAPTCHA validation to return True (valid)
    mock_captcha.return_value = AsyncMock(return_value=True)
    
    # Mock webhook to return True (successful)
    mock_webhook.return_value = AsyncMock(return_value=True)
    
    # Valid test data
    data = {
        "discord_id": "123456789012345678",  # Valid Discord ID format
        "discord_username": "testuser",
        "captcha_token": "valid-token",
        "metadata": {"source": "test"}
    }
    
    response = client.post("/verify", json=data)
    
    assert response.status_code == 200
    assert response.json()["success"] is True
    assert "Verification successful" in response.json()["message"]

@patch('app.captcha.validate_captcha')
def test_verify_endpoint_invalid_discord_id(mock_captcha):
    """Test verification with invalid Discord ID"""
    # Mock CAPTCHA validation to return True (shouldn't reach this)
    mock_captcha.return_value = AsyncMock(return_value=True)
    
    # Invalid Discord ID (not 17-20 digits)
    data = {
        "discord_id": "invalid_id",  # Invalid Discord ID format
        "discord_username": "testuser",
        "captcha_token": "valid-token",
        "metadata": {}
    }
    
    response = client.post("/verify", json=data)
    
    assert response.status_code == 400
    assert "Invalid Discord ID format" in response.json()["detail"]

@patch('app.captcha.validate_captcha')
def test_verify_endpoint_failed_captcha(mock_captcha):
    """Test verification with failed CAPTCHA validation"""
    # Mock CAPTCHA validation to return False (invalid)
    mock_captcha.return_value = AsyncMock(return_value=False)
    
    # Valid test data
    data = {
        "discord_id": "123456789012345678",  # Valid Discord ID format
        "discord_username": "testuser",
        "captcha_token": "invalid-token",
        "metadata": {}
    }
    
    response = client.post("/verify", json=data)
    
    assert response.status_code == 400
    assert "CAPTCHA validation failed" in response.json()["detail"]

def test_verify_endpoint_missing_fields():
    """Test verification with missing required fields"""
    # Missing required fields
    data = {
        "discord_id": "123456789012345678",  # Valid Discord ID format
        # Missing discord_username and captcha_token
    }
    
    response = client.post("/verify", json=data)
    
    assert response.status_code == 422  # Validation error

def test_rate_limiting():
    """Test rate limiting functionality"""
    # Mock CAPTCHA validation to return True (valid)
    with patch('app.captcha.validate_captcha', return_value=AsyncMock(return_value=True)), \
         patch('app.webhooks.send_webhook', return_value=AsyncMock(return_value=True)):
        
        # Send multiple requests from the same IP (should trigger rate limiting)
        data = {
            "discord_id": "123456789012345678",
            "discord_username": "testuser",
            "captcha_token": "valid-token",
            "metadata": {}
        }
        
        # Send 6 requests (rate limit is 5 per 10 minutes)
        for i in range(6):
            response = client.post("/verify", json=data, headers={"X-Forwarded-For": "192.168.1.1"})
            if i == 5:  # The 6th request should be rate limited
                assert response.status_code == 429
                break
        else:
            # If rate limiting isn't working as expected in test environment,
            # we'll just verify that the first 5 requests succeeded
            assert response.status_code == 200

if __name__ == "__main__":
    pytest.main()