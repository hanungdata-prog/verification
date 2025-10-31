import requests

# Test the API endpoints

# Test the root endpoint
try:
    response = requests.get("http://localhost:8000/")
    print(f"Root endpoint status: {response.status_code}")
except requests.exceptions.ConnectionError:
    print("Server is not running on localhost:8000")

# Test the privacy endpoint
try:
    response = requests.get("http://localhost:8000/privacy")
    print(f"Privacy endpoint status: {response.status_code}")
except requests.exceptions.ConnectionError:
    print("Server is not running on localhost:8000")

# Example of how to test the verify endpoint (without a valid CAPTCHA token, it will fail validation)
try:
    test_data = {
        "discord_id": "123456789012345678",
        "discord_username": "testuser",
        "captcha_token": "invalid-token-for-testing",
        "metadata": {"source": "test"}
    }
    response = requests.post("http://localhost:8000/verify", json=test_data)
    print(f"Verify endpoint status (with invalid CAPTCHA): {response.status_code}")
    print(f"Response: {response.json()}")
except requests.exceptions.ConnectionError:
    print("Server is not running on localhost:8000")
except Exception as e:
    print(f"Error: {e}")