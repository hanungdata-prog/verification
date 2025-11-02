#!/usr/bin/env python3
"""
Test script to verify security error page functionality
"""

import asyncio
import httpx
import sys

BASE_URL = "https://apinode1a2b3c4d5e6f7g8h9i0j1k2l3m4n.vercel.app"  # Change to your deployment URL

async def test_security_error_page():
    """Test the security error page with different error types"""

    print("🧪 Testing Security Error Page")
    print("=" * 50)

    # Test different error reasons
    test_cases = [
        {"reason": "domain", "expected_title": "Invalid Domain Access"},
        {"reason": "vpn", "expected_title": "VPN or Proxy Detected"},
        {"reason": "rate_limit", "expected_title": "Rate Limit Exceeded"},
        {"reason": "already_verified", "expected_title": "Already Verified"},
        {"reason": "suspicious", "expected_title": "Suspicious Activity Detected"},
        {"reason": "blocked", "expected_title": "Access Blocked"},
        {"reason": "csrf", "expected_title": "Security Token Invalid"},
        {"reason": "unknown", "expected_title": "Security Error"}  # Test unknown reason
    ]

    async with httpx.AsyncClient() as client:
        for i, test_case in enumerate(test_cases, 1):
            reason = test_case["reason"]
            expected_title = test_case["expected_title"]

            print(f"\n📋 Test {i}: {reason}")
            print("-" * 30)

            try:
                # Test the security error page
                url = f"{BASE_URL}/security-error.html"
                params = {"reason": reason, "message": f"Test message for {reason}"}

                response = await client.get(url, params=params, timeout=10)

                print(f"Status Code: {response.status_code}")

                if response.status_code == 200:
                    content = response.text

                    # Check if expected title is in content
                    if expected_title in content:
                        print(f"✅ Contains expected title: '{expected_title}'")
                    else:
                        print(f"❌ Missing expected title: '{expected_title}'")
                        print(f"Content preview: {content[:200]}...")

                    # Check for basic HTML structure
                    if "<!DOCTYPE html>" in content and "</html>" in content:
                        print("✅ Valid HTML structure")
                    else:
                        print("❌ Invalid HTML structure")

                    # Check for security icon
                    if "🛡️" in content:
                        print("✅ Contains security icon")
                    else:
                        print("❌ Missing security icon")

                    # Check for return button
                    if "Return to Verification" in content:
                        print("✅ Contains return button")
                    else:
                        print("❌ Missing return button")

                else:
                    print(f"❌ Failed with status: {response.status_code}")
                    print(f"Response: {response.text[:200]}...")

            except httpx.RequestError as e:
                print(f"❌ Request failed: {e}")
            except Exception as e:
                print(f"❌ Unexpected error: {e}")

async def test_test_endpoint():
    """Test the test security error endpoint"""

    print("\n\n🧪 Testing Test Endpoint")
    print("=" * 50)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{BASE_URL}/test-security-error", timeout=10)

            print(f"Status Code: {response.status_code}")

            if response.status_code == 200:
                print("✅ Test endpoint working")
                print(f"Content preview: {response.text[:200]}...")
            else:
                print(f"❌ Test endpoint failed: {response.status_code}")
                print(f"Response: {response.text[:200]}...")

    except Exception as e:
        print(f"❌ Test endpoint error: {e}")

async def test_file_serving():
    """Test if the static security-error.html file can be served directly"""

    print("\n\n🧪 Testing Static File Serving")
    print("=" * 50)

    file_paths = [
        "public/security-error.html",
        "/public/security-error.html"
    ]

    for file_path in file_paths:
        print(f"\n📁 Testing file: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                print(f"✅ File found and readable ({len(content)} characters)")

                # Check file content
                if "🛡️" in content:
                    print("✅ Contains security icon")
                if "error-container" in content:
                    print("✅ Contains expected CSS classes")
                if "errorReasons" in content:
                    print("✅ Contains JavaScript error handling")

        except FileNotFoundError:
            print(f"❌ File not found: {file_path}")
        except Exception as e:
            print(f"❌ Error reading file: {e}")

async def main():
    """Main test function"""
    print("🚀 AuthGateway Security Error Page Tests")
    print("=" * 60)
    print(f"Testing against: {BASE_URL}")

    # Test file serving first
    await test_file_serving()

    # Test test endpoint
    await test_test_endpoint()

    # Test security error page with different parameters
    await test_security_error_page()

    print("\n\n🎉 Testing Complete!")
    print("=" * 60)
    print("If all tests passed, the security error page should work correctly.")

if __name__ == "__main__":
    # Allow command line argument to change base URL
    if len(sys.argv) > 1:
        BASE_URL = sys.argv[1]

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Test suite failed: {e}")
        sys.exit(1)