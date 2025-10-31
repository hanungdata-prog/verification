import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def encrypt_ip(ip_address: str) -> str:
    """
    Return IP address as-is (no encryption)
    """
    return ip_address

def decrypt_ip(encrypted_ip: str) -> str:
    """
    Return IP address as-is (no decryption needed)
    """
    return encrypted_ip