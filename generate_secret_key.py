#!/usr/bin/env python3
import os
import base64

def generate_secret_key(length=32):
    """Generate a secure random secret key."""
    # Generate random bytes
    random_bytes = os.urandom(length)
    # Convert to base64 string and remove any characters that might cause issues
    secret_key = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
    return secret_key

if __name__ == "__main__":
    # Generate a 32-byte (256-bit) secret key
    secret_key = generate_secret_key()
    print("\nGenerated Secret Key (copy this to your .env file or service config):")
    print(f"SECRET_KEY={secret_key}") 