#!/usr/bin/env python
"""
Test script to check connectivity to OpenAI API servers
"""
import os
import sys
import requests
import socket
import time
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.environ.get('OPENAI_API_KEY')
API_DOMAIN = 'api.openai.com'

def check_dns():
    """Check if the OpenAI API domain can be resolved via DNS"""
    print(f"Testing DNS resolution for {API_DOMAIN}...")
    try:
        ip_address = socket.gethostbyname(API_DOMAIN)
        print(f"✅ DNS resolution successful: {API_DOMAIN} resolves to {ip_address}")
        return True
    except socket.gaierror as e:
        print(f"❌ DNS resolution failed: {e}")
        return False

def check_connection():
    """Check if we can establish a connection to the OpenAI API server"""
    print(f"Testing connection to {API_DOMAIN}...")
    try:
        start_time = time.time()
        response = requests.get(f"https://{API_DOMAIN}/v1/models", 
                               headers={"Authorization": f"Bearer {API_KEY}"},
                               timeout=10)
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            print(f"✅ Connection successful (took {elapsed:.2f}s)")
            print(f"Available models: {len(response.json()['data'])} models")
            return True
        else:
            print(f"❌ Connection failed with status code {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Connection failed: {e}")
        return False

def test_api_call():
    """Test a simple API call to OpenAI"""
    if not API_KEY:
        print("❌ API key not found. Please set the OPENAI_API_KEY environment variable.")
        return False
    
    print("Testing OpenAI API with a simple query...")
    try:
        url = f"https://{API_DOMAIN}/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}"
        }
        data = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Say hello!"}
            ],
            "max_tokens": 10
        }
        
        start_time = time.time()
        response = requests.post(url, headers=headers, json=data, timeout=15)
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            content = response.json()["choices"][0]["message"]["content"]
            print(f"✅ API call successful (took {elapsed:.2f}s)")
            print(f"Response: {content}")
            return True
        else:
            print(f"❌ API call failed with status code {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ API call failed: {e}")
        return False

if __name__ == "__main__":
    print("=== OpenAI API Connection Test ===")
    
    dns_ok = check_dns()
    if not dns_ok:
        print("\nTroubleshooting tips for DNS issues:")
        print("1. Check your internet connection")
        print("2. Try flushing your DNS cache")
        print("3. Try using a different DNS server")
        print("4. Check if your firewall is blocking DNS requests")
    
    print("\n" + "="*30 + "\n")
    
    conn_ok = check_connection()
    if not conn_ok:
        print("\nTroubleshooting tips for connection issues:")
        print("1. Check if your firewall or proxy is blocking HTTPS connections")
        print("2. Check if you need to configure proxy settings")
        print("3. Try using a different network connection")
    
    print("\n" + "="*30 + "\n")
    
    api_ok = test_api_call()
    if not api_ok:
        print("\nTroubleshooting tips for API issues:")
        print("1. Verify your API key is correct")
        print("2. Check if your account has access to the requested model")
        print("3. Check if you've reached your API rate limit")
    
    print("\n" + "="*30 + "\n")
    
    if dns_ok and conn_ok and api_ok:
        print("✅ All tests passed! Your connection to OpenAI is working properly.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Please review the troubleshooting suggestions above.")
        sys.exit(1) 