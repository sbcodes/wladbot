#!/usr/bin/env python
"""
Test script to check if our get_ai_response function works correctly
"""
import os
import sys
import logging
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Import the function
# We need to add some of the dummy dependencies needed by the function
import random

# Define fallback responses to match app.py
FALLBACK_RESPONSES = [
    "I'm here to help! What can I assist you with today?",
    "Hello! How can I make your day better?",
    "Greetings! I'm WladBot, your friendly assistant.",
    "Hello there! I'm ready to chat and help out.",
    "Hi! I'm currently operating in offline mode, but I'll do my best to assist you.",
]

def get_fallback_response(user_message):
    """Get a fallback response when the API call fails"""
    return random.choice(FALLBACK_RESPONSES)

def get_ai_response(user_message):
    """Get response from OpenAI API using the official OpenAI Python library with debug logging"""
    try:
        # Log the start of the function
        logger.info("=== Starting OpenAI API request ===")
        
        # Get the API key
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key:
            logger.warning("OPENAI_API_KEY not set! Using fallback responses.")
            return get_fallback_response(user_message)
        
        logger.info("API key is set")
        
        # Import OpenAI library inside function to avoid global initialization issues
        from openai import OpenAI
        
        logger.info("Creating OpenAI client with default configuration")
        
        try:
            # Create client with explicit configuration
            client = OpenAI(
                api_key=api_key,
                timeout=10.0,  # Set timeout to 10 seconds
                max_retries=0  # Disable retries
            )
            logger.info("OpenAI client created successfully")
        except Exception as client_error:
            logger.error(f"Error creating OpenAI client: {client_error}")
            return get_fallback_response(user_message)
        
        logger.info(f"Sending request to OpenAI API with message: '{user_message[:30]}...'")
        logger.info(f"Using model: gpt-4o")
        
        try:
            # Create completion request with explicit response format
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant named WladBot."},
                    {"role": "user", "content": user_message}
                ],
                max_tokens=500,
                temperature=0.7
            )
            logger.info("Received response from OpenAI API")
            
        except Exception as api_error:
            logger.error(f"Error during API call: {api_error}")
            return get_fallback_response(user_message)
        
        # Extract message content
        try:
            ai_response = response.choices[0].message.content.strip()
            logger.info(f"Successfully extracted response: '{ai_response[:50]}...'")
            return ai_response
        except Exception as parse_error:
            logger.error(f"Error parsing response: {parse_error}")
            logger.error(f"Response object: {response}")
            return get_fallback_response(user_message)
            
    except Exception as e:
        logger.error(f"Unexpected error in get_ai_response: {e}")
        return get_fallback_response(user_message)

def test_with_message(message):
    print(f"\n{'=' * 50}")
    print(f"Testing with message: '{message}'")
    print(f"{'=' * 50}\n")
    
    response = get_ai_response(message)
    
    print(f"\n{'=' * 50}")
    print(f"Response: '{response}'")
    print(f"{'=' * 50}\n")
    
    return response

if __name__ == "__main__":
    print("=== Testing OpenAI Response Function ===\n")
    
    messages = [
        "Hello there! How are you today?",
        "What's the weather like?",
        "Tell me a joke",
        "What can you help me with?"
    ]
    
    for msg in messages:
        test_with_message(msg)
        print("\nWaiting 5 seconds before next request...\n")
        import time
        time.sleep(5) 