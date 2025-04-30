#!/usr/bin/env python3
import bcrypt
import getpass

def hash_password():
    password = getpass.getpass("Enter password to hash: ")
    confirm = getpass.getpass("Confirm password: ")
    
    if password != confirm:
        print("Passwords don't match!")
        return
    
    # Generate salt and hash the password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Print the hash that can be used in environment variables
    print("\nHashed password (copy this to your .env file or service config):")
    print(f"HASHED_PASSWORD={hashed.decode('utf-8')}")

if __name__ == "__main__":
    hash_password() 