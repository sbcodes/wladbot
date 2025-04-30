#!/usr/bin/env python
"""
Script to fix the DATABASE_URL in the environment and service file
"""
import os
import sys
import subprocess
import urllib.parse

def fix_db_url():
    # Check if DATABASE_URL is set
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        print("Error: DATABASE_URL environment variable not set.")
        print("Please run this script with the DATABASE_URL environment variable set.")
        print("Example: DATABASE_URL=postgresql://username:password@localhost/dbname python fix_db_url.py")
        sys.exit(1)
    
    # Parse the URL to extract components
    try:
        scheme = database_url.split("://")[0]
        rest = database_url.split("://")[1]
        
        credentials, connection = rest.split("@", 1)
        username, password = credentials.split(":", 1)
        
        # URL encode the password
        encoded_password = urllib.parse.quote_plus(password)
        
        # Reconstruct the URL
        fixed_url = f"{scheme}://{username}:{encoded_password}@{connection}"
        
        print(f"Original URL: {scheme}://{username}:****@{connection}")
        print(f"Fixed URL: {scheme}://{username}:****@{connection}")
        print(f"Password encoding changed: {'Yes' if password != encoded_password else 'No'}")
        
        # Update the service file
        service_path = "/etc/systemd/system/wladbot.service"
        if os.path.exists(service_path):
            # Need to use sudo for this
            print(f"\nTo update the systemd service file, run:")
            print(f"sudo sed -i 's|DATABASE_URL=.*|DATABASE_URL={fixed_url}|g' {service_path}")
            print(f"sudo systemctl daemon-reload")
        
        # Print instructions for manual update
        print("\nTo update your current session:")
        print(f"export DATABASE_URL='{fixed_url}'")
        
        print("\nTo make this change permanent, update your .env file or add it to /etc/environment:")
        print(f"DATABASE_URL='{fixed_url}'")
        
        return fixed_url
        
    except Exception as e:
        print(f"Error parsing DATABASE_URL: {e}")
        sys.exit(1)

if __name__ == "__main__":
    fixed_url = fix_db_url()
    
    # Offer to update the environment
    should_update = input("\nDo you want to export the fixed DATABASE_URL to the current shell? (y/n): ")
    if should_update.lower() == 'y':
        # Just print the export command for the user to run
        print(f"\nRun this command:")
        print(f"export DATABASE_URL='{fixed_url}'")
        
        print("\nThen initialize the database:")
        print("python init_db.py") 