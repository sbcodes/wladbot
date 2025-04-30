#!/usr/bin/env python
"""
Script to fix the DATABASE_URL in the systemd service file
This script must be run with sudo
"""
import os
import sys
import re
import urllib.parse
import subprocess

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("This script must be run as root (sudo).")
        print("Run: sudo python fix_service_db_url.py")
        sys.exit(1)
    
    service_file = "/etc/systemd/system/wladbot.service"
    
    # Check if service file exists
    if not os.path.exists(service_file):
        print(f"Error: Service file {service_file} not found.")
        sys.exit(1)
    
    # Read the service file
    with open(service_file, 'r') as f:
        content = f.read()
    
    # Find the DATABASE_URL line using regex
    database_url_match = re.search(r'Environment="DATABASE_URL=([^"]+)"', content)
    if not database_url_match:
        print("DATABASE_URL not found in the service file.")
        sys.exit(1)
    
    database_url = database_url_match.group(1)
    print(f"Found DATABASE_URL in service file.")
    
    # Parse the URL and fix it
    try:
        # Extract components using regex
        match = re.match(r'postgresql://([^:]+):([^@]+)@([^/]+)/(.+)', database_url)
        if not match:
            print(f"Error: Could not parse DATABASE_URL format.")
            sys.exit(1)
        
        username, password, host, dbname = match.groups()
        
        # URL encode the password
        encoded_password = urllib.parse.quote_plus(password)
        
        # Reconstruct the URL
        fixed_url = f"postgresql://{username}:{encoded_password}@{host}/{dbname}"
        
        # Check if it needs fixing
        if fixed_url == database_url:
            print("DATABASE_URL is already properly encoded. No changes needed.")
            sys.exit(0)
        
        # Update the service file
        new_content = content.replace(
            f'Environment="DATABASE_URL={database_url}"', 
            f'Environment="DATABASE_URL={fixed_url}"'
        )
        
        with open(service_file, 'w') as f:
            f.write(new_content)
        
        print("Updated DATABASE_URL in service file.")
        print("Running systemctl daemon-reload...")
        
        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"])
        
        print("\nDone! You should now be able to run:")
        print("python init_db.py")
        print("\nThen restart your service:")
        print("sudo systemctl restart wladbot")
        
    except Exception as e:
        print(f"Error updating DATABASE_URL: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 