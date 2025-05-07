#!/usr/bin/env python
"""
Simple Socket.IO client to test connectivity to the server
"""
import socketio
import time
import sys
import os
import argparse

def main():
    parser = argparse.ArgumentParser(description='Test Socket.IO connection')
    parser.add_argument('--url', default='https://localhost:8443', help='Server URL (default: https://localhost:8443)')
    parser.add_argument('--message', default='Hello from test client!', help='Test message to send')
    args = parser.parse_args()
    
    print(f"Connecting to {args.url}...")
    
    # Create a Socket.IO client
    sio = socketio.Client(ssl_verify=False)  # Skip SSL verification for self-signed certs
    
    # Define event handlers
    @sio.event
    def connect():
        print("Connected to server!")
        print(f"Session ID: {sio.sid}")
        print("Sending test message...")
        sio.emit('send_message', {'message': args.message})
    
    @sio.event
    def connect_error(data):
        print(f"Connection error: {data}")
    
    @sio.event
    def disconnect():
        print("Disconnected from server")
    
    @sio.on('new_message')
    def on_message(data):
        print(f"Received message: {data['username']}: {data['message']} ({data['timestamp']})")
    
    @sio.on('message_history')
    def on_history(data):
        print(f"Received message history ({len(data)} messages)")
        for msg in data:
            print(f"  {msg['username']}: {msg['message']} ({msg['timestamp']})")
    
    # Connect to the server
    try:
        sio.connect(args.url, transports=['websocket'], wait_timeout=10)
        
        # Keep the connection alive for a bit
        print("Connection established, waiting for events...")
        for i in range(30):
            print(f"Waiting... ({i+1}/30)", end='\r')
            time.sleep(1)
        
        # Disconnect
        sio.disconnect()
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main()) 