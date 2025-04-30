#!/usr/bin/env python
"""
Local development server runner optimized for Socket.IO
"""
import os
import eventlet
import ssl

# Need to monkey patch before importing any other libraries
eventlet.monkey_patch()

from app import app, socketio

if __name__ == '__main__':
    # Enable SSL support
    ssl_args = {}
    cert_path = os.path.join('certs', 'cert.pem')
    key_path = os.path.join('certs', 'key.pem')
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        # Create an SSL context for eventlet
        ssl_args['certfile'] = cert_path
        ssl_args['keyfile'] = key_path
        print(f"SSL certificates found, running with HTTPS")
    else:
        print(f"SSL certificates not found at {cert_path} and {key_path}")
        print("Running without HTTPS (not recommended)")
    
    # Determine port
    port = int(os.environ.get('PORT', 8443))
    
    print(f"Starting development server on {'https' if ssl_args else 'http'}://localhost:{port}")
    print("Press Ctrl+C to stop")
    
    # Run the development server
    # When using eventlet directly, we need to pass certfile/keyfile instead of ssl_context
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=True,
        **ssl_args,  # Pass SSL arguments directly
        use_reloader=True,
        allow_unsafe_werkzeug=True
    ) 