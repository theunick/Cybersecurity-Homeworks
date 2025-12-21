#!/usr/bin/env python3
"""
VPN Server - SafeGuard Protocol
Implements the server side of the SafeGuard VPN protocol.

Protocol Flow (Server's perspective):
1. Listen for client connections
2. Receive CLIENT_HELLO and perform key exchange
3. Send SERVER_HELLO with public key
4. Receive encrypted data from client
5. Decrypt, forward to destination
6. Encrypt response and send back to client
"""

import socket
import sys
import os
import threading
import time
import requests
from urllib.parse import urlparse

# Add shared directory to path
sys.path.insert(0, '/app/shared')

from protocol import (
    SafeGuardProtocol,
    MSG_CLIENT_HELLO, MSG_SERVER_HELLO, MSG_DATA, MSG_ERROR, MSG_CLOSE,
    send_message, receive_message
)


class SafeGuardServer:
    """SafeGuard VPN Server implementation."""
    
    def __init__(self, host='0.0.0.0', port=8443):
        self.host = host
        self.port = port
        self.active_sessions = 0
    
    def handle_client(self, conn, addr):
        """
        Handle a single VPN client session.
        
        Args:
            conn: Socket connection
            addr: Client address
        """
        print(f"\n{'='*60}")
        print(f"🔒 New VPN connection from {addr}")
        print(f"{'='*60}\n")
        
        protocol = SafeGuardProtocol()
        
        try:
            # Phase 1: Handshake - Receive CLIENT_HELLO
            print("📥 Phase 1: Waiting for CLIENT_HELLO...")
            msg = receive_message(conn)
            
            if msg is None or msg['type'] != MSG_CLIENT_HELLO:
                send_message(conn, MSG_ERROR, message="Expected CLIENT_HELLO")
                return
            
            print(f"✅ Received CLIENT_HELLO")
            print(f"   Client public key: {msg['data']['public_key'][:32]}...")
            
            # Phase 2: Respond with SERVER_HELLO
            print(f"\n📤 Phase 2: Performing key exchange...")
            server_hello = protocol.respond_handshake(msg)
            
            # Parse the JSON to send as message
            import json
            server_hello_data = json.loads(server_hello)
            send_message(conn, MSG_SERVER_HELLO, **server_hello_data['data'])
            
            print(f"✅ Sent SERVER_HELLO")
            print(f"   Server public key: {server_hello_data['data']['public_key'][:32]}...")
            print(f"✅ Shared secret computed via ECDH")
            print(f"✅ Session keys derived using HKDF")
            print(f"🔐 Secure tunnel established!\n")
            
            # Phase 3: Handle encrypted traffic
            print("📡 Phase 3: Waiting for encrypted requests...\n")
            
            while True:
                # Receive encrypted request from client
                msg = receive_message(conn)
                
                if msg is None:
                    print("Connection closed by client")
                    break
                
                if msg['type'] == MSG_CLOSE:
                    print("Client requested connection close")
                    break
                
                if msg['type'] == MSG_ERROR:
                    print(f"❌ Error from client: {msg['data']['message']}")
                    break
                
                if msg['type'] != MSG_DATA:
                    print(f"❌ Unexpected message type: {msg['type']}")
                    continue
                
                # Decrypt the request
                try:
                    plaintext = protocol.decrypt_data(msg)
                    request_data = plaintext.decode('utf-8')
                    
                    print(f"🔓 Decrypted request from client:")
                    print(f"   {request_data[:100]}...")
                    
                    # Parse the HTTP request
                    import json
                    request_info = json.loads(request_data)
                    url = request_info['url']
                    
                    print(f"\n🌐 Forwarding request to: {url}")
                    
                    # Forward the request to the actual destination
                    start_time = time.time()
                    response = requests.get(url, stream=True, timeout=60)
                    
                    # Read response data
                    response_data = response.content
                    elapsed = time.time() - start_time
                    
                    print(f"✅ Received response: {len(response_data)} bytes")
                    print(f"⏱️  Time: {elapsed:.2f}s\n")
                    
                    # Prepare response info
                    response_info = {
                        'status_code': response.status_code,
                        'content_length': len(response_data),
                        'elapsed_time': elapsed
                    }
                    
                    # Encrypt and send back to client
                    response_json = json.dumps(response_info)
                    encrypted_msg = protocol.encrypt_data(response_json.encode('utf-8'))
                    
                    # Parse and send
                    encrypted_data = json.loads(encrypted_msg)
                    send_message(conn, MSG_DATA, **encrypted_data['data'])
                    
                    print(f"🔒 Encrypted and sent response to client\n")
                    print(f"{'='*60}\n")
                    
                except Exception as e:
                    print(f"❌ Error processing request: {e}")
                    send_message(conn, MSG_ERROR, message=str(e))
                    break
            
            print(f"✅ Session ended with {addr}")
            
        except Exception as e:
            print(f"❌ Error handling client: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
            self.active_sessions -= 1
    
    def start(self):
        """Start the VPN server."""
        print(f"\n{'='*60}")
        print(f"🚀 SafeGuard VPN Server Starting")
        print(f"{'='*60}")
        print(f"📡 Listening on {self.host}:{self.port}")
        print(f"🔐 Protocol: SafeGuard VPN v1.0")
        print(f"🔒 Encryption: AES-256-GCM")
        print(f"🔑 Key Exchange: ECDH with Curve25519")
        print(f"✨ Perfect Forward Secrecy enabled")
        print(f"{'='*60}\n")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(5)
            
            print(f"✅ Server ready and waiting for connections...\n")
            
            while True:
                try:
                    conn, addr = server_sock.accept()
                    self.active_sessions += 1
                    
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    print("\n🛑 Server shutting down...")
                    break
                except Exception as e:
                    print(f"❌ Error accepting connection: {e}")


def main():
    """Main entry point."""
    host = os.getenv('SERVER_HOST', '0.0.0.0')
    port = int(os.getenv('SERVER_PORT', 8443))
    
    server = SafeGuardServer(host, port)
    server.start()


if __name__ == '__main__':
    main()
