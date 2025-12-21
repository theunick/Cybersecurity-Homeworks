#!/usr/bin/env python3
"""
VPN Client - SafeGuard Protocol
Implements the client side of the SafeGuard VPN protocol.

Protocol Flow (Client's perspective):
1. Connect to VPN server
2. Send CLIENT_HELLO and perform key exchange
3. Receive SERVER_HELLO
4. Encrypt HTTP request and send through tunnel
5. Receive encrypted response
6. Decrypt and process response
7. Run performance benchmark with and without VPN
"""

import socket
import sys
import os
import time
import json
import subprocess

# Add shared directory to path
sys.path.insert(0, '/app/shared')

from protocol import (
    SafeGuardProtocol,
    MSG_CLIENT_HELLO, MSG_SERVER_HELLO, MSG_DATA, MSG_ERROR, MSG_CLOSE,
    send_message, receive_message
)


class SafeGuardClient:
    """SafeGuard VPN Client implementation."""
    
    def __init__(self, server_host='server', server_port=8443):
        self.server_host = server_host
        self.server_port = server_port
        self.protocol = SafeGuardProtocol()
        self.connected = False
        self.sock = None
    
    def connect(self):
        """Establish VPN connection to server."""
        print(f"\n{'='*60}")
        print(f"🔒 SafeGuard VPN Client")
        print(f"{'='*60}")
        print(f"📡 Connecting to VPN server at {self.server_host}:{self.server_port}")
        print(f"🔐 Protocol: SafeGuard VPN v1.0")
        print(f"{'='*60}\n")
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_host, self.server_port))
            print(f"✅ TCP connection established\n")
            
            # Phase 1: Send CLIENT_HELLO
            print("📤 Phase 1: Initiating handshake...")
            client_hello = self.protocol.initiate_handshake()
            
            # Parse and send
            client_hello_data = json.loads(client_hello)
            send_message(self.sock, MSG_CLIENT_HELLO, **client_hello_data['data'])
            
            print(f"✅ Sent CLIENT_HELLO")
            print(f"   Client public key: {client_hello_data['data']['public_key'][:32]}...")
            
            # Phase 2: Receive SERVER_HELLO
            print(f"\n📥 Phase 2: Waiting for SERVER_HELLO...")
            msg = receive_message(self.sock)
            
            if msg is None or msg['type'] != MSG_SERVER_HELLO:
                print(f"❌ Expected SERVER_HELLO, got: {msg['type'] if msg else 'None'}")
                return False
            
            print(f"✅ Received SERVER_HELLO")
            print(f"   Server public key: {msg['data']['public_key'][:32]}...")
            
            # Complete handshake
            self.protocol.complete_handshake(msg)
            
            print(f"✅ Shared secret computed via ECDH")
            print(f"✅ Session keys derived using HKDF")
            print(f"🔐 Secure VPN tunnel established!\n")
            
            self.connected = True
            return True
            
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def send_request(self, url):
        """
        Send HTTP request through VPN tunnel.
        
        Args:
            url: URL to request
            
        Returns:
            Response info dictionary or None
        """
        if not self.connected:
            print("❌ Not connected to VPN")
            return None
        
        try:
            print(f"{'='*60}")
            print(f"🌐 Sending request through VPN tunnel")
            print(f"{'='*60}")
            print(f"📍 URL: {url}")
            
            # Prepare request
            request_data = json.dumps({'url': url})
            
            # Encrypt request
            print(f"\n🔒 Encrypting request with AES-256-GCM...")
            encrypted_msg = self.protocol.encrypt_data(request_data.encode('utf-8'))
            
            # Parse and send
            encrypted_data = json.loads(encrypted_msg)
            print(f"✅ Request encrypted")
            print(f"   Nonce: {encrypted_data['data']['nonce'][:24]}...")
            print(f"   Ciphertext: {len(encrypted_data['data']['ciphertext'])} hex chars")
            
            print(f"\n📤 Sending encrypted request to VPN server...")
            start_time = time.time()
            send_message(self.sock, MSG_DATA, **encrypted_data['data'])
            
            # Receive encrypted response
            print(f"📥 Waiting for encrypted response...")
            msg = receive_message(self.sock)
            
            if msg is None:
                print("❌ Connection closed")
                return None
            
            if msg['type'] == MSG_ERROR:
                print(f"❌ Error from server: {msg['data']['message']}")
                return None
            
            if msg['type'] != MSG_DATA:
                print(f"❌ Unexpected message type: {msg['type']}")
                return None
            
            # Decrypt response
            print(f"🔓 Decrypting response...")
            plaintext = self.protocol.decrypt_data(msg)
            response_info = json.loads(plaintext.decode('utf-8'))
            
            elapsed = time.time() - start_time
            
            print(f"✅ Response received and decrypted")
            print(f"   Status: {response_info['status_code']}")
            print(f"   Size: {response_info['content_length']} bytes")
            print(f"   Server time: {response_info['elapsed_time']:.2f}s")
            print(f"   Total VPN time: {elapsed:.2f}s")
            print(f"{'='*60}\n")
            
            response_info['total_time'] = elapsed
            return response_info
            
        except Exception as e:
            print(f"❌ Request failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def close(self):
        """Close VPN connection."""
        if self.sock:
            try:
                send_message(self.sock, MSG_CLOSE)
            except:
                pass
            self.sock.close()
            self.connected = False
            print("🔒 VPN connection closed")
    
    def benchmark_direct(self, url):
        """
        Benchmark direct connection (no VPN).
        
        Args:
            url: URL to test
            
        Returns:
            Time in seconds or None
        """
        print(f"\n{'='*60}")
        print(f"📊 BENCHMARK: Direct Connection (No VPN)")
        print(f"{'='*60}")
        print(f"📍 URL: {url}\n")
        
        try:
            cmd = [
                'curl', '-o', '/dev/null', '-w', '%{time_total}\\n', '-s', url
            ]
            
            print("⏱️  Running: curl -o /dev/null -w \"%{time_total}\\n\" <URL>")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                time_str = result.stdout.strip()
                total_time = float(time_str)
                print(f"✅ Direct connection time: {total_time:.2f}s")
                print(f"{'='*60}\n")
                return total_time
            else:
                print(f"❌ Curl failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"❌ Benchmark failed: {e}")
            return None
    
    def benchmark_vpn(self, url):
        """
        Benchmark VPN connection.
        
        Args:
            url: URL to test
            
        Returns:
            Time in seconds or None
        """
        print(f"\n{'='*60}")
        print(f"📊 BENCHMARK: VPN Connection")
        print(f"{'='*60}")
        print(f"📍 URL: {url}\n")
        
        response = self.send_request(url)
        
        if response:
            print(f"✅ VPN connection time: {response['total_time']:.2f}s")
            print(f"{'='*60}\n")
            return response['total_time']
        else:
            return None
    
    def run_performance_test(self, test_url):
        """
        Run complete performance test comparing direct vs VPN.
        
        Args:
            test_url: URL for testing
        """
        print(f"\n{'#'*60}")
        print(f"🚀 PERFORMANCE COMPARISON TEST")
        print(f"{'#'*60}\n")
        
        # Test 1: Direct connection
        direct_time = self.benchmark_direct(test_url)
        
        time.sleep(2)  # Brief pause between tests
        
        # Test 2: VPN connection
        vpn_time = self.benchmark_vpn(test_url)
        
        # Summary
        print(f"\n{'#'*60}")
        print(f"📈 RESULTS SUMMARY")
        print(f"{'#'*60}\n")
        
        if direct_time and vpn_time:
            overhead = vpn_time - direct_time
            overhead_pct = (overhead / direct_time) * 100
            
            print(f"⚡ Direct Connection: {direct_time:.2f}s")
            print(f"🔒 VPN Connection:    {vpn_time:.2f}s")
            print(f"📊 VPN Overhead:      {overhead:.2f}s ({overhead_pct:.1f}%)")
            print(f"\n💡 The VPN adds encryption/decryption overhead and routing latency")
            print(f"🔐 In exchange, all traffic is encrypted end-to-end with AES-256-GCM")
        else:
            print(f"❌ Could not complete full comparison")
        
        print(f"\n{'#'*60}\n")


def main():
    """Main entry point."""
    server_host = os.getenv('SERVER_HOST', 'server')
    server_port = int(os.getenv('SERVER_PORT', 8443))
    test_url = os.getenv('TEST_URL', 'https://speed.cloudflare.com/__down?bytes=500000000')
    startup_delay = int(os.getenv('STARTUP_DELAY', 3))
    
    print(f"⏳ Waiting {startup_delay}s for server to start...")
    time.sleep(startup_delay)
    
    client = SafeGuardClient(server_host, server_port)
    
    try:
        # Connect to VPN
        if not client.connect():
            print("❌ Failed to establish VPN connection")
            sys.exit(1)
        
        time.sleep(1)
        
        # Run performance test
        client.run_performance_test(test_url)
        
    finally:
        client.close()


if __name__ == '__main__':
    main()
