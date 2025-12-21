"""
SafeGuard VPN Protocol
Implements a cryptographically secure VPN protocol with ECDH key exchange,
AES-256-GCM encryption, and perfect forward secrecy.
"""

import hashlib
import secrets
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Protocol message types
MSG_CLIENT_HELLO = "CLIENT_HELLO"
MSG_SERVER_HELLO = "SERVER_HELLO"
MSG_DATA = "DATA"
MSG_ERROR = "ERROR"
MSG_CLOSE = "CLOSE"

# Cryptographic constants
NONCE_SIZE = 12  # 96 bits for AES-GCM
KEY_SIZE = 32    # 256 bits for AES-256
TAG_SIZE = 16    # 128 bits for GCM authentication tag


class KeyExchange:
    """
    Implements Elliptic Curve Diffie-Hellman (ECDH) key exchange using Curve25519.
    
    Properties:
    - Forward Secrecy: New ephemeral keys for each session
    - Security: 128-bit security level (equivalent to 3072-bit RSA)
    - Performance: Faster than traditional DH
    """
    
    def __init__(self):
        """Generate ephemeral ECDH key pair."""
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self):
        """Get public key as bytes for transmission."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def compute_shared_secret(self, peer_public_key_bytes):
        """
        Compute shared secret using ECDH.
        
        Args:
            peer_public_key_bytes: Peer's public key (32 bytes)
            
        Returns:
            Shared secret (32 bytes)
        """
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret


class KeyDerivation:
    """
    Implements HKDF (HMAC-based Key Derivation Function).
    
    Derives multiple cryptographically independent keys from a shared secret.
    Uses SHA-256 as the underlying hash function.
    """
    
    @staticmethod
    def derive_keys(shared_secret, salt=None, info=b"SafeGuard VPN v1.0"):
        """
        Derive encryption and MAC keys from shared secret.
        
        Args:
            shared_secret: ECDH shared secret
            salt: Optional salt (uses random if None)
            info: Context information
            
        Returns:
            Tuple (encryption_key, mac_key)
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for encryption + 32 bytes for MAC
            salt=salt,
            info=info,
            backend=default_backend()
        )
        
        key_material = hkdf.derive(shared_secret)
        encryption_key = key_material[:32]  # AES-256 key
        mac_key = key_material[32:]         # HMAC key
        
        return encryption_key, mac_key, salt


class SymmetricCrypto:
    """
    Implements AES-256-GCM for authenticated encryption.
    
    Properties:
    - Confidentiality: AES-256 encryption
    - Integrity: GCM authentication tag
    - Efficiency: Hardware-accelerated on modern CPUs
    """
    
    def __init__(self, key):
        """
        Initialize AES-GCM cipher.
        
        Args:
            key: 256-bit encryption key
        """
        self.cipher = AESGCM(key)
    
    def encrypt(self, plaintext, associated_data=None):
        """
        Encrypt data with AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt (bytes)
            associated_data: Additional authenticated data (optional)
            
        Returns:
            Tuple (nonce, ciphertext) - ciphertext includes auth tag
        """
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = self.cipher.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    
    def decrypt(self, nonce, ciphertext, associated_data=None):
        """
        Decrypt data with AES-256-GCM.
        
        Args:
            nonce: Nonce used for encryption
            ciphertext: Encrypted data (includes auth tag)
            associated_data: Additional authenticated data (optional)
            
        Returns:
            Decrypted plaintext
            
        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        plaintext = self.cipher.decrypt(nonce, ciphertext, associated_data)
        return plaintext


class SafeGuardProtocol:
    """
    Main SafeGuard VPN protocol implementation.
    
    Handles key exchange, session setup, and encrypted communication.
    """
    
    def __init__(self):
        self.key_exchange = None
        self.symmetric_crypto = None
        self.session_established = False
        self.peer_public_key = None
    
    def initiate_handshake(self):
        """
        Initiate handshake as client.
        
        Returns:
            CLIENT_HELLO message with public key
        """
        self.key_exchange = KeyExchange()
        public_key_bytes = self.key_exchange.get_public_key_bytes()
        
        return create_message(
            MSG_CLIENT_HELLO,
            public_key=public_key_bytes.hex(),
            nonce=secrets.token_hex(16)
        )
    
    def respond_handshake(self, client_hello_msg):
        """
        Respond to handshake as server.
        
        Args:
            client_hello_msg: Parsed CLIENT_HELLO message
            
        Returns:
            SERVER_HELLO message with public key
        """
        self.key_exchange = KeyExchange()
        
        # Get client's public key
        client_public_key = bytes.fromhex(client_hello_msg['data']['public_key'])
        self.peer_public_key = client_public_key
        
        # Compute shared secret and derive keys
        shared_secret = self.key_exchange.compute_shared_secret(client_public_key)
        encryption_key, mac_key, salt = KeyDerivation.derive_keys(shared_secret)
        
        # Initialize symmetric crypto
        self.symmetric_crypto = SymmetricCrypto(encryption_key)
        self.session_established = True
        
        # Send server's public key
        server_public_key = self.key_exchange.get_public_key_bytes()
        
        return create_message(
            MSG_SERVER_HELLO,
            public_key=server_public_key.hex(),
            salt=salt.hex()
        )
    
    def complete_handshake(self, server_hello_msg):
        """
        Complete handshake as client.
        
        Args:
            server_hello_msg: Parsed SERVER_HELLO message
        """
        # Get server's public key
        server_public_key = bytes.fromhex(server_hello_msg['data']['public_key'])
        salt = bytes.fromhex(server_hello_msg['data']['salt'])
        self.peer_public_key = server_public_key
        
        # Compute shared secret and derive keys
        shared_secret = self.key_exchange.compute_shared_secret(server_public_key)
        encryption_key, mac_key, _ = KeyDerivation.derive_keys(shared_secret, salt=salt)
        
        # Initialize symmetric crypto
        self.symmetric_crypto = SymmetricCrypto(encryption_key)
        self.session_established = True
    
    def encrypt_data(self, data):
        """
        Encrypt data for transmission through VPN tunnel.
        
        Args:
            data: Plaintext data (bytes)
            
        Returns:
            Encrypted DATA message
        """
        if not self.session_established:
            raise RuntimeError("Session not established")
        
        nonce, ciphertext = self.symmetric_crypto.encrypt(data)
        
        return create_message(
            MSG_DATA,
            nonce=nonce.hex(),
            ciphertext=ciphertext.hex()
        )
    
    def decrypt_data(self, data_msg):
        """
        Decrypt data received through VPN tunnel.
        
        Args:
            data_msg: Parsed DATA message
            
        Returns:
            Decrypted plaintext (bytes)
        """
        if not self.session_established:
            raise RuntimeError("Session not established")
        
        nonce = bytes.fromhex(data_msg['data']['nonce'])
        ciphertext = bytes.fromhex(data_msg['data']['ciphertext'])
        
        plaintext = self.symmetric_crypto.decrypt(nonce, ciphertext)
        return plaintext


def create_message(msg_type, **kwargs):
    """
    Create a protocol message.
    
    Args:
        msg_type: Type of message
        **kwargs: Message-specific data
        
    Returns:
        JSON-encoded message string
    """
    message = {"type": msg_type, "data": kwargs}
    return json.dumps(message)


def parse_message(message_str):
    """
    Parse a protocol message.
    
    Args:
        message_str: JSON-encoded message string
        
    Returns:
        Dictionary with 'type' and 'data' keys
    """
    try:
        message = json.loads(message_str)
        if "type" not in message or "data" not in message:
            raise ValueError("Invalid message format")
        return message
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse message: {e}")


def send_message(sock, msg_type, **kwargs):
    """Send a protocol message over a socket."""
    message = create_message(msg_type, **kwargs)
    message_bytes = message.encode('utf-8')
    length_prefix = len(message_bytes).to_bytes(4, 'big')
    sock.sendall(length_prefix + message_bytes)


def receive_message(sock):
    """Receive a protocol message from a socket."""
    # Read length prefix
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    
    message_length = int.from_bytes(length_bytes, 'big')
    
    # Read message
    message_bytes = b''
    while len(message_bytes) < message_length:
        chunk = sock.recv(min(4096, message_length - len(message_bytes)))
        if not chunk:
            raise ConnectionError("Connection closed while receiving message")
        message_bytes += chunk
    
    message_str = message_bytes.decode('utf-8')
    return parse_message(message_str)
