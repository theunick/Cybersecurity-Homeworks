# SafeGuard VPN Protocol

A cryptographically secure Virtual Private Network implementation using a custom SafeGuard protocol.

## 🎯 Project Overview

This project implements a VPN system where a client (C) and server (S) establish a secure tunnel for encrypted communication over the network. The SafeGuard protocol uses modern cryptographic primitives to ensure confidentiality, integrity, and authentication.

## 🔐 Security Features

- **Key Exchange**: Elliptic Curve Diffie-Hellman (ECDH) with Curve25519
- **Symmetric Encryption**: AES-256-GCM for tunnel traffic
- **Authentication**: HMAC-SHA256 for message authentication
- **Perfect Forward Secrecy**: New session keys for each connection
- **Nonce-based Security**: Random nonces prevent replay attacks

## 🏗️ Architecture

```
HW09/
├── client/
│   ├── Dockerfile         # Client container configuration
│   └── client.py         # VPN client implementation
├── server/
│   ├── Dockerfile         # Server container configuration
│   └── server.py         # VPN server implementation
├── shared/
│   └── protocol.py       # Shared protocol and crypto logic
├── docker-compose.yml    # Orchestration configuration
├── Makefile             # Build and run commands
└── README.md            # This file
```

## 📋 Requirements

- Docker Desktop (installed and running)
- Python 3.11+ (for local testing, not required for Docker)

## 🚀 Quick Start

### Using Make (Recommended)

```bash
# Build Docker images
make build

# Run the VPN demo
make test

# View logs
make logs

# Cleanup
make clean-docker
```

### Using Docker Compose Directly

```bash
# Build and run
docker-compose up --build

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## 🔒 SafeGuard Protocol Flow

### Phase 1 - Handshake & Key Exchange

1. **Client Initiation**
   - Client generates ephemeral ECDH key pair
   - Client sends public key to server
   - Client computes nonce for freshness

2. **Server Response**
   - Server generates ephemeral ECDH key pair
   - Server sends public key to client
   - Both parties compute shared secret using ECDH

3. **Key Derivation**
   - Shared secret is used to derive:
     - Encryption key (AES-256)
     - MAC key (HMAC-SHA256)
   - Uses HKDF (HMAC-based Key Derivation Function)

### Phase 2 - Secure Tunnel

4. **Encrypted Communication**
   - All traffic encrypted with AES-256-GCM
   - Each message includes:
     - Nonce (96-bit random value)
     - Ciphertext (encrypted payload)
     - Authentication tag (128-bit GCM tag)

5. **Traffic Forwarding**
   - Client wraps HTTP requests in VPN tunnel
   - Server decrypts, forwards to destination
   - Server encrypts response, sends back to client
   - Client decrypts and delivers to application

### Why This is Secure

- **Confidentiality**: AES-256-GCM ensures data cannot be read by eavesdroppers
- **Integrity**: GCM authentication tag ensures data hasn't been modified
- **Forward Secrecy**: Ephemeral keys mean past sessions cannot be decrypted even if long-term keys are compromised
- **Authentication**: HMAC ensures messages come from the expected party
- **Replay Protection**: Nonces prevent replay attacks

## 🛠️ Configuration

Environment variables in `docker-compose.yml`:

### Server Configuration
- `SERVER_HOST`: Bind address (default: 0.0.0.0)
- `SERVER_PORT`: VPN server port (default: 8443)

### Client Configuration
- `SERVER_HOST`: VPN server hostname (default: server)
- `SERVER_PORT`: VPN server port (default: 8443)
- `TEST_URL`: URL for performance test (default: https://speed.cloudflare.com/...)

## 📊 Performance Testing

The project includes automated performance testing comparing:
- Direct connection (no VPN)
- VPN connection (tunneled through SafeGuard)

### Test Command
```bash
curl -o /dev/null -w "%{time_total}\n" \
  "https://speed.cloudflare.com/__down?bytes=500000000"
```

### Expected Results
- VPN adds encryption/decryption overhead
- Network latency may be affected by tunneling
- Results vary based on network conditions and system resources

## 🔬 Cryptographic Principles

### 1. Elliptic Curve Diffie-Hellman (ECDH)
- Uses Curve25519 for optimal security and performance
- Provides 128-bit security level
- Faster than traditional DH with equivalent security

### 2. AES-256-GCM
- Authenticated encryption mode
- Provides both confidentiality and authenticity
- GCM (Galois/Counter Mode) is highly efficient

### 3. Key Derivation (HKDF)
- Expands shared ECDH secret into multiple keys
- Uses cryptographic hash function (SHA-256)
- Ensures keys are cryptographically independent

### 4. Perfect Forward Secrecy
- Each session uses ephemeral keys
- Compromise of one session doesn't affect others
- Keys are never stored, only used for active session

## 📝 Implementation Details

### Client (client.py)
- Establishes connection to VPN server
- Performs key exchange
- Encrypts outgoing traffic
- Decrypts incoming traffic
- Runs performance benchmarks

### Server (server.py)
- Listens for client connections
- Performs key exchange
- Decrypts incoming traffic
- Forwards to destination (acts as proxy)
- Encrypts responses back to client

### Shared Protocol (shared/protocol.py)
- `SafeGuardProtocol`: Main protocol implementation
- `KeyExchange`: ECDH key exchange logic
- `SymmetricCrypto`: AES-256-GCM encryption/decryption
- `KeyDerivation`: HKDF-based key derivation
- Network message serialization/deserialization

## 🧪 Testing

```bash
# Run full test suite
make test

# Run with verbose logging
make test-verbose

# Performance test only
make benchmark
```

## 🐛 Troubleshooting

### Connection Issues
- Ensure Docker is running
- Check firewall settings
- Verify network connectivity between containers

### Performance Issues
- Check system resources (CPU, memory)
- Verify network bandwidth
- Consider adjusting encryption parameters

## 📚 References

- RFC 7748: Elliptic Curves for Security (Curve25519)
- NIST SP 800-38D: Galois/Counter Mode (GCM)
- RFC 5869: HMAC-based Key Derivation Function (HKDF)
- RFC 4493: The AES-CMAC Algorithm

## 📄 License

Academic project for Cybersecurity course - Nicolas Leone (1986354)
