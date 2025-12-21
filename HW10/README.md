# TLS Configuration Analysis

Comprehensive technical assessment of server-side TLS configurations using OpenSSL client-side tools and online analysis platforms.

## 🎯 Project Overview

This project performs an in-depth security analysis of TLS/SSL configurations on web servers, combining protocol-level inspection with policy-based evaluation. The analysis compares manual OpenSSL inspection results with automated assessment tools like SSL Labs.

## 🔐 Analysis Components

### Protocol-Level Analysis (OpenSSL)
- **TLS Version Negotiation**: Protocol versions supported and negotiated
- **Cipher Suite Selection**: Symmetric encryption, MAC, and key exchange algorithms
- **Certificate Chain Validation**: X.509 certificate hierarchy and trust paths
- **Extension Support**: ALPN, SNI, OCSP stapling, session tickets

### Policy-Based Evaluation (SSL Labs)
- **Overall Security Rating**: Letter grade (A+ to F)
- **Protocol Support Assessment**: Evaluation of enabled TLS/SSL versions
- **Cipher Strength Analysis**: Key sizes, algorithm security
- **Configuration Best Practices**: Industry standards compliance

## 🏗️ Architecture

```
HW10/
├── analyze_tls.py              # Main TLS analysis script
├── ssllabs_check.py            # SSL Labs API integration
├── results/
│   ├── openssl_analysis.txt    # OpenSSL command outputs
│   ├── ssllabs_results.json    # SSL Labs API results
│   └── comparison.txt          # Side-by-side comparison
├── Makefile                    # Build automation
├── README.md                   # This file
└── HW10_Nicolas_Leone_1986354.tex
```

## 📋 Requirements

### System Tools
```bash
# OpenSSL (usually pre-installed on macOS/Linux)
openssl version

# Python 3.11+
python3 --version
```

### Python Dependencies
```bash
pip3 install requests cryptography
```

## 🚀 Quick Start

### Using Make (Recommended)

```bash
# Run complete TLS analysis
make analyze

# Query SSL Labs only
make ssllabs

# Compile PDF report
make pdf

# Run all analyses and generate PDF
make all
```

### Manual Execution

```bash
# Analyze specific server with OpenSSL
python3 analyze_tls.py www.example.com

# Check SSL Labs rating
python3 ssllabs_check.py www.example.com

# Custom port
python3 analyze_tls.py www.example.com:8443
```

## 🔍 Analysis Scope

### 1. TLS Version and Cipher Suite

**OpenSSL Analysis:**
```bash
openssl s_client -connect server:443 -tls1_3
openssl s_client -connect server:443 -tls1_2
```

Examines:
- Highest TLS version supported (1.3, 1.2, 1.1, 1.0)
- Negotiated cipher suite components:
  - Key exchange (ECDHE, DHE, RSA)
  - Authentication (RSA, ECDSA)
  - Encryption (AES-GCM, ChaCha20-Poly1305)
  - Hash function (SHA256, SHA384)

### 2. Key Exchange and Forward Secrecy

**Forward Secrecy Analysis:**
- Ephemeral key exchange (ECDHE, DHE) vs. static (RSA)
- Curve selection for ECDHE (X25519, P-256, P-384)
- DH group parameters and key sizes

**Security Implications:**
- Perfect Forward Secrecy (PFS) protection
- Resistance to key compromise

### 3. Certificate Chain Validation

**Certificate Hierarchy:**
- End-entity (server) certificate
- Intermediate CA certificates
- Root CA (trust anchor)

**Validation Checks:**
- Certificate validity period
- Chain of trust completeness
- Signature algorithms (RSA-SHA256, ECDSA-SHA384)
- Key usage extensions
- Subject Alternative Names (SANs)

### 4. ALPN and OCSP Stapling

**Application-Layer Protocol Negotiation (ALPN):**
- HTTP/2 (h2) support
- HTTP/1.1 fallback

**Online Certificate Status Protocol (OCSP) Stapling:**
- Certificate revocation status
- Privacy and performance benefits
- Stapled response validation

## 📊 Analysis Results

### Example Server Analysis

**Target:** `www.google.com`

#### OpenSSL Results
```
TLS Version: TLSv1.3
Cipher Suite: TLS_AES_256_GCM_SHA384
Key Exchange: X25519
Server Certificate: CN=*.google.com
Certificate Chain: 2 certificates (Google Trust Services)
ALPN: h2, http/1.1
OCSP Stapling: Yes
```

#### SSL Labs Results
```
Overall Rating: A+
Certificate: 100/100
Protocol Support: 100/100
Key Exchange: 90/100
Cipher Strength: 90/100
```

#### Comparison Analysis
- **Consistency**: Both tools confirm TLSv1.3 support
- **Discrepancies**: SSL Labs considers broader attack scenarios
- **Security Posture**: Excellent - modern protocols, strong ciphers, PFS enabled

## 🔬 Technical Analysis

### TLS Handshake Inspection

```bash
# Verbose handshake analysis
openssl s_client -connect server:443 -state -debug

# Extract specific information
openssl s_client -connect server:443 < /dev/null 2>&1 | \
  openssl x509 -noout -text
```

### Cipher Suite Testing

```bash
# Test specific cipher
openssl s_client -connect server:443 -cipher 'ECDHE-RSA-AES256-GCM-SHA384'

# List all supported ciphers
nmap --script ssl-enum-ciphers -p 443 server
```

## 🛡️ Security Evaluation Criteria

### Protocol Security
- ✅ TLS 1.3 or 1.2 only
- ❌ SSLv3, TLS 1.0, TLS 1.1 (deprecated/insecure)

### Cipher Suite Security
- ✅ AEAD ciphers (GCM, ChaCha20-Poly1305)
- ✅ Ephemeral key exchange (ECDHE, DHE)
- ❌ CBC mode ciphers (vulnerable to padding oracle)
- ❌ RC4, DES, 3DES (weak encryption)
- ❌ Static RSA key exchange (no forward secrecy)

### Certificate Security
- ✅ 2048-bit RSA or 256-bit ECDSA minimum
- ✅ SHA-256 or better signature algorithm
- ✅ Valid chain to trusted root CA
- ❌ MD5, SHA-1 signatures (collision vulnerable)
- ❌ Self-signed certificates (untrusted)

## 📈 Comparison Methodology

### Protocol-Level vs. Policy-Based

**OpenSSL (Protocol-Level):**
- Direct TLS handshake observation
- Actual negotiated parameters
- Real-time connection analysis
- Low-level protocol details

**SSL Labs (Policy-Based):**
- Comprehensive configuration scan
- Multiple protocol version tests
- Known vulnerability checks
- Best practice compliance scoring

**Discrepancy Analysis:**
- SSL Labs tests all supported versions; OpenSSL tests one connection
- SSL Labs considers legacy client compatibility
- SSL Labs applies security policies and known attack scenarios
- OpenSSL shows actual deployed behavior

## 🔧 Troubleshooting

### Connection Issues
```bash
# Test connectivity
curl -I https://server

# Check firewall/DNS
ping server
traceroute server
```

### Certificate Errors
```bash
# Ignore certificate verification (testing only)
openssl s_client -connect server:443 -no_verify

# Check certificate expiration
echo | openssl s_client -connect server:443 2>/dev/null | \
  openssl x509 -noout -dates
```

## 📚 References

- **RFC 8446**: The Transport Layer Security (TLS) Protocol Version 1.3
- **RFC 5246**: The Transport Layer Security (TLS) Protocol Version 1.2
- **RFC 7540**: Hypertext Transfer Protocol Version 2 (HTTP/2)
- **RFC 6066**: Transport Layer Security (TLS) Extensions
- **NIST SP 800-52 Rev. 2**: Guidelines for TLS Implementations
- **SSL Labs Best Practices**: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices

## 📄 Report Structure

The technical report includes:

1. **Executive Summary**: Overall security posture assessment
2. **Methodology**: Analysis approach and tools used
3. **OpenSSL Analysis**: Protocol-level inspection results
4. **SSL Labs Analysis**: Policy-based evaluation results
5. **Comparative Analysis**: Discrepancies and their implications
6. **Security Recommendations**: Configuration improvements
7. **Conclusions**: Final assessment and takeaways

## 🎓 Academic Context

**Course**: Cybersecurity  
**Student**: Nicolas Leone (1986354)  
**Assignment**: HW10 - TLS Configuration Analysis

---

*This analysis demonstrates practical application of TLS/SSL security principles, certificate chain validation, and the importance of comprehensive security assessment using multiple methodologies.*
