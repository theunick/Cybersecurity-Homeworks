# Homework 08: Digital Signature Verification

Analysis of PAdES-signed PDF documents with focus on certificate chain extraction, X.509 field analysis, CRL update intervals, and OCSP verification.

## Overview

This homework implements a comprehensive digital signature verification system for PAdES (PDF Advanced Electronic Signatures) documents. The analysis includes:

- Complete checklist for digital signature verification
- Certificate chain extraction from signed PDFs
- Detailed X.509 certificate field analysis
- CRL (Certificate Revocation List) update interval determination
- OCSP (Online Certificate Status Protocol) real-time verification

## Files

- `HW08_Nicolas_Leone_1986354.tex` - LaTeX report with complete analysis
- `analyze_signature.py` - Main analysis script for signature verification
- `extract_certs.py` - Certificate extraction utility
- `Makefile` - Build automation
- `test_signed.pdf` - Sample PAdES-signed document
- `analysis_results.txt` - Summary of verification results

## Requirements

### System Tools
```bash
# macOS
brew install poppler openssl

# Ubuntu/Debian
sudo apt-get install poppler-utils openssl
```

### Python Dependencies
```bash
pip3 install PyPDF2 cryptography
```

## Usage

### Complete Analysis
```bash
make all          # Run analysis and compile PDF report
make analyze      # Run signature verification only
make pdf          # Compile LaTeX document only
```

### Individual Operations
```bash
make certs        # Extract certificate chain
make ocsp         # Query OCSP responder
make crl          # Download and analyze CRL
```

### Cleanup
```bash
make clean        # Remove temporary files
make cleanall     # Remove all generated files
```

## Analysis Results

The analysis of `test_signed.pdf` revealed:

### Signature Verification
- ✅ **Valid Signature** - Mathematically correct and verified
- ✅ **Document Integrity** - No modifications after signing
- 🔐 **Algorithm**: SHA-256 with RSA
- 📅 **Signed**: December 8, 2025 15:49:26
- 🏛️ **Type**: ETSI.CAdES.detached (PAdES compliant)

### Certificate Details
- **Subject**: Fabrizio d'Amore (TINIT-DMRFRZ60P04H501I)
- **Issuer**: ArubaPEC EU Qualified Certificates CA G1
- **Validity**: Nov 5, 2024 → Nov 5, 2027
- **Key Usage**: Non-Repudiation (critical)
- **Certificate Type**: eIDAS Qualified Certificate
- **Key Size**: RSA 2048-bit

### Revocation Status
- ✅ **CRL Status**: NOT REVOKED
- ✅ **OCSP Status**: GOOD
- 🔄 **Update Interval**: 24 hours (both CRL and OCSP)
- 📡 **CRL URL**: http://crl01.pec.it/va/arubapec-eidas-g1/crl
- 🌐 **OCSP URL**: http://ocsp01.pec.it/va/arubapec-eidas-g1

## Digital Signature Verification Checklist

### 1. Signature Integrity
- [x] Verify digital signature is mathematically correct
- [x] Confirm document has not been modified after signing
- [x] Validate computed hash matches signed hash

### 2. Certificate Validation
- [x] Extract and validate complete certificate chain
- [x] Check certificate was valid at signing time
- [x] Verify certificate has correct key usage extensions
- [x] Ensure certificate is in valid X.509 format

### 3. Revocation Status
- [x] Verify certificate against CRL
- [x] Ensure CRL is current and not expired
- [x] Query OCSP responder for real-time status
- [x] Verify OCSP response signature and freshness

### 4. Trust Validation
- [x] Verify root CA (requires manual trust store verification)
- [x] Check certificate policy compliance (eIDAS)
- [x] Validate name constraints

### 5. Timestamp Verification
- [x] Validate signing time is within certificate validity

### 6. PAdES-Specific Checks
- [x] Verify conformance to PAdES standards
- [x] Validate PDF signature dictionary
- [x] Check signature type (ETSI.CAdES.detached)

## X.509 Certificate Fields

### Standard Fields
- **Version**: 3 (X.509v3)
- **Serial Number**: 60:7e:88:fc:e0:f3:c5:00:7c:11:11:2d:90:20:46:a5
- **Signature Algorithm**: sha256WithRSAEncryption
- **Issuer DN**: C=IT, L=Arezzo, O=ArubaPEC S.p.A., CN=ArubaPEC EU Qualified Certificates CA G1
- **Subject DN**: C=IT, SN=d'Amore, GN=Fabrizio, serialNumber=TINIT-DMRFRZ60P04H501I, CN=Fabrizio d'Amore

### Extensions
- **Key Usage** (critical): Non Repudiation
- **Authority Information Access**:
  - CA Issuers: http://cacert.pec.it/certs/arubapec-eidas-g1
  - OCSP: http://ocsp01.pec.it/va/arubapec-eidas-g1
- **CRL Distribution Points**: http://crl01.pec.it/va/arubapec-eidas-g1/crl
- **Certificate Policies**: Includes eIDAS qualified certificate policies
- **QC Statements**: Qualified Certificate under eIDAS Regulation

## CRL Update Interval

The Certificate Revocation List (CRL) for this certificate has the following update characteristics:

- **Last Update**: December 16, 2025 14:48:13 GMT
- **Next Update**: December 17, 2025 14:48:13 GMT
- **Update Interval**: 24 hours

This means the CRL is updated daily, ensuring revocation information is reasonably fresh while balancing server load and network traffic.

## OCSP Response Analysis

OCSP provides real-time certificate status verification:

- **Response Status**: Successful
- **Certificate Status**: GOOD (not revoked)
- **This Update**: December 16, 2025 14:48:13 GMT
- **Next Update**: December 17, 2025 14:48:13 GMT
- **Response Produced**: December 16, 2025 15:06:28 GMT
- **Update Interval**: 24 hours (synchronized with CRL)

The OCSP responder uses the same 24-hour update cycle as the CRL, providing consistent revocation information across both verification methods.

## Security Considerations

### Strengths
- Strong cryptographic algorithms (SHA-256, RSA-2048)
- eIDAS Qualified Certificate provides legal standing
- Non-repudiation ensures signer cannot deny signing
- Dual revocation checking (CRL + OCSP)
- Regular updates (24-hour cycle)

### Limitations
- Root CA trust requires manual verification
- 24-hour CRL/OCSP update interval means newly revoked certificates may not be detected immediately
- Requires active internet connection for revocation checking

## References

- ETSI EN 319 142-1: PAdES Digital Signatures
- RFC 5280: X.509 PKI Certificate and CRL Profile
- RFC 6960: X.509 OCSP
- eIDAS Regulation (EU) No 910/2014
- ISO 32000: PDF Specification

## Author

Nicolas Leone (1986354)  
Cybersecurity - Sapienza University of Rome
