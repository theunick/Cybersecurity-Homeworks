#!/usr/bin/env python3
"""
Extract certificates from PAdES-signed PDF
Author: Nicolas Leone (1986354)
"""

import sys
from pathlib import Path

try:
    from PyPDF2 import PdfReader
except ImportError:
    print("PyPDF2 not installed. Installing...")
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "PyPDF2"], check=True)
    from PyPDF2 import PdfReader

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("cryptography not installed. Installing...")
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "cryptography"], check=True)
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization


def extract_certificates_from_pdf(pdf_path):
    """Extract certificates from a signed PDF"""
    
    pdf_path = Path(pdf_path)
    reader = PdfReader(str(pdf_path))
    
    # Look for signature in Acroform
    if '/AcroForm' not in reader.trailer['/Root']:
        print("No AcroForm found in PDF")
        return []
    
    acroform = reader.trailer['/Root']['/AcroForm']
    
    if '/Fields' not in acroform:
        print("No fields in AcroForm")
        return []
    
    certificates = []
    
    # Iterate through fields
    fields = acroform['/Fields']
    for field_ref in fields:
        field = field_ref.get_object()
        
        # Check if it's a signature field
        if field.get('/FT') == '/Sig' and '/V' in field:
            sig_dict = field['/V']
            
            # Try to extract certificate from Contents
            if '/Contents' in sig_dict:
                contents = sig_dict['/Contents']
                
                # The contents is typically the PKCS#7 signature
                # We need to parse it to extract certificates
                try:
                    cert_data = bytes(contents)
                    # Save the raw signature
                    sig_file = "signature.p7s"
                    with open(sig_file, 'wb') as f:
                        f.write(cert_data)
                    print(f"✅ Extracted signature to {sig_file}")
                    certificates.append(sig_file)
                except Exception as e:
                    print(f"Error extracting signature: {e}")
    
    return certificates


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_certs.py <signed_pdf>")
        sys.exit(1)
    
    pdf_file = sys.argv[1]
    
    print("Extracting certificates from PDF...")
    certs = extract_certificates_from_pdf(pdf_file)
    
    if certs:
        print(f"\n✅ Extracted {len(certs)} signature(s)")
        
        # Now use OpenSSL to extract certificates from PKCS#7
        print("\nExtracting certificates from PKCS#7 signature...")
        import subprocess
        
        for i, sig_file in enumerate(certs):
            out_file = f"certs_chain.pem"
            result = subprocess.run(
                ["openssl", "pkcs7", "-inform", "DER", "-in", sig_file, 
                 "-print_certs", "-out", out_file],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"✅ Extracted certificates to {out_file}")
                
                # Split the PEM file into individual certificates
                with open(out_file, 'r') as f:
                    pem_data = f.read()
                
                certs_list = pem_data.split('-----BEGIN CERTIFICATE-----')
                cert_num = 0
                for cert in certs_list[1:]:  # Skip empty first element
                    cert_content = '-----BEGIN CERTIFICATE-----' + cert
                    cert_file = f"cert_{cert_num}.pem"
                    with open(cert_file, 'w') as f:
                        f.write(cert_content)
                    print(f"📜 Saved certificate #{cert_num} to {cert_file}")
                    cert_num += 1
            else:
                print(f"❌ Error: {result.stderr}")
    else:
        print("❌ No signatures found")


if __name__ == '__main__':
    main()
