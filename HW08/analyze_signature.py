#!/usr/bin/env python3
"""
Digital Signature Analysis Tool
Analyzes PAdES-signed PDF documents and extracts certificate information
Author: Nicolas Leone (1986354)
"""

import sys
import os
import argparse
import subprocess
from datetime import datetime
from pathlib import Path


class SignatureAnalyzer:
    """Analyzes digital signatures in PDF documents"""
    
    def __init__(self, pdf_path):
        self.pdf_path = Path(pdf_path)
        if not self.pdf_path.exists():
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
        
        self.cert_dir = Path(".")
        self.certs = []
        
    def run_command(self, cmd, capture_output=True):
        """Run a shell command and return output"""
        try:
            if capture_output:
                result = subprocess.run(
                    cmd, 
                    shell=True, 
                    capture_output=True, 
                    text=True,
                    check=False
                )
                return result.returncode, result.stdout, result.stderr
            else:
                result = subprocess.run(cmd, shell=True, check=False)
                return result.returncode, "", ""
        except Exception as e:
            return -1, "", str(e)
    
    def check_dependencies(self):
        """Check if required tools are available"""
        tools = {
            'pdfsig': 'poppler-utils',
            'openssl': 'openssl'
        }
        
        missing = []
        for tool, package in tools.items():
            returncode, _, _ = self.run_command(f"which {tool}")
            if returncode != 0:
                missing.append(f"{tool} (install: {package})")
        
        if missing:
            print("⚠️  Missing required tools:")
            for tool in missing:
                print(f"   - {tool}")
            print("\nOn macOS, install with:")
            print("   brew install poppler openssl")
            return False
        return True
    
    def verify_signature(self):
        """Verify the PDF signature using pdfsig"""
        print("\n" + "="*80)
        print("SIGNATURE VERIFICATION")
        print("="*80)
        
        returncode, stdout, stderr = self.run_command(f"pdfsig {self.pdf_path}")
        
        if returncode == 0:
            print(stdout)
            return True
        else:
            print(f"❌ Error verifying signature: {stderr}")
            return False
    
    def extract_certificates(self):
        """Extract certificates from the signed PDF"""
        print("\n" + "="*80)
        print("CERTIFICATE CHAIN EXTRACTION")
        print("="*80)
        
        # First, try to use pdfsig to dump certificates
        returncode, stdout, stderr = self.run_command(
            f"pdfsig -dump {self.pdf_path}"
        )
        
        if returncode == 0 and "Certificate #" in stdout:
            print("✅ Certificates found in PDF")
            print(stdout)
            
            # Parse output to find certificate files
            for line in stdout.split('\n'):
                if line.strip().startswith("Saved as:"):
                    cert_file = line.split("Saved as:")[1].strip()
                    if os.path.exists(cert_file):
                        self.certs.append(cert_file)
                        print(f"📜 Found certificate: {cert_file}")
        else:
            print("⚠️  Could not extract certificates with pdfsig")
            print("Trying alternative method...")
            
            # Alternative: try to extract from signature dictionary
            self._extract_certs_alternative()
        
        return len(self.certs) > 0
    
    def _extract_certs_alternative(self):
        """Alternative method to extract certificates"""
        # This would require PyPDF2 or similar library
        # For now, we'll note that manual extraction may be needed
        print("ℹ️  Alternative extraction methods:")
        print("   1. Use Adobe Acrobat to export certificates")
        print("   2. Use PDFtk or qpdf to extract signature objects")
        print("   3. Parse PDF structure manually with PyPDF2")
    
    def analyze_certificate(self, cert_path):
        """Analyze a single certificate"""
        print(f"\n{'='*80}")
        print(f"CERTIFICATE ANALYSIS: {cert_path}")
        print('='*80)
        
        # Convert DER to PEM if needed
        pem_path = cert_path
        if cert_path.endswith('.der'):
            pem_path = cert_path.replace('.der', '.pem')
            returncode, _, _ = self.run_command(
                f"openssl x509 -inform DER -in {cert_path} -outform PEM -out {pem_path}"
            )
            if returncode != 0:
                print(f"❌ Could not convert certificate to PEM format")
                return
        
        # Display certificate in text format
        returncode, stdout, stderr = self.run_command(
            f"openssl x509 -in {pem_path} -text -noout"
        )
        
        if returncode == 0:
            print(stdout)
            
            # Extract specific fields
            self._extract_key_fields(pem_path)
        else:
            print(f"❌ Error analyzing certificate: {stderr}")
    
    def _extract_key_fields(self, cert_path):
        """Extract and display key certificate fields"""
        print("\n" + "-"*80)
        print("KEY FIELDS SUMMARY")
        print("-"*80)
        
        fields = {
            'Subject': '-subject',
            'Issuer': '-issuer',
            'Serial Number': '-serial',
            'Not Before': '-startdate',
            'Not After': '-enddate',
            'Subject Alternative Name': '-ext subjectAltName',
            'CRL Distribution Points': '-ext crlDistributionPoints',
            'OCSP URL': '-ocsp_uri',
        }
        
        for field_name, option in fields.items():
            returncode, stdout, stderr = self.run_command(
                f"openssl x509 -in {cert_path} -noout {option}"
            )
            if returncode == 0 and stdout.strip():
                print(f"\n{field_name}:")
                print(f"  {stdout.strip()}")
    
    def analyze_crl(self, cert_path):
        """Download and analyze CRL"""
        print("\n" + "="*80)
        print("CRL ANALYSIS")
        print("="*80)
        
        # Extract CRL distribution point
        returncode, stdout, stderr = self.run_command(
            f"openssl x509 -in {cert_path} -noout -ext crlDistributionPoints"
        )
        
        if returncode != 0 or not stdout.strip():
            print("❌ No CRL distribution point found in certificate")
            return
        
        print("CRL Distribution Points:")
        print(stdout)
        
        # Try to extract URL
        crl_url = None
        for line in stdout.split('\n'):
            if 'URI:' in line:
                crl_url = line.split('URI:')[1].strip()
                break
        
        if not crl_url:
            print("⚠️  Could not parse CRL URL")
            return
        
        print(f"\n📡 Downloading CRL from: {crl_url}")
        
        # Download CRL
        crl_file = "crl.der"
        returncode, _, _ = self.run_command(f"curl -s -o {crl_file} '{crl_url}'")
        
        if returncode != 0 or not os.path.exists(crl_file):
            print("❌ Failed to download CRL")
            return
        
        print("✅ CRL downloaded successfully")
        
        # Convert to PEM if needed
        returncode, _, _ = self.run_command(
            f"openssl crl -inform DER -in {crl_file} -outform PEM -out crl.pem"
        )
        
        # Analyze CRL
        print("\n" + "-"*80)
        print("CRL INFORMATION")
        print("-"*80)
        
        returncode, stdout, stderr = self.run_command(
            "openssl crl -in crl.pem -text -noout"
        )
        
        if returncode == 0:
            print(stdout)
            
            # Calculate update interval
            self._calculate_crl_interval(stdout)
        else:
            print(f"❌ Error analyzing CRL: {stderr}")
    
    def _calculate_crl_interval(self, crl_text):
        """Calculate CRL update interval from This Update and Next Update"""
        print("\n" + "-"*80)
        print("CRL UPDATE INTERVAL")
        print("-"*80)
        
        this_update = None
        next_update = None
        
        for line in crl_text.split('\n'):
            if 'Last Update:' in line or 'This Update:' in line:
                this_update = line.split(':', 1)[1].strip()
            elif 'Next Update:' in line:
                next_update = line.split(':', 1)[1].strip()
        
        if this_update and next_update:
            print(f"This Update: {this_update}")
            print(f"Next Update: {next_update}")
            
            # Try to calculate interval
            try:
                # OpenSSL format: "Nov 15 10:30:45 2024 GMT"
                fmt = "%b %d %H:%M:%S %Y %Z"
                this_dt = datetime.strptime(this_update, fmt)
                next_dt = datetime.strptime(next_update, fmt)
                interval = next_dt - this_dt
                
                print(f"\nUpdate Interval: {interval}")
                print(f"  Days: {interval.days}")
                print(f"  Hours: {interval.total_seconds() / 3600:.2f}")
            except Exception as e:
                print(f"⚠️  Could not calculate interval: {e}")
        else:
            print("⚠️  Could not find update timestamps in CRL")
    
    def check_ocsp(self, cert_path, issuer_path=None):
        """Query OCSP responder"""
        print("\n" + "="*80)
        print("OCSP CHECK")
        print("="*80)
        
        # Extract OCSP URL
        returncode, stdout, stderr = self.run_command(
            f"openssl x509 -in {cert_path} -noout -ocsp_uri"
        )
        
        if returncode != 0 or not stdout.strip():
            print("❌ No OCSP URL found in certificate")
            return
        
        ocsp_url = stdout.strip()
        print(f"OCSP Responder URL: {ocsp_url}")
        
        if not issuer_path:
            print("\n⚠️  Issuer certificate not provided")
            print("OCSP check requires the issuer certificate")
            print("Usage: provide issuer certificate path")
            return
        
        # Perform OCSP check
        print(f"\n📡 Querying OCSP responder...")
        
        cmd = f"openssl ocsp -issuer {issuer_path} -cert {cert_path} -url {ocsp_url} -resp_text"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0:
            print("\n" + "-"*80)
            print("OCSP RESPONSE")
            print("-"*80)
            print(stdout)
            
            # Save response
            with open("ocsp_response.txt", "w") as f:
                f.write(stdout)
            print("\n💾 OCSP response saved to: ocsp_response.txt")
        else:
            print(f"\n⚠️  OCSP query completed with warnings")
            print(stdout)
            if stderr:
                print(f"Errors: {stderr}")
    
    def full_analysis(self):
        """Perform complete analysis"""
        print("\n" + "="*80)
        print(f"DIGITAL SIGNATURE ANALYSIS: {self.pdf_path.name}")
        print("="*80)
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if not self.check_dependencies():
            return False
        
        # 1. Verify signature
        self.verify_signature()
        
        # 2. Extract certificates
        if not self.extract_certificates():
            print("\n❌ Could not extract certificates automatically")
            print("Please extract certificates manually and run analysis again")
            return False
        
        # 3. Analyze each certificate
        for cert_path in self.certs:
            self.analyze_certificate(cert_path)
        
        # 4. Analyze CRL (for first certificate)
        if self.certs:
            self.analyze_crl(self.certs[0])
        
        # 5. Check OCSP (if issuer available)
        if len(self.certs) >= 2:
            self.check_ocsp(self.certs[0], self.certs[1])
        elif len(self.certs) == 1:
            print("\n⚠️  Only one certificate found - cannot perform OCSP check")
            print("OCSP check requires both the subject and issuer certificates")
        
        print("\n" + "="*80)
        print("ANALYSIS COMPLETE")
        print("="*80)
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description='Analyze digital signatures in PAdES-signed PDF documents'
    )
    parser.add_argument(
        'pdf_file',
        help='Path to the signed PDF file'
    )
    parser.add_argument(
        '--extract-certs',
        action='store_true',
        help='Extract certificates only'
    )
    parser.add_argument(
        '--ocsp',
        action='store_true',
        help='Check OCSP status only'
    )
    parser.add_argument(
        '--crl',
        action='store_true',
        help='Analyze CRL only'
    )
    
    args = parser.parse_args()
    
    try:
        analyzer = SignatureAnalyzer(args.pdf_file)
        
        if args.extract_certs:
            analyzer.extract_certificates()
        elif args.ocsp:
            analyzer.extract_certificates()
            if len(analyzer.certs) >= 2:
                analyzer.check_ocsp(analyzer.certs[0], analyzer.certs[1])
            else:
                print("❌ Need at least 2 certificates for OCSP check")
        elif args.crl:
            analyzer.extract_certificates()
            if analyzer.certs:
                analyzer.analyze_crl(analyzer.certs[0])
            else:
                print("❌ No certificates found")
        else:
            # Full analysis
            analyzer.full_analysis()
            
    except FileNotFoundError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
