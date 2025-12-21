#!/usr/bin/env python3
"""
TLS Configuration Analysis Tool
Performs comprehensive TLS/SSL security analysis using OpenSSL s_client.

Author: Nicolas Leone (1986354)
Course: Cybersecurity - HW10
"""

import subprocess
import sys
import re
import json
from datetime import datetime
from pathlib import Path


class TLSAnalyzer:
    """Analyzes TLS configuration of remote servers using OpenSSL."""
    
    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port
        self.results = {}
    
    def run_openssl_command(self, extra_args=None):
        """
        Execute openssl s_client command.
        
        Args:
            extra_args: Additional arguments for openssl s_client
            
        Returns:
            Command output as string
        """
        cmd = ['openssl', 's_client', '-connect', f'{self.hostname}:{self.port}']
        
        if extra_args:
            cmd.extend(extra_args)
        
        cmd.extend(['-servername', self.hostname])  # SNI support
        
        try:
            # Send empty input and capture output
            result = subprocess.run(
                cmd,
                input=b'',
                capture_output=True,
                timeout=10
            )
            return result.stdout.decode('utf-8', errors='ignore') + \
                   result.stderr.decode('utf-8', errors='ignore')
        except subprocess.TimeoutExpired:
            return "ERROR: Connection timeout"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def analyze_protocol_version(self):
        """Determine supported TLS versions."""
        print(f"\n🔍 Analyzing TLS protocol versions for {self.hostname}...")
        
        versions = {
            'TLS 1.3': ['-tls1_3'],
            'TLS 1.2': ['-tls1_2'],
            'TLS 1.1': ['-tls1_1'],
            'TLS 1.0': ['-tls1'],
        }
        
        supported = []
        negotiated_version = None
        
        for version_name, args in versions.items():
            output = self.run_openssl_command(args)
            
            if 'Cipher is' in output and 'Cipher is (NONE)' not in output:
                supported.append(version_name)
                if not negotiated_version:
                    negotiated_version = version_name
                print(f"  ✅ {version_name}: Supported")
            else:
                print(f"  ❌ {version_name}: Not supported")
        
        self.results['supported_versions'] = supported
        self.results['negotiated_version'] = negotiated_version or 'None'
        
        return supported
    
    def analyze_cipher_suite(self):
        """Extract negotiated cipher suite information."""
        print(f"\n🔐 Analyzing cipher suite for {self.hostname}...")
        
        output = self.run_openssl_command()
        
        # Extract cipher suite
        cipher_match = re.search(r'Cipher\s*:\s*(\S+)', output)
        cipher = cipher_match.group(1) if cipher_match else 'Unknown'
        
        # Extract protocol
        protocol_match = re.search(r'Protocol\s*:\s*(\S+)', output)
        protocol = protocol_match.group(1) if protocol_match else 'Unknown'
        
        print(f"  Protocol: {protocol}")
        print(f"  Cipher: {cipher}")
        
        # Analyze cipher components
        self._analyze_cipher_components(cipher)
        
        self.results['cipher_suite'] = cipher
        self.results['protocol'] = protocol
        
        return cipher
    
    def _analyze_cipher_components(self, cipher):
        """Analyze cipher suite components for security properties."""
        components = {
            'forward_secrecy': False,
            'key_exchange': 'Unknown',
            'encryption': 'Unknown',
            'authentication': 'Unknown'
        }
        
        # TLS 1.3 cipher suites (e.g., TLS_AES_256_GCM_SHA384)
        # TLS 1.3 always provides forward secrecy
        if cipher.startswith('TLS_'):
            components['forward_secrecy'] = True
            components['key_exchange'] = 'ECDHE (TLS 1.3)'
            print(f"  ✅ Forward Secrecy: Yes (TLS 1.3 mandatory)")
        # TLS 1.2 and earlier cipher suites
        elif 'ECDHE' in cipher or 'DHE' in cipher:
            components['forward_secrecy'] = True
            components['key_exchange'] = 'ECDHE' if 'ECDHE' in cipher else 'DHE'
            print(f"  ✅ Forward Secrecy: Yes ({components['key_exchange']})")
        else:
            print(f"  ❌ Forward Secrecy: No")
            if 'RSA' in cipher:
                components['key_exchange'] = 'RSA (static)'
        
        # Check encryption algorithm
        if 'AES' in cipher:
            if 'GCM' in cipher:
                components['encryption'] = 'AES-GCM (AEAD)'
                print(f"  ✅ Encryption: {components['encryption']}")
            elif 'CBC' in cipher:
                components['encryption'] = 'AES-CBC'
                print(f"  ⚠️  Encryption: {components['encryption']} (padding oracle risk)")
        elif 'CHACHA20' in cipher:
            components['encryption'] = 'ChaCha20-Poly1305 (AEAD)'
            print(f"  ✅ Encryption: {components['encryption']}")
        
        # Check authentication
        if 'ECDSA' in cipher:
            components['authentication'] = 'ECDSA'
        elif 'RSA' in cipher:
            components['authentication'] = 'RSA'
        
        self.results['cipher_components'] = components
    
    def analyze_certificate_chain(self):
        """Extract and analyze certificate chain."""
        print(f"\n📜 Analyzing certificate chain for {self.hostname}...")
        
        output = self.run_openssl_command(['-showcerts'])
        
        # Count certificates in chain
        cert_count = output.count('-----BEGIN CERTIFICATE-----')
        print(f"  Certificates in chain: {cert_count}")
        
        # Extract certificate details
        cert_output = self.run_openssl_command()
        
        # Subject
        subject_match = re.search(r'subject=(.+)', cert_output)
        subject = subject_match.group(1).strip() if subject_match else 'Unknown'
        print(f"  Subject: {subject}")
        
        # Issuer
        issuer_match = re.search(r'issuer=(.+)', cert_output)
        issuer = issuer_match.group(1).strip() if issuer_match else 'Unknown'
        print(f"  Issuer: {issuer}")
        
        # Validity
        valid_from = re.search(r'notBefore=(.+)', cert_output)
        valid_to = re.search(r'notAfter=(.+)', cert_output)
        
        if valid_from and valid_to:
            print(f"  Valid from: {valid_from.group(1).strip()}")
            print(f"  Valid to: {valid_to.group(1).strip()}")
        
        # Verification result
        verify_match = re.search(r'Verify return code: (\d+) \((.+?)\)', cert_output)
        if verify_match:
            verify_code = verify_match.group(1)
            verify_msg = verify_match.group(2)
            
            if verify_code == '0':
                print(f"  ✅ Verification: OK")
            else:
                print(f"  ❌ Verification: {verify_msg}")
            
            self.results['cert_verification'] = {
                'code': verify_code,
                'message': verify_msg
            }
        
        self.results['certificate'] = {
            'subject': subject,
            'issuer': issuer,
            'chain_length': cert_count
        }
        
        return cert_count
    
    def analyze_extensions(self):
        """Analyze TLS extensions (ALPN, OCSP, SNI)."""
        print(f"\n🔧 Analyzing TLS extensions for {self.hostname}...")
        
        # Check ALPN
        alpn_output = self.run_openssl_command(['-alpn', 'h2,http/1.1'])
        alpn_match = re.search(r'ALPN protocol:\s*(\S+)', alpn_output)
        
        if alpn_match:
            alpn = alpn_match.group(1)
            print(f"  ✅ ALPN: {alpn}")
            self.results['alpn'] = alpn
        else:
            print(f"  ❌ ALPN: Not supported")
            self.results['alpn'] = None
        
        # Check OCSP stapling
        status_output = self.run_openssl_command(['-status'])
        
        if 'OCSP Response Status: successful' in status_output:
            print(f"  ✅ OCSP Stapling: Supported")
            self.results['ocsp_stapling'] = True
        elif 'OCSP response: no response sent' in status_output:
            print(f"  ❌ OCSP Stapling: Not configured")
            self.results['ocsp_stapling'] = False
        else:
            print(f"  ⚠️  OCSP Stapling: Status unclear")
            self.results['ocsp_stapling'] = None
        
        # Check session tickets
        if 'TLS session ticket' in status_output:
            print(f"  ✅ Session Tickets: Supported")
            self.results['session_tickets'] = True
        else:
            print(f"  ❌ Session Tickets: Not observed")
            self.results['session_tickets'] = False
    
    def run_full_analysis(self):
        """Run complete TLS analysis."""
        print(f"\n{'='*60}")
        print(f"🔒 TLS Security Analysis: {self.hostname}:{self.port}")
        print(f"{'='*60}")
        print(f"📅 Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            self.analyze_protocol_version()
            self.analyze_cipher_suite()
            self.analyze_certificate_chain()
            self.analyze_extensions()
            
            print(f"\n{'='*60}")
            print(f"✅ Analysis complete for {self.hostname}")
            print(f"{'='*60}\n")
            
            return self.results
            
        except Exception as e:
            print(f"\n❌ Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def save_results(self, output_dir='results'):
        """Save analysis results to file."""
        Path(output_dir).mkdir(exist_ok=True)
        
        filename = f"{output_dir}/openssl_{self.hostname.replace('.', '_')}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                'hostname': self.hostname,
                'port': self.port,
                'timestamp': datetime.now().isoformat(),
                'results': self.results
            }, f, indent=2)
        
        print(f"💾 Results saved to: {filename}")
        
        # Also save human-readable text
        text_filename = f"{output_dir}/openssl_{self.hostname.replace('.', '_')}.txt"
        with open(text_filename, 'w') as f:
            f.write(f"TLS Analysis Report\n")
            f.write(f"{'='*60}\n")
            f.write(f"Hostname: {self.hostname}:{self.port}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"Protocol Version: {self.results.get('negotiated_version', 'Unknown')}\n")
            f.write(f"Cipher Suite: {self.results.get('cipher_suite', 'Unknown')}\n")
            
            if 'cipher_components' in self.results:
                comp = self.results['cipher_components']
                f.write(f"\nCipher Components:\n")
                f.write(f"  - Forward Secrecy: {'Yes' if comp['forward_secrecy'] else 'No'}\n")
                f.write(f"  - Key Exchange: {comp['key_exchange']}\n")
                f.write(f"  - Encryption: {comp['encryption']}\n")
            
            if 'certificate' in self.results:
                cert = self.results['certificate']
                f.write(f"\nCertificate:\n")
                f.write(f"  - Subject: {cert['subject']}\n")
                f.write(f"  - Issuer: {cert['issuer']}\n")
                f.write(f"  - Chain Length: {cert['chain_length']}\n")
            
            f.write(f"\nExtensions:\n")
            f.write(f"  - ALPN: {self.results.get('alpn', 'Not supported')}\n")
            f.write(f"  - OCSP Stapling: {'Yes' if self.results.get('ocsp_stapling') else 'No'}\n")
        
        print(f"📄 Text report saved to: {text_filename}")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_tls.py <hostname1> [hostname2] ...")
        print("Example: python3 analyze_tls.py www.google.com github.com")
        sys.exit(1)
    
    servers = sys.argv[1:]
    
    all_results = {}
    
    for server in servers:
        # Parse hostname:port
        if ':' in server:
            hostname, port = server.split(':', 1)
            port = int(port)
        else:
            hostname = server
            port = 443
        
        analyzer = TLSAnalyzer(hostname, port)
        results = analyzer.run_full_analysis()
        
        if results:
            analyzer.save_results()
            all_results[hostname] = results
    
    # Save summary
    Path('results').mkdir(exist_ok=True)
    with open('results/openssl_summary.json', 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'servers_analyzed': len(all_results),
            'results': all_results
        }, f, indent=2)
    
    print(f"\n✅ All analyses complete! Results saved in 'results/' directory")


if __name__ == '__main__':
    main()
