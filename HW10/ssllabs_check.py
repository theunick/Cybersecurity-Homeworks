#!/usr/bin/env python3
"""
SSL Labs API Integration
Queries SSL Labs API for comprehensive TLS configuration assessment.

Author: Nicolas Leone (1986354)
Course: Cybersecurity - HW10

API Documentation: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
"""

import requests
import time
import json
import sys
from datetime import datetime
from pathlib import Path


class SSLLabsChecker:
    """Integrates with SSL Labs API for TLS analysis."""
    
    API_URL = "https://api.ssllabs.com/api/v3/"
    
    def __init__(self, hostname):
        self.hostname = hostname
        self.results = None
    
    def check_availability(self):
        """Check if SSL Labs API is available."""
        try:
            response = requests.get(f"{self.API_URL}info")
            if response.status_code == 200:
                info = response.json()
                print(f"✅ SSL Labs API available")
                print(f"   Engine version: {info.get('engineVersion', 'Unknown')}")
                print(f"   Criteria version: {info.get('criteriaVersion', 'Unknown')}")
                return True
            else:
                print(f"❌ SSL Labs API not available: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error connecting to SSL Labs: {e}")
            return False
    
    def analyze(self, from_cache=True, max_age=24):
        """
        Analyze hostname using SSL Labs.
        
        Args:
            from_cache: Use cached results if available
            max_age: Maximum age of cached results in hours
            
        Returns:
            Analysis results dictionary
        """
        print(f"\n{'='*60}")
        print(f"🌐 SSL Labs Analysis: {self.hostname}")
        print(f"{'='*60}")
        
        if not self.check_availability():
            return None
        
        # Start analysis
        print(f"\n📡 Initiating scan...")
        
        params = {
            'host': self.hostname,
            'fromCache': 'on' if from_cache else 'off',
            'maxAge': max_age,
            'all': 'done'
        }
        
        try:
            response = requests.get(
                f"{self.API_URL}analyze",
                params=params,
                timeout=30
            )
            
            if response.status_code != 200:
                print(f"❌ API error: {response.status_code}")
                return None
            
            data = response.json()
            status = data.get('status')
            
            print(f"Status: {status}")
            
            # Poll until analysis is complete
            while status in ['DNS', 'IN_PROGRESS']:
                print(f"⏳ Analysis in progress... ({status})")
                time.sleep(10)
                
                response = requests.get(
                    f"{self.API_URL}analyze",
                    params={'host': self.hostname, 'all': 'done'},
                    timeout=30
                )
                
                data = response.json()
                status = data.get('status')
            
            if status == 'READY':
                print(f"✅ Analysis complete!")
                self.results = data
                self._display_results(data)
                return data
            elif status == 'ERROR':
                print(f"❌ Analysis error: {data.get('statusMessage', 'Unknown error')}")
                return None
            else:
                print(f"❌ Unexpected status: {status}")
                return None
                
        except requests.Timeout:
            print(f"❌ Request timeout")
            return None
        except Exception as e:
            print(f"❌ Error during analysis: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _display_results(self, data):
        """Display analysis results in human-readable format."""
        print(f"\n{'='*60}")
        print(f"📊 SSL Labs Results Summary")
        print(f"{'='*60}\n")
        
        # Host info
        host = data.get('host', 'Unknown')
        port = data.get('port', 443)
        protocol = data.get('protocol', 'HTTP')
        
        print(f"Host: {host}:{port} ({protocol})")
        
        # Endpoints
        endpoints = data.get('endpoints', [])
        print(f"Endpoints analyzed: {len(endpoints)}\n")
        
        for idx, endpoint in enumerate(endpoints, 1):
            print(f"Endpoint {idx}:")
            print(f"  IP Address: {endpoint.get('ipAddress', 'Unknown')}")
            
            grade = endpoint.get('grade', 'Unknown')
            print(f"  Overall Grade: {grade}")
            
            # Detailed scores
            if 'details' in endpoint:
                details = endpoint['details']
                
                # Certificate score
                cert_score = details.get('cert', {}).get('score', 'N/A')
                print(f"  Certificate: {cert_score}/100")
                
                # Protocol support
                protocols = details.get('protocols', [])
                print(f"  Protocols: {len(protocols)} supported")
                for proto in protocols:
                    pname = proto.get('name', 'Unknown')
                    pversion = proto.get('version', '')
                    print(f"    - {pname} {pversion}")
                
                # Key exchange
                key_exchange = details.get('keyExchange', {})
                print(f"  Key Exchange: {key_exchange.get('alg', 'Unknown')}")
                
                # Forward secrecy
                forward_secrecy = details.get('forwardSecrecy', 0)
                fs_text = ['Not supported', 'Some suites', 'All suites', 'Modern suites'][min(forward_secrecy, 3)]
                print(f"  Forward Secrecy: {fs_text}")
                
                # Cipher suites
                suites = details.get('suites', {}).get('list', [])
                print(f"  Cipher Suites: {len(suites)} total")
                
                if suites:
                    print(f"  Preferred Suite: {suites[0].get('name', 'Unknown')}")
                
                # Vulnerabilities
                vulns = []
                if details.get('vulnBeast', False):
                    vulns.append('BEAST')
                if details.get('poodle', False):
                    vulns.append('POODLE')
                if details.get('heartbleed', False):
                    vulns.append('Heartbleed')
                if details.get('freak', False):
                    vulns.append('FREAK')
                if details.get('logjam', False):
                    vulns.append('Logjam')
                if details.get('drownVulnerable', False):
                    vulns.append('DROWN')
                
                if vulns:
                    print(f"  ⚠️  Vulnerabilities: {', '.join(vulns)}")
                else:
                    print(f"  ✅ No known vulnerabilities")
            
            print()
    
    def save_results(self, output_dir='results'):
        """Save SSL Labs results to file."""
        if not self.results:
            print("⚠️  No results to save")
            return
        
        Path(output_dir).mkdir(exist_ok=True)
        
        # Save JSON
        filename = f"{output_dir}/ssllabs_{self.hostname.replace('.', '_')}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                'hostname': self.hostname,
                'timestamp': datetime.now().isoformat(),
                'results': self.results
            }, f, indent=2)
        
        print(f"💾 Results saved to: {filename}")
        
        # Save summary text
        text_filename = f"{output_dir}/ssllabs_{self.hostname.replace('.', '_')}.txt"
        
        with open(text_filename, 'w') as f:
            f.write(f"SSL Labs Analysis Report\n")
            f.write(f"{'='*60}\n")
            f.write(f"Hostname: {self.hostname}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            endpoints = self.results.get('endpoints', [])
            
            for idx, endpoint in enumerate(endpoints, 1):
                f.write(f"\nEndpoint {idx}: {endpoint.get('ipAddress', 'Unknown')}\n")
                f.write(f"Overall Grade: {endpoint.get('grade', 'Unknown')}\n")
                
                if 'details' in endpoint:
                    details = endpoint['details']
                    
                    f.write(f"\nScores:\n")
                    f.write(f"  Certificate: {details.get('cert', {}).get('score', 'N/A')}/100\n")
                    
                    protocols = details.get('protocols', [])
                    f.write(f"\nProtocols ({len(protocols)}):\n")
                    for proto in protocols:
                        f.write(f"  - {proto.get('name', 'Unknown')} {proto.get('version', '')}\n")
                    
                    suites = details.get('suites', {}).get('list', [])
                    if suites:
                        f.write(f"\nCipher Suites ({len(suites)} total):\n")
                        f.write(f"  Preferred: {suites[0].get('name', 'Unknown')}\n")
        
        print(f"📄 Text summary saved to: {text_filename}")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python3 ssllabs_check.py <hostname1> [hostname2] ...")
        print("Example: python3 ssllabs_check.py www.google.com github.com")
        print("\nNote: SSL Labs scans can take 1-2 minutes per host")
        sys.exit(1)
    
    servers = sys.argv[1:]
    
    for server in servers:
        checker = SSLLabsChecker(server)
        results = checker.analyze(from_cache=True, max_age=24)
        
        if results:
            checker.save_results()
        
        # Rate limiting: wait between requests
        if len(servers) > 1 and server != servers[-1]:
            print(f"\n⏳ Waiting 10 seconds before next scan...")
            time.sleep(10)
    
    print(f"\n✅ All SSL Labs analyses complete!")


if __name__ == '__main__':
    main()
