#!/usr/bin/env python3
"""
Okta WebAuthn Factor Audit Script - Detailed Version
Provides detailed factor information and validation
"""

import os
import sys
import csv
import json
from datetime import datetime
from typing import List, Dict, Optional
import requests
from urllib.parse import urlparse
import time
import argparse


class OktaWebAuthnAuditor:
    # Human-readable factor type names
    FACTOR_NAMES = {
        'webauthn': 'WebAuthn/FIDO2',
        'push': 'Okta Verify Push',
        'signed_nonce': 'Okta FastPass',
        'token:software:totp': 'TOTP App',
        'token:hardware': 'Hardware Token',
        'sms': 'SMS',
        'call': 'Voice Call',
        'email': 'Email',
        'question': 'Security Question',
        'password': 'Password',
        'u2f': 'U2F (Legacy)',
        'token': 'Token',
        'claims_provider': 'IDP'
    }
    
    def __init__(self, domain: str, api_token: str, debug: bool = False):
        """
        Initialize the Okta WebAuthn auditor.
        
        Args:
            domain: Your Okta domain
            api_token: Your Okta API token
            debug: Enable debug output
        """
        self.domain = domain.rstrip('/')
        if not self.domain.startswith('https://'):
            self.domain = f'https://{self.domain}'
        
        self.api_token = api_token
        self.debug = debug
        self.headers = {
            'Authorization': f'SSWS {api_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Rate limiting
        self.rate_limit_remaining = 1000
        self.rate_limit_reset = 0
        
    def _make_request(self, url: str, params: Optional[Dict] = None) -> requests.Response:
        """Make a request to Okta API with rate limiting handling."""
        if self.rate_limit_remaining < 10:
            wait_time = max(0, self.rate_limit_reset - time.time())
            if wait_time > 0:
                print(f"Rate limit approaching, waiting {wait_time:.1f} seconds...")
                time.sleep(wait_time + 1)
        
        response = self.session.get(url, params=params)
        
        # Update rate limit info
        if 'x-rate-limit-remaining' in response.headers:
            self.rate_limit_remaining = int(response.headers['x-rate-limit-remaining'])
        if 'x-rate-limit-reset' in response.headers:
            self.rate_limit_reset = int(response.headers['x-rate-limit-reset'])
        
        if response.status_code == 429:
            retry_after = int(response.headers.get('x-rate-limit-reset', 60))
            print(f"Rate limited. Waiting {retry_after} seconds...")
            time.sleep(retry_after)
            return self._make_request(url, params)
        
        response.raise_for_status()
        return response
    
    def get_all_users(self, status: str = 'ACTIVE') -> List[Dict]:
        """Fetch all users from Okta."""
        users = []
        url = f'{self.domain}/api/v1/users'
        params = {'limit': 200}
        
        if status:
            params['filter'] = f'status eq "{status}"'
        
        print(f"Fetching {status} users from Okta...")
        
        while url:
            try:
                response = self._make_request(url, params if not urlparse(url).query else None)
                batch = response.json()
                users.extend(batch)
                
                print(f"  Fetched {len(users)} users so far...")
                
                # Check for next page
                links = response.links
                url = links.get('next', {}).get('url')
                
            except requests.exceptions.RequestException as e:
                print(f"Error fetching users: {e}")
                sys.exit(1)
        
        print(f"Total users fetched: {len(users)}")
        return users
    
    def get_user_factors(self, user_id: str, email: str) -> List[Dict]:
        """Get all enrolled factors for a specific user."""
        url = f'{self.domain}/api/v1/users/{user_id}/factors'
        
        try:
            response = self._make_request(url)
            factors = response.json()
            
            if self.debug and factors:
                print(f"\n=== DEBUG: Factors for {email} ===")
                for factor in factors:
                    if factor.get('status') == 'ACTIVE':
                        print(f"  Type: {factor.get('factorType')}")
                        print(f"  Provider: {factor.get('provider')}")
                        print(f"  Status: {factor.get('status')}")
                        if factor.get('factorType') == 'webauthn':
                            print(f"  Profile: {json.dumps(factor.get('profile', {}), indent=4)}")
                        print("  ---")
            
            return factors
        except requests.exceptions.RequestException as e:
            print(f"Error fetching factors for user {user_id}: {e}")
            return []
    
    def analyze_factors(self, factors: List[Dict]) -> Dict:
        """Analyze factors and extract detailed information."""
        result = {
            'has_webauthn': False,
            'webauthn_details': [],
            'factor_summary': {},
            'all_factors': []
        }
        
        for factor in factors:
            if factor.get('status') != 'ACTIVE':
                continue
            
            factor_type = factor.get('factorType', 'unknown')
            provider = factor.get('provider', '')
            
            # Build readable name
            if factor_type in self.FACTOR_NAMES:
                readable_name = self.FACTOR_NAMES[factor_type]
            else:
                readable_name = factor_type
            
            # Add provider info for some types
            if provider and provider != 'OKTA':
                readable_name = f"{readable_name} ({provider})"
            
            # Track all factors
            result['all_factors'].append(readable_name)
            
            # Count by type
            if readable_name not in result['factor_summary']:
                result['factor_summary'][readable_name] = 0
            result['factor_summary'][readable_name] += 1
            
            # Special handling for WebAuthn
            if factor_type == 'webauthn':
                result['has_webauthn'] = True
                profile = factor.get('profile', {})
                auth_name = profile.get('authenticatorName')
                if auth_name is None:
                    auth_name = 'Unknown'
                result['webauthn_details'].append({
                    'authenticatorName': auth_name,
                    'credentialId': profile.get('credentialId', 'N/A')[:20] + '...' if profile.get('credentialId') else 'N/A',
                    'created': factor.get('created', 'Unknown'),
                    'lastVerified': factor.get('lastVerified', 'Never')
                })
        
        return result
    
    def audit_users(self, users: List[Dict], sample_size: Optional[int] = None) -> Dict[str, List[Dict]]:
        """Audit users for WebAuthn factors with detailed analysis."""
        results = {
            'has_webauthn': [],
            'no_webauthn': []
        }
        
        # For debugging, optionally limit sample size
        if sample_size:
            users = users[:sample_size]
            print(f"\nDEBUG MODE: Auditing first {sample_size} users only")
        
        print(f"\nAuditing {len(users)} users for WebAuthn factors...")
        
        for i, user in enumerate(users, 1):
            user_id = user['id']
            email = user['profile'].get('email', 'N/A')
            login = user['profile'].get('login', 'N/A')
            first_name = user['profile'].get('firstName', '')
            last_name = user['profile'].get('lastName', '')
            
            # Progress indicator
            if i % 10 == 0:
                print(f"  Processed {i}/{len(users)} users...")
            
            # Get and analyze factors
            factors = self.get_user_factors(user_id, email)
            analysis = self.analyze_factors(factors)
            
            # Prepare user info with detailed factor breakdown
            user_info = {
                'id': user_id,
                'email': email,
                'login': login,
                'firstName': first_name,
                'lastName': last_name,
                'status': user['status'],
                'created': user.get('created', ''),
                'lastLogin': user.get('lastLogin', ''),
                'has_webauthn': analysis['has_webauthn'],
                'webauthn_count': len(analysis['webauthn_details']),
                'webauthn_authenticators': ', '.join([d.get('authenticatorName', 'Unknown') for d in analysis['webauthn_details']]),
                'total_factors': len(analysis['all_factors']),
                'factor_list': ', '.join(analysis['all_factors']),
                # Individual factor columns
                'has_okta_verify_push': 'Okta Verify Push' in analysis['factor_summary'],
                'has_okta_fastpass': 'Okta FastPass' in analysis['factor_summary'],
                'has_totp': 'TOTP App' in analysis['factor_summary'],
                'has_sms': 'SMS' in analysis['factor_summary']
            }
            
            if analysis['has_webauthn']:
                results['has_webauthn'].append(user_info)
            else:
                results['no_webauthn'].append(user_info)
        
        return results
    
    def save_detailed_results(self, results: Dict[str, List[Dict]], output_dir: str = '.'):
        """Save detailed audit results to CSV files."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Enhanced fieldnames with individual factor columns
        fieldnames = [
            'email', 'login', 'firstName', 'lastName', 'status',
            'has_webauthn', 'webauthn_count', 'webauthn_authenticators',
            'has_okta_verify_push', 'has_okta_fastpass', 'has_totp', 'has_sms',
            'total_factors', 'factor_list',
            'created', 'lastLogin', 'id'
        ]
        
        # Save users WITH WebAuthn
        with_webauthn_file = os.path.join(output_dir, f'users_with_webauthn_detailed_{timestamp}.csv')
        if results['has_webauthn']:
            with open(with_webauthn_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(results['has_webauthn'])
            print(f"\nUsers WITH WebAuthn saved to: {with_webauthn_file}")
        
        # Save users WITHOUT WebAuthn
        without_webauthn_file = os.path.join(output_dir, f'users_without_webauthn_detailed_{timestamp}.csv')
        if results['no_webauthn']:
            with open(without_webauthn_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(results['no_webauthn'])
            print(f"Users WITHOUT WebAuthn saved to: {without_webauthn_file}")
        
        # Enhanced summary with factor distribution
        summary_file = os.path.join(output_dir, f'webauthn_audit_detailed_{timestamp}.txt')
        with open(summary_file, 'w') as f:
            f.write("Okta WebAuthn Factor Audit - Detailed Report\n")
            f.write("=" * 60 + "\n")
            f.write(f"Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Okta Domain: {self.domain}\n\n")
            
            total_users = len(results['has_webauthn']) + len(results['no_webauthn'])
            f.write(f"Total Active Users Audited: {total_users}\n")
            f.write(f"Users WITH WebAuthn: {len(results['has_webauthn'])} ({len(results['has_webauthn'])/total_users*100:.1f}%)\n")
            f.write(f"Users WITHOUT WebAuthn: {len(results['no_webauthn'])} ({len(results['no_webauthn'])/total_users*100:.1f}%)\n")
            
            # WebAuthn authenticator types
            f.write("\n" + "=" * 60 + "\n")
            f.write("WebAuthn Authenticator Distribution:\n")
            auth_types = {}
            for user in results['has_webauthn']:
                for auth in user.get('webauthn_authenticators', '').split(', '):
                    if auth:
                        auth_types[auth] = auth_types.get(auth, 0) + 1
            
            for auth_type, count in sorted(auth_types.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {auth_type}: {count} users\n")
            
            # Factor distribution for non-WebAuthn users
            f.write("\n" + "=" * 60 + "\n")
            f.write("Factor Distribution (users WITHOUT WebAuthn):\n")
            factor_stats = {
                'Okta Verify Push': 0,
                'Okta FastPass': 0,
                'TOTP App': 0,
                'SMS': 0
            }
            
            for user in results['no_webauthn']:
                if user.get('has_okta_verify_push'):
                    factor_stats['Okta Verify Push'] += 1
                if user.get('has_okta_fastpass'):
                    factor_stats['Okta FastPass'] += 1
                if user.get('has_totp'):
                    factor_stats['TOTP App'] += 1
                if user.get('has_sms'):
                    factor_stats['SMS'] += 1
            
            for factor_type, count in sorted(factor_stats.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    f.write(f"  {factor_type}: {count} users ({count/len(results['no_webauthn'])*100:.1f}%)\n")
        
        print(f"Detailed summary saved to: {summary_file}")
        
        return {
            'with_webauthn_file': with_webauthn_file,
            'without_webauthn_file': without_webauthn_file,
            'summary_file': summary_file
        }


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Audit Okta users for WebAuthn factors')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--sample', type=int, help='Only audit first N users (for testing)')
    args = parser.parse_args()
    
    print("Okta WebAuthn Factor Audit Tool - Detailed Version")
    print("=" * 60)
    
    # Get configuration
    domain = os.environ.get('OKTA_DOMAIN')
    api_token = os.environ.get('OKTA_API_TOKEN')
    
    if not domain:
        domain = input("Enter your Okta domain (e.g., example.okta.com): ").strip()
    
    if not api_token:
        print("\nEnter your Okta API token")
        api_token = input("API Token: ").strip()
    
    if not domain or not api_token:
        print("Error: Okta domain and API token are required.")
        sys.exit(1)
    
    # Initialize auditor
    auditor = OktaWebAuthnAuditor(domain, api_token, debug=args.debug)
    
    # Test connection
    print("\nTesting connection to Okta...")
    try:
        test_response = auditor._make_request(f'{auditor.domain}/api/v1/users', {'limit': 1})
        print("Connection successful!")
    except Exception as e:
        print(f"Failed to connect to Okta: {e}")
        sys.exit(1)
    
    # Fetch users
    users = auditor.get_all_users(status='ACTIVE')
    
    if not users:
        print("No active users found.")
        sys.exit(0)
    
    # Audit users
    results = auditor.audit_users(users, sample_size=args.sample)
    
    # Display summary
    print("\n" + "=" * 60)
    print("AUDIT RESULTS")
    print("=" * 60)
    total_users = len(results['has_webauthn']) + len(results['no_webauthn'])
    print(f"Total Active Users: {total_users}")
    print(f"Users WITH WebAuthn: {len(results['has_webauthn'])} ({len(results['has_webauthn'])/total_users*100:.1f}%)")
    print(f"Users WITHOUT WebAuthn: {len(results['no_webauthn'])} ({len(results['no_webauthn'])/total_users*100:.1f}%)")
    
    # Show sample of WebAuthn authenticators found
    if results['has_webauthn'] and args.debug:
        print("\nSample WebAuthn Authenticators Found:")
        auth_types = set()
        for user in results['has_webauthn'][:10]:
            auths = user.get('webauthn_authenticators', '')
            if auths:
                for auth in auths.split(', '):
                    auth_types.add(auth)
        for auth in sorted(auth_types):
            print(f"  - {auth}")
    
    # Save results
    saved_files = auditor.save_detailed_results(results)
    
    print("\n" + "=" * 60)
    print("Audit complete! Detailed results have been saved.")
    print("\nOutput includes:")
    print("- Separate columns for each factor type (WebAuthn, Push, FastPass, TOTP, SMS)")
    print("- WebAuthn authenticator names (YubiKey, Touch ID, Windows Hello, etc.)")
    print("- Count of WebAuthn devices per user")
    print("- Human-readable factor names")


if __name__ == '__main__':
    main()