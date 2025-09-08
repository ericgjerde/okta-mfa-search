#!/usr/bin/env python3
"""
Okta WebAuthn Factor Audit Script
Checks all active users in an Okta instance for WebAuthn authentication factors
and generates reports of who has/doesn't have WebAuthn configured.
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime
from typing import List, Dict, Optional
import requests
from urllib.parse import urlparse
import time
from getpass import getpass


class OktaWebAuthnAuditor:
    # Human-readable factor type names (used in detailed mode)
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
    
    def __init__(self, domain: str, api_token: str, detailed: bool = False):
        """
        Initialize the Okta WebAuthn auditor.
        
        Args:
            domain: Your Okta domain (e.g., 'example.okta.com')
            api_token: Your Okta API token
            detailed: Enable detailed output mode
        """
        self.domain = domain.rstrip('/')
        if not self.domain.startswith('https://'):
            self.domain = f'https://{self.domain}'
        
        self.api_token = api_token
        self.detailed = detailed
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
            try:
                self.rate_limit_remaining = int(response.headers['x-rate-limit-remaining'])
            except ValueError:
                pass
        if 'x-rate-limit-reset' in response.headers:
            try:
                self.rate_limit_reset = int(response.headers['x-rate-limit-reset'])
            except ValueError:
                pass

        if response.status_code == 429:
            headers = {k.lower(): v for k, v in response.headers.items()}
            sleep_seconds: Optional[int] = None
            # Prefer Retry-After if present (seconds)
            if 'retry-after' in headers:
                try:
                    sleep_seconds = int(headers['retry-after'])
                except ValueError:
                    sleep_seconds = None
            # Fallback to X-Rate-Limit-Reset (epoch seconds)
            if sleep_seconds is None and 'x-rate-limit-reset' in headers:
                try:
                    reset_epoch = int(headers['x-rate-limit-reset'])
                    sleep_seconds = max(0, reset_epoch - int(time.time())) + 1
                except ValueError:
                    sleep_seconds = None
            if sleep_seconds is None:
                sleep_seconds = 60
            print(f"Rate limited. Waiting {sleep_seconds} seconds...")
            time.sleep(sleep_seconds)
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
                response = self._make_request(url, params)
                batch = response.json()
                users.extend(batch)
                
                # Check for pagination
                links = response.links
                url = links.get('next', {}).get('url')
                params = None  # URL already has params
                
                print(f"  Fetched {len(users)} users so far...")
                
            except requests.exceptions.RequestException as e:
                print(f"Error fetching users: {e}")
                break
        
        print(f"Total users fetched: {len(users)}")
        return users
    
    def get_user_factors(self, user_id: str) -> List[Dict]:
        """Get all enrolled factors for a specific user."""
        url = f'{self.domain}/api/v1/users/{user_id}/factors'
        
        try:
            response = self._make_request(url)
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching factors for user {user_id}: {e}")
            return []
    
    def get_factor_display_name(self, factor: Dict) -> str:
        """Get human-readable factor name."""
        factor_type = factor.get('factorType', 'unknown')
        provider = factor.get('provider', '')
        
        if self.detailed:
            # Use detailed names mapping
            if factor_type in self.FACTOR_NAMES:
                return self.FACTOR_NAMES[factor_type]
            elif f"{factor_type}:{provider}" in self.FACTOR_NAMES:
                return self.FACTOR_NAMES[f"{factor_type}:{provider}"]
        
        # Default format
        if provider and provider != 'OKTA':
            return f"{factor_type}:{provider}"
        return factor_type
    
    def audit_users_for_webauthn(self, users: List[Dict]) -> tuple:
        """
        Analyze provided users for WebAuthn factors.
        Returns tuple of (users_with_webauthn, users_without_webauthn)
        """
        users_with_webauthn: List[Dict] = []
        users_without_webauthn: List[Dict] = []

        print(f"\nAnalyzing WebAuthn enrollment for {len(users)} users...")

        for i, user in enumerate(users, 1):
            if i % 10 == 0:
                print(f"  Processing user {i}/{len(users)}...")

            user_id = user.get('id')
            factors = self.get_user_factors(user_id)

            # Check for WebAuthn
            has_webauthn = any(f.get('factorType') == 'webauthn' for f in factors)

            # Get all factor types for reporting
            factor_types = [self.get_factor_display_name(f) for f in factors]

            user_info = {
                'email': user.get('profile', {}).get('email', ''),
                'login': user.get('profile', {}).get('login', ''),
                'firstName': user.get('profile', {}).get('firstName', ''),
                'lastName': user.get('profile', {}).get('lastName', ''),
                'status': user.get('status', ''),
                'created': user.get('created', ''),
                'lastLogin': user.get('lastLogin', ''),
                'factorTypes': ', '.join(factor_types) if factor_types else 'None',
                'factorCount': len(factors),
                'userId': user_id
            }

            if self.detailed:
                # Add additional fields for detailed mode
                user_info['department'] = user.get('profile', {}).get('department', '')
                user_info['hasWebAuthn'] = 'Yes' if has_webauthn else 'No'

                # Add individual factor details
                for f in factors:
                    if f.get('factorType') == 'webauthn':
                        user_info['webauthnDetails'] = f.get('profile', {}).get('authenticatorName', 'Unknown')
                        break

            if has_webauthn:
                users_with_webauthn.append(user_info)
            else:
                users_without_webauthn.append(user_info)

        print(f"\nAudit complete!")
        print(f"  Users with WebAuthn: {len(users_with_webauthn)}")
        print(f"  Users without WebAuthn: {len(users_without_webauthn)}")

        return users_with_webauthn, users_without_webauthn

    def audit_webauthn(self, status: str = 'ACTIVE') -> tuple:
        """
        Fetch users by status and analyze for WebAuthn factors.
        Returns tuple of (users_with_webauthn, users_without_webauthn)
        """
        users = self.get_all_users(status=status)
        return self.audit_users_for_webauthn(users)
    
    def save_results(self, users_with: List[Dict], users_without: List[Dict]) -> None:
        """Save audit results to CSV files and generate summary."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        mode_suffix = '_detailed' if self.detailed else ''
        
        # Define CSV fields based on mode
        if self.detailed:
            csv_fields = [
                'email', 'login', 'firstName', 'lastName', 'department',
                'status', 'created', 'lastLogin', 'hasWebAuthn',
                'factorTypes', 'factorCount', 'webauthnDetails', 'userId'
            ]
        else:
            csv_fields = [
                'email', 'login', 'firstName', 'lastName',
                'status', 'created', 'lastLogin',
                'factorTypes', 'factorCount', 'userId'
            ]
        
        # Save users with WebAuthn
        with_file = f'users_with_webauthn{mode_suffix}_{timestamp}.csv'
        with open(with_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(users_with)
        print(f"\nSaved users WITH WebAuthn to: {with_file}")
        
        # Save users without WebAuthn
        without_file = f'users_without_webauthn{mode_suffix}_{timestamp}.csv'
        with open(without_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(users_without)
        print(f"Saved users WITHOUT WebAuthn to: {without_file}")
        
        # Generate summary report
        summary_file = f'webauthn_audit_summary{mode_suffix}_{timestamp}.txt'
        with open(summary_file, 'w') as f:
            f.write("Okta WebAuthn Factor Audit Summary\n")
            f.write("=" * 50 + "\n")
            f.write(f"Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Okta Domain: {self.domain}\n")
            f.write(f"Mode: {'Detailed' if self.detailed else 'Standard'}\n\n")
            
            total_users = len(users_with) + len(users_without)
            f.write(f"Total Active Users Audited: {total_users}\n")
            if total_users > 0:
                with_pct = (len(users_with) / total_users) * 100
                without_pct = (len(users_without) / total_users) * 100
            else:
                with_pct = 0.0
                without_pct = 0.0
            f.write(f"Users WITH WebAuthn: {len(users_with)} ({with_pct:.1f}%)\n")
            f.write(f"Users WITHOUT WebAuthn: {len(users_without)} ({without_pct:.1f}%)\n")
            
            if self.detailed:
                # Add detailed statistics
                f.write("\n" + "=" * 50 + "\n")
                f.write("Detailed Factor Analysis:\n\n")
                
                # Analyze WebAuthn authenticator types
                if users_with:
                    f.write("WebAuthn Authenticator Distribution:\n")
                    auth_types = {}
                    for user in users_with:
                        auth_name = user.get('webauthnDetails', 'Unknown')
                        auth_types[auth_name] = auth_types.get(auth_name, 0) + 1
                    
                    for auth_type, count in sorted(auth_types.items(), key=lambda x: x[1], reverse=True):
                        f.write(f"  {auth_type}: {count} users\n")
            
            # Factor distribution for users without WebAuthn
            f.write("\n" + "=" * 50 + "\n")
            f.write("Factor Type Distribution (for users without WebAuthn):\n")
            
            factor_counts = {}
            for user in users_without:
                factors = user.get('factorTypes', '').split(', ')
                for factor in factors:
                    if factor and factor != 'None':
                        factor_counts[factor] = factor_counts.get(factor, 0) + 1
            
            for factor, count in sorted(factor_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {factor}: {count} users\n")
            
            f.write("\n")
        
        print(f"Saved summary report to: {summary_file}")


def is_allowed_okta_domain(domain: str) -> bool:
    """Validate that the provided domain is an Okta-hosted domain we trust."""
    if not domain:
        return False
    d = domain.strip()
    if not d:
        return False
    if not d.startswith('http://') and not d.startswith('https://'):
        d = f'https://{d}'
    parsed = urlparse(d)
    host = parsed.hostname or ''
    allowed_suffixes = (
        'okta.com',
        'oktapreview.com',
        'okta-emea.com',
    )
    return any(host == s or host.endswith('.' + s) for s in allowed_suffixes)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Audit Okta users for WebAuthn enrollment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard audit using environment variables
  export OKTA_DOMAIN="example.okta.com"
  export OKTA_API_TOKEN="your-token-here"
  python okta_webauthn_audit.py

  # Detailed audit with prompts for credentials
  python okta_webauthn_audit.py --detailed

  # Quick audit with inline credentials (not recommended for production)
  OKTA_DOMAIN="example.okta.com" OKTA_API_TOKEN="token" python okta_webauthn_audit.py
        """
    )
    
    parser.add_argument(
        '--detailed', '-d',
        action='store_true',
        help='Enable detailed output mode with additional user fields and statistics'
    )
    
    parser.add_argument(
        '--domain',
        help='Okta domain (e.g., example.okta.com). Can also be set via OKTA_DOMAIN env var'
    )
    
    parser.add_argument(
        '--status',
        default='ACTIVE',
        choices=['ACTIVE', 'PROVISIONED', 'STAGED', 'SUSPENDED', 'DEPROVISIONED', 'ALL'],
        help='User status to audit (default: ACTIVE). Use ALL to audit all statuses'
    )
    
    args = parser.parse_args()
    
    print("Okta WebAuthn Factor Audit Tool")
    print("=" * 50)
    
    # Get configuration
    domain = args.domain or os.environ.get('OKTA_DOMAIN')
    api_token = os.environ.get('OKTA_API_TOKEN')
    
    if not domain:
        domain = input("Enter your Okta domain (e.g., example.okta.com): ").strip()
    
    if not api_token:
        print("\nEnter your Okta API token")
        print("(You can create one in Okta Admin > Security > API > Tokens)")
        api_token = getpass("API Token: ").strip()
    
    if not domain or not api_token:
        print("Error: Okta domain and API token are required.")
        sys.exit(1)

    # Safety: ensure domain belongs to Okta-managed domains
    if not is_allowed_okta_domain(domain):
        print("Error: Domain must be an Okta-hosted domain (okta.com, oktapreview.com, okta-emea.com).")
        sys.exit(1)

    # Initialize auditor
    auditor = OktaWebAuthnAuditor(domain, api_token, detailed=args.detailed)
    
    # Test connection
    print("\nTesting connection to Okta...")
    try:
        test_response = auditor._make_request(f'{auditor.domain}/api/v1/users', {'limit': 1})
        print("Connection successful!")
    except Exception as e:
        print(f"Failed to connect to Okta: {e}")
        print("\nPlease check:")
        print("1. Your Okta domain is correct")
        print("2. Your API token is valid")
        print("3. Your API token has permission to read users and factors")
        sys.exit(1)
    
    # Run audit
    try:
        if args.status == 'ALL':
            # Audit all user statuses
            all_with: List[Dict] = []
            all_without: List[Dict] = []

            for status in ['ACTIVE', 'PROVISIONED', 'STAGED', 'SUSPENDED']:
                print(f"\nAuditing {status} users...")
                users = auditor.get_all_users(status=status)
                if users:
                    with_wa, without_wa = auditor.audit_users_for_webauthn(users)
                    all_with.extend(with_wa)
                    all_without.extend(without_wa)

            auditor.save_results(all_with, all_without)
        else:
            # Audit specific status
            users_with_webauthn, users_without_webauthn = auditor.audit_webauthn(status=args.status)
            auditor.save_results(users_with_webauthn, users_without_webauthn)

        print("\nAudit complete! Check the generated CSV and summary files for details.")

    except KeyboardInterrupt:
        print("\nAudit interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during audit: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
