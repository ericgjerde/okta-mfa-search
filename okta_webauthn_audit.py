#!/usr/bin/env python3
"""
Okta WebAuthn Factor Audit Script
Checks all active users in an Okta instance for WebAuthn authentication factors
and generates a report of who has/doesn't have WebAuthn configured.
"""

import os
import sys
import csv
import json
from datetime import datetime
from typing import List, Dict, Optional
import requests
from urllib.parse import urlparse, parse_qs
import time


class OktaWebAuthnAuditor:
    def __init__(self, domain: str, api_token: str):
        """
        Initialize the Okta WebAuthn auditor.
        
        Args:
            domain: Your Okta domain (e.g., 'example.okta.com' or 'example.oktapreview.com')
            api_token: Your Okta API token
        """
        self.domain = domain.rstrip('/')
        if not self.domain.startswith('https://'):
            self.domain = f'https://{self.domain}'
        
        self.api_token = api_token
        self.headers = {
            'Authorization': f'SSWS {api_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Rate limiting - Okta has default limits
        self.rate_limit_remaining = 1000
        self.rate_limit_reset = 0
        
    def _make_request(self, url: str, params: Optional[Dict] = None) -> requests.Response:
        """
        Make a request to Okta API with rate limiting handling.
        """
        # Check rate limiting
        if self.rate_limit_remaining < 10:
            wait_time = max(0, self.rate_limit_reset - time.time())
            if wait_time > 0:
                print(f"Rate limit approaching, waiting {wait_time:.1f} seconds...")
                time.sleep(wait_time + 1)
        
        response = self.session.get(url, params=params)
        
        # Update rate limit info from headers
        if 'x-rate-limit-remaining' in response.headers:
            self.rate_limit_remaining = int(response.headers['x-rate-limit-remaining'])
        if 'x-rate-limit-reset' in response.headers:
            self.rate_limit_reset = int(response.headers['x-rate-limit-reset'])
        
        # Handle rate limiting
        if response.status_code == 429:
            retry_after = int(response.headers.get('x-rate-limit-reset', 60))
            print(f"Rate limited. Waiting {retry_after} seconds...")
            time.sleep(retry_after)
            return self._make_request(url, params)
        
        response.raise_for_status()
        return response
    
    def get_all_users(self, status: str = 'ACTIVE') -> List[Dict]:
        """
        Fetch all users from Okta with the specified status.
        
        Args:
            status: User status filter (ACTIVE, PROVISIONED, etc.)
        
        Returns:
            List of user dictionaries
        """
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
    
    def get_user_factors(self, user_id: str) -> List[Dict]:
        """
        Get all enrolled factors for a specific user.
        
        Args:
            user_id: The Okta user ID
        
        Returns:
            List of factor dictionaries
        """
        url = f'{self.domain}/api/v1/users/{user_id}/factors'
        
        try:
            response = self._make_request(url)
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching factors for user {user_id}: {e}")
            return []
    
    def has_webauthn_factor(self, factors: List[Dict]) -> bool:
        """
        Check if any of the factors is a WebAuthn factor.
        
        Args:
            factors: List of factor dictionaries
        
        Returns:
            True if user has WebAuthn factor, False otherwise
        """
        for factor in factors:
            # WebAuthn factors have factorType of 'webauthn'
            if factor.get('factorType') == 'webauthn' and factor.get('status') == 'ACTIVE':
                return True
        return False
    
    def audit_users(self, users: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Audit all users for WebAuthn factors.
        
        Args:
            users: List of user dictionaries
        
        Returns:
            Dictionary with 'has_webauthn' and 'no_webauthn' lists
        """
        results = {
            'has_webauthn': [],
            'no_webauthn': []
        }
        
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
            
            # Get user's factors
            factors = self.get_user_factors(user_id)
            
            # Check for WebAuthn
            has_webauthn = self.has_webauthn_factor(factors)
            
            # Prepare user info
            user_info = {
                'id': user_id,
                'email': email,
                'login': login,
                'firstName': first_name,
                'lastName': last_name,
                'status': user['status'],
                'created': user.get('created', ''),
                'lastLogin': user.get('lastLogin', ''),
                'has_webauthn': has_webauthn,
                'factor_count': len(factors),
                'factor_types': ', '.join(set(f.get('factorType', 'unknown') for f in factors if f.get('status') == 'ACTIVE'))
            }
            
            if has_webauthn:
                results['has_webauthn'].append(user_info)
            else:
                results['no_webauthn'].append(user_info)
        
        return results
    
    def save_results(self, results: Dict[str, List[Dict]], output_dir: str = '.'):
        """
        Save audit results to CSV files.
        
        Args:
            results: Dictionary with audit results
            output_dir: Directory to save output files
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save users WITH WebAuthn
        with_webauthn_file = os.path.join(output_dir, f'users_with_webauthn_{timestamp}.csv')
        if results['has_webauthn']:
            with open(with_webauthn_file, 'w', newline='') as f:
                fieldnames = ['email', 'login', 'firstName', 'lastName', 'status', 
                             'created', 'lastLogin', 'factor_types', 'factor_count', 'id']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(results['has_webauthn'])
            print(f"\nUsers WITH WebAuthn saved to: {with_webauthn_file}")
        
        # Save users WITHOUT WebAuthn
        without_webauthn_file = os.path.join(output_dir, f'users_without_webauthn_{timestamp}.csv')
        if results['no_webauthn']:
            with open(without_webauthn_file, 'w', newline='') as f:
                fieldnames = ['email', 'login', 'firstName', 'lastName', 'status', 
                             'created', 'lastLogin', 'factor_types', 'factor_count', 'id']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(results['no_webauthn'])
            print(f"Users WITHOUT WebAuthn saved to: {without_webauthn_file}")
        
        # Save summary report
        summary_file = os.path.join(output_dir, f'webauthn_audit_summary_{timestamp}.txt')
        with open(summary_file, 'w') as f:
            f.write("Okta WebAuthn Factor Audit Summary\n")
            f.write("=" * 50 + "\n")
            f.write(f"Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Okta Domain: {self.domain}\n\n")
            
            total_users = len(results['has_webauthn']) + len(results['no_webauthn'])
            f.write(f"Total Active Users Audited: {total_users}\n")
            f.write(f"Users WITH WebAuthn: {len(results['has_webauthn'])} ({len(results['has_webauthn'])/total_users*100:.1f}%)\n")
            f.write(f"Users WITHOUT WebAuthn: {len(results['no_webauthn'])} ({len(results['no_webauthn'])/total_users*100:.1f}%)\n")
            
            f.write("\n" + "=" * 50 + "\n")
            f.write("Factor Type Distribution (for users without WebAuthn):\n")
            factor_distribution = {}
            for user in results['no_webauthn']:
                factors = user.get('factor_types', '').split(', ')
                for factor in factors:
                    if factor:
                        factor_distribution[factor] = factor_distribution.get(factor, 0) + 1
            
            for factor_type, count in sorted(factor_distribution.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {factor_type}: {count} users\n")
        
        print(f"Summary report saved to: {summary_file}")
        
        return {
            'with_webauthn_file': with_webauthn_file,
            'without_webauthn_file': without_webauthn_file,
            'summary_file': summary_file
        }


def main():
    """Main execution function."""
    print("Okta WebAuthn Factor Audit Tool")
    print("=" * 50)
    
    # Get configuration from environment variables or prompt
    domain = os.environ.get('OKTA_DOMAIN')
    api_token = os.environ.get('OKTA_API_TOKEN')
    
    if not domain:
        domain = input("Enter your Okta domain (e.g., example.okta.com): ").strip()
    
    if not api_token:
        print("\nEnter your Okta API token")
        print("(You can create one in Okta Admin > Security > API > Tokens)")
        api_token = input("API Token: ").strip()
    
    if not domain or not api_token:
        print("Error: Okta domain and API token are required.")
        sys.exit(1)
    
    # Initialize auditor
    auditor = OktaWebAuthnAuditor(domain, api_token)
    
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
        print("3. Your API token has appropriate permissions")
        sys.exit(1)
    
    # Fetch active users
    users = auditor.get_all_users(status='ACTIVE')
    
    if not users:
        print("No active users found.")
        sys.exit(0)
    
    # Audit users
    results = auditor.audit_users(users)
    
    # Display summary
    print("\n" + "=" * 50)
    print("AUDIT RESULTS")
    print("=" * 50)
    total_users = len(results['has_webauthn']) + len(results['no_webauthn'])
    print(f"Total Active Users: {total_users}")
    print(f"Users WITH WebAuthn: {len(results['has_webauthn'])} ({len(results['has_webauthn'])/total_users*100:.1f}%)")
    print(f"Users WITHOUT WebAuthn: {len(results['no_webauthn'])} ({len(results['no_webauthn'])/total_users*100:.1f}%)")
    
    # Save results
    saved_files = auditor.save_results(results)
    
    print("\n" + "=" * 50)
    print("Audit complete! Results have been saved.")
    print("\nYou can find:")
    print("- List of users WITH WebAuthn in the CSV file")
    print("- List of users WITHOUT WebAuthn in the CSV file (for follow-up)")
    print("- Summary report with statistics")


if __name__ == '__main__':
    main()