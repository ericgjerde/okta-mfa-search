#!/usr/bin/env python3
"""
Okta Device Trust Audit Script
Checks all active users in an Okta instance for Device Trust enrollment
and generates reports of who has/doesn't have Device Trust configured.
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import requests
from urllib.parse import urlparse
import time
from getpass import getpass


class OktaDeviceTrustAuditor:
    def __init__(self, domain: str, api_token: str, detailed: bool = False):
        """
        Initialize the Okta Device Trust auditor.

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

    def get_user_devices(self, user_id: str) -> List[Dict]:
        """Get all enrolled devices for a specific user."""
        url = f'{self.domain}/api/v1/users/{user_id}/devices'

        try:
            response = self._make_request(url)
            return response.json()
        except requests.exceptions.RequestException as e:
            # Some users may not have device endpoints available
            return []

    def get_user_factors(self, user_id: str) -> List[Dict]:
        """Get all enrolled factors for a specific user."""
        url = f'{self.domain}/api/v1/users/{user_id}/factors'

        try:
            response = self._make_request(url)
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching factors for user {user_id}: {e}")
            return []

    def check_device_trust_status(self, user_id: str, factors: List[Dict]) -> Tuple[bool, List[Dict], str]:
        """
        Check if a user has Device Trust enrolled.
        Returns: (has_device_trust, trusted_devices, trust_status)

        Trust status can be:
        - 'ENROLLED': Has Device Trust with enrolled devices
        - 'PENDING': Has Okta Verify but no trusted devices yet
        - 'NOT_ENROLLED': No Device Trust capability
        """
        # Check for Okta Verify factors (FastPass/signed_nonce is the key indicator)
        signed_nonce_factors = [
            f for f in factors
            if f.get('factorType') == 'signed_nonce'
            and f.get('provider', '').upper() == 'OKTA'
        ]

        # Also check for legacy push factors
        push_factors = [
            f for f in factors
            if f.get('factorType') == 'push'
            and f.get('provider', '').upper() == 'OKTA'
        ]

        okta_verify_factors = signed_nonce_factors + push_factors

        if not okta_verify_factors:
            return False, [], 'NOT_ENROLLED'

        # Get user's devices
        devices = self.get_user_devices(user_id)

        # Filter for managed/trusted devices
        # Note: The device structure has nested 'device' object
        trusted_devices = []
        for device_entry in devices:
            # Handle the nested structure - actual device data is in 'device' field
            actual_device = device_entry.get('device', device_entry)
            device_profile = actual_device.get('profile', {})
            device_status = actual_device.get('status', '').upper()

            # Check if device is managed or registered (both indicate Device Trust)
            is_managed = device_profile.get('managed', False)
            is_registered = device_profile.get('registered', False)

            # A device with ACTIVE status and either managed or registered is trusted
            if device_status == 'ACTIVE' and (is_managed or is_registered):
                device_info = {
                    'id': actual_device.get('id'),
                    'displayName': device_profile.get('displayName', 'Unknown Device'),
                    'platform': device_profile.get('platform', 'Unknown'),
                    'osVersion': device_profile.get('osVersion', 'Unknown'),
                    'managed': is_managed,
                    'registered': is_registered,
                    'lastUpdated': actual_device.get('lastUpdated', ''),
                    'status': device_status,
                    'secureHardwarePresent': device_profile.get('secureHardwarePresent', False),
                    'diskEncryptionType': device_profile.get('diskEncryptionType', 'Unknown')
                }
                trusted_devices.append(device_info)

        # If user has signed_nonce factors AND registered/managed devices, they have Device Trust
        if signed_nonce_factors and trusted_devices:
            return True, trusted_devices, 'ENROLLED'
        elif okta_verify_factors:
            # Has Okta Verify but no trusted devices (or only push without signed_nonce)
            return False, [], 'PENDING'
        else:
            return False, [], 'NOT_ENROLLED'

    def audit_users_for_device_trust(self, users: List[Dict]) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """
        Analyze provided users for Device Trust enrollment.
        Returns tuple of (enrolled_users, pending_users, not_enrolled_users)
        """
        enrolled_users: List[Dict] = []
        pending_users: List[Dict] = []
        not_enrolled_users: List[Dict] = []

        print(f"\nAnalyzing Device Trust enrollment for {len(users)} users...")

        for i, user in enumerate(users, 1):
            if i % 10 == 0:
                print(f"  Processing user {i}/{len(users)}...")

            user_id = user.get('id')
            factors = self.get_user_factors(user_id)

            # Check Device Trust status
            has_device_trust, trusted_devices, trust_status = self.check_device_trust_status(user_id, factors)

            # Get all factor types for reporting
            factor_types = []
            for f in factors:
                factor_type = f.get('factorType', 'unknown')
                provider = f.get('provider', '')
                if provider and provider != 'OKTA':
                    factor_types.append(f"{factor_type}:{provider}")
                else:
                    factor_types.append(factor_type)

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
                'deviceTrustStatus': trust_status,
                'trustedDeviceCount': len(trusted_devices),
                'userId': user_id
            }

            if self.detailed:
                # Add additional fields for detailed mode
                user_info['department'] = user.get('profile', {}).get('department', '')
                user_info['manager'] = user.get('profile', {}).get('manager', '')
                user_info['hasOktaVerify'] = 'Yes' if any(f.get('factorType') in ['push', 'signed_nonce'] for f in factors) else 'No'
                user_info['hasFastPass'] = 'Yes' if any(f.get('factorType') == 'signed_nonce' for f in factors) else 'No'

                # Add device details
                if trusted_devices:
                    device_summaries = []
                    for device in trusted_devices[:3]:  # Limit to first 3 devices for readability
                        managed_status = "Managed" if device['managed'] else "Registered"
                        device_summaries.append(
                            f"{device['displayName']} ({device['platform']} {device['osVersion']}, {managed_status})"
                        )
                    user_info['trustedDevices'] = '; '.join(device_summaries)
                else:
                    user_info['trustedDevices'] = 'None'

            # Categorize users
            if trust_status == 'ENROLLED':
                enrolled_users.append(user_info)
            elif trust_status == 'PENDING':
                pending_users.append(user_info)
            else:
                not_enrolled_users.append(user_info)

        print(f"\nAudit complete!")
        print(f"  Users with Device Trust enrolled: {len(enrolled_users)}")
        print(f"  Users with Okta Verify (pending device enrollment): {len(pending_users)}")
        print(f"  Users without Device Trust capability: {len(not_enrolled_users)}")

        return enrolled_users, pending_users, not_enrolled_users

    def audit_device_trust(self, status: str = 'ACTIVE') -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """
        Fetch users by status and analyze for Device Trust.
        Returns tuple of (enrolled_users, pending_users, not_enrolled_users)
        """
        users = self.get_all_users(status=status)
        return self.audit_users_for_device_trust(users)

    def save_results(self, enrolled: List[Dict], pending: List[Dict], not_enrolled: List[Dict]) -> None:
        """Save audit results to CSV files and generate summary."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        mode_suffix = '_detailed' if self.detailed else ''

        # Define CSV fields based on mode
        if self.detailed:
            csv_fields = [
                'email', 'login', 'firstName', 'lastName', 'department', 'manager',
                'status', 'created', 'lastLogin', 'deviceTrustStatus',
                'hasOktaVerify', 'hasFastPass', 'trustedDeviceCount', 'trustedDevices',
                'factorTypes', 'factorCount', 'userId'
            ]
        else:
            csv_fields = [
                'email', 'login', 'firstName', 'lastName',
                'status', 'created', 'lastLogin', 'deviceTrustStatus',
                'trustedDeviceCount', 'factorTypes', 'factorCount', 'userId'
            ]

        # Save enrolled users
        enrolled_file = f'users_device_trust_enrolled{mode_suffix}_{timestamp}.csv'
        with open(enrolled_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(enrolled)
        print(f"\nSaved users WITH Device Trust enrolled to: {enrolled_file}")

        # Save pending users
        pending_file = f'users_device_trust_pending{mode_suffix}_{timestamp}.csv'
        with open(pending_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(pending)
        print(f"Saved users PENDING Device Trust enrollment to: {pending_file}")

        # Save not enrolled users
        not_enrolled_file = f'users_device_trust_not_enrolled{mode_suffix}_{timestamp}.csv'
        with open(not_enrolled_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(not_enrolled)
        print(f"Saved users WITHOUT Device Trust capability to: {not_enrolled_file}")

        # Generate summary report
        summary_file = f'device_trust_audit_summary{mode_suffix}_{timestamp}.txt'
        with open(summary_file, 'w') as f:
            f.write("Okta Device Trust Audit Summary\n")
            f.write("=" * 50 + "\n")
            f.write(f"Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Okta Domain: {self.domain}\n")
            f.write(f"Mode: {'Detailed' if self.detailed else 'Standard'}\n\n")

            total_users = len(enrolled) + len(pending) + len(not_enrolled)
            f.write(f"Total Active Users Audited: {total_users}\n\n")

            if total_users > 0:
                enrolled_pct = (len(enrolled) / total_users) * 100
                pending_pct = (len(pending) / total_users) * 100
                not_enrolled_pct = (len(not_enrolled) / total_users) * 100
            else:
                enrolled_pct = 0.0
                pending_pct = 0.0
                not_enrolled_pct = 0.0

            f.write("Device Trust Status Breakdown:\n")
            f.write("-" * 30 + "\n")
            f.write(f"✓ ENROLLED (Device Trust active): {len(enrolled)} users ({enrolled_pct:.1f}%)\n")
            f.write(f"⚠ PENDING (Okta Verify, no devices): {len(pending)} users ({pending_pct:.1f}%)\n")
            f.write(f"✗ NOT ENROLLED (No capability): {len(not_enrolled)} users ({not_enrolled_pct:.1f}%)\n")

            if self.detailed and enrolled:
                # Device statistics for enrolled users
                f.write("\n" + "=" * 50 + "\n")
                f.write("Device Distribution (Enrolled Users):\n\n")

                device_counts = {}
                total_devices = 0
                for user in enrolled:
                    count = user.get('trustedDeviceCount', 0)
                    device_counts[count] = device_counts.get(count, 0) + 1
                    total_devices += count

                for count, users_count in sorted(device_counts.items()):
                    f.write(f"  {count} device(s): {users_count} users\n")

                if enrolled:
                    avg_devices = total_devices / len(enrolled)
                    f.write(f"\nAverage devices per enrolled user: {avg_devices:.1f}\n")

            # Factor distribution for users without Device Trust
            f.write("\n" + "=" * 50 + "\n")
            f.write("Factor Distribution (Users without Device Trust):\n\n")

            factor_counts = {}
            for user in not_enrolled:
                factors = user.get('factorTypes', '').split(', ')
                for factor in factors:
                    if factor and factor != 'None':
                        factor_counts[factor] = factor_counts.get(factor, 0) + 1

            for factor, count in sorted(factor_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {factor}: {count} users\n")

            # Next steps recommendations
            f.write("\n" + "=" * 50 + "\n")
            f.write("Recommendations:\n\n")

            if pending:
                f.write(f"• {len(pending)} users have Okta Verify but need device enrollment\n")
                f.write("  Action: Guide these users through device enrollment process\n\n")

            if not_enrolled:
                f.write(f"• {len(not_enrolled)} users need Okta Verify installation\n")
                f.write("  Action: Deploy Okta Verify and enable Device Trust policies\n\n")

            if enrolled:
                f.write(f"• {len(enrolled)} users are successfully enrolled\n")
                f.write("  Action: Monitor for compliance and device health\n")

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
        description='Audit Okta users for Device Trust enrollment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard audit using environment variables
  export OKTA_DOMAIN="example.okta.com"
  export OKTA_API_TOKEN="your-token-here"
  python okta_device_trust_audit.py

  # Detailed audit with prompts for credentials
  python okta_device_trust_audit.py --detailed

  # Quick audit with inline credentials (not recommended for production)
  OKTA_DOMAIN="example.okta.com" OKTA_API_TOKEN="token" python okta_device_trust_audit.py
        """
    )

    parser.add_argument(
        '--detailed', '-d',
        action='store_true',
        help='Enable detailed output mode with device information and additional statistics'
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

    print("Okta Device Trust Audit Tool")
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
    auditor = OktaDeviceTrustAuditor(domain, api_token, detailed=args.detailed)

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
        print("3. Your API token has permission to read users, factors, and devices")
        sys.exit(1)

    # Run audit
    try:
        if args.status == 'ALL':
            # Audit all user statuses
            all_enrolled: List[Dict] = []
            all_pending: List[Dict] = []
            all_not_enrolled: List[Dict] = []

            for status in ['ACTIVE', 'PROVISIONED', 'STAGED', 'SUSPENDED']:
                print(f"\nAuditing {status} users...")
                users = auditor.get_all_users(status=status)
                if users:
                    enrolled, pending, not_enrolled = auditor.audit_users_for_device_trust(users)
                    all_enrolled.extend(enrolled)
                    all_pending.extend(pending)
                    all_not_enrolled.extend(not_enrolled)

            auditor.save_results(all_enrolled, all_pending, all_not_enrolled)
        else:
            # Audit specific status
            enrolled, pending, not_enrolled = auditor.audit_device_trust(status=args.status)
            auditor.save_results(enrolled, pending, not_enrolled)

        print("\nAudit complete! Check the generated CSV and summary files for details.")

    except KeyboardInterrupt:
        print("\nAudit interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during audit: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()