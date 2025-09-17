#!/usr/bin/env python3
"""
Debug script to understand Device Trust data from Okta API
"""

import os
import sys
import json
import requests
from urllib.parse import urlparse
from getpass import getpass


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
    print("Okta Device Trust Debug Tool")
    print("=" * 50)

    # Get configuration
    domain = os.environ.get('OKTA_DOMAIN')
    api_token = os.environ.get('OKTA_API_TOKEN')

    if not domain:
        domain = input("Enter your Okta domain (e.g., example.okta.com): ").strip()

    if not api_token:
        print("\nEnter your Okta API token")
        api_token = getpass("API Token: ").strip()

    # Get specific user email to debug
    user_email = input("\nEnter a user email to debug (e.g., user@example.com): ").strip()

    if not domain or not api_token or not user_email:
        print("Error: All fields are required.")
        sys.exit(1)

    # Safety check
    if not is_allowed_okta_domain(domain):
        print("Error: Domain must be an Okta-hosted domain.")
        sys.exit(1)

    # Setup
    if not domain.startswith('https://'):
        domain = f'https://{domain}'

    headers = {
        'Authorization': f'SSWS {api_token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    session = requests.Session()
    session.headers.update(headers)

    print(f"\nSearching for user: {user_email}")

    # Find the user
    try:
        response = session.get(
            f'{domain}/api/v1/users',
            params={'q': user_email, 'limit': 10}
        )
        response.raise_for_status()
        users = response.json()

        if not users:
            print(f"User not found: {user_email}")
            sys.exit(1)

        # Find exact match
        user = None
        for u in users:
            if u.get('profile', {}).get('email', '').lower() == user_email.lower():
                user = u
                break

        if not user:
            print(f"Exact user match not found. Found these similar users:")
            for u in users:
                print(f"  - {u.get('profile', {}).get('email')}")
            sys.exit(1)

        user_id = user['id']
        print(f"Found user: {user['profile'].get('firstName')} {user['profile'].get('lastName')} (ID: {user_id})")

    except Exception as e:
        print(f"Error finding user: {e}")
        sys.exit(1)

    # Get factors
    print("\n" + "=" * 50)
    print("FACTORS:")
    print("=" * 50)
    try:
        response = session.get(f'{domain}/api/v1/users/{user_id}/factors')
        response.raise_for_status()
        factors = response.json()

        for factor in factors:
            print(f"\nFactor Type: {factor.get('factorType')}")
            print(f"Provider: {factor.get('provider')}")
            print(f"Status: {factor.get('status')}")

            if factor.get('factorType') in ['push', 'signed_nonce']:
                print("*** This is Okta Verify ***")
                print(f"Full factor data: {json.dumps(factor, indent=2)}")

        if not factors:
            print("No factors enrolled")

    except Exception as e:
        print(f"Error getting factors: {e}")

    # Get devices
    print("\n" + "=" * 50)
    print("DEVICES:")
    print("=" * 50)
    try:
        response = session.get(f'{domain}/api/v1/users/{user_id}/devices')
        response.raise_for_status()
        devices = response.json()

        if devices:
            print(f"Found {len(devices)} device(s):")
            for i, device in enumerate(devices, 1):
                print(f"\n--- Device {i} ---")
                print(f"ID: {device.get('id')}")
                print(f"Status: {device.get('status')}")
                print(f"Created: {device.get('created')}")
                print(f"Last Updated: {device.get('lastUpdated')}")

                profile = device.get('profile', {})
                print(f"Display Name: {profile.get('displayName')}")
                print(f"Platform: {profile.get('platform')}")
                print(f"OS Version: {profile.get('osVersion')}")
                print(f"Managed: {profile.get('managed')}")
                print(f"Registered: {profile.get('registered')}")
                print(f"Secure Hardware Present: {profile.get('secureHardwarePresent')}")
                print(f"Device Trust Status: {profile.get('trustLevel')}")

                # Show full device data for analysis
                print(f"\nFull device data:")
                print(json.dumps(device, indent=2))
        else:
            print("No devices found")

    except Exception as e:
        print(f"Error getting devices: {e}")
        # Try to get more info about the error
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status: {e.response.status_code}")
            print(f"Response body: {e.response.text}")

    # Check for Okta FastPass/Device Trust in factors
    print("\n" + "=" * 50)
    print("DEVICE TRUST ANALYSIS:")
    print("=" * 50)

    has_okta_verify = any(
        f.get('factorType') in ['push', 'signed_nonce']
        and f.get('provider', '').upper() == 'OKTA'
        for f in factors
    )

    print(f"Has Okta Verify: {has_okta_verify}")

    # Look for signed_nonce specifically (FastPass)
    fastpass_factors = [
        f for f in factors
        if f.get('factorType') == 'signed_nonce'
    ]

    if fastpass_factors:
        print(f"Has Okta FastPass: Yes ({len(fastpass_factors)} factor(s))")
        for fp in fastpass_factors:
            print(f"  - Status: {fp.get('status')}")
            if 'profile' in fp:
                print(f"  - Profile: {json.dumps(fp['profile'], indent=4)}")
    else:
        print("Has Okta FastPass: No")

    print("\n" + "=" * 50)
    print("SUMMARY:")
    print("=" * 50)
    print("Review the above data to understand how Device Trust appears in your Okta tenant.")
    print("Look for:")
    print("1. 'signed_nonce' factor type (indicates FastPass/Device Trust)")
    print("2. Device 'managed' or 'registered' flags")
    print("3. Device 'trustLevel' field")
    print("4. Any other device trust indicators in the raw JSON")


if __name__ == '__main__':
    main()