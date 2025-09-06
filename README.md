# Okta WebAuthn Factor Audit Tool

A Python script to audit WebAuthn authentication factors across all active users in your Okta instance.

## Features

- Fetches all active users from your Okta instance
- Checks each user for WebAuthn authentication factors
- Generates CSV reports of users with and without WebAuthn
- Creates a summary report with statistics
- Handles Okta API rate limiting automatically
- Shows other enrolled factor types for users without WebAuthn

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create an Okta API Token:
   - Log into your Okta Admin Console
   - Navigate to Security > API > Tokens
   - Create a new token and save it securely

## Usage

### Method 1: Environment Variables (Recommended)

Set your Okta credentials as environment variables:

```bash
export OKTA_DOMAIN="your-domain.okta.com"
export OKTA_API_TOKEN="your-api-token-here"
python okta_webauthn_audit.py
```

### Method 2: Interactive Prompt

Run the script and enter credentials when prompted:

```bash
python okta_webauthn_audit.py
```

## Output Files

The script generates three files with timestamps:

1. **users_with_webauthn_YYYYMMDD_HHMMSS.csv** - Users who have WebAuthn configured
2. **users_without_webauthn_YYYYMMDD_HHMMSS.csv** - Users who need WebAuthn enrollment
3. **webauthn_audit_summary_YYYYMMDD_HHMMSS.txt** - Summary statistics and factor distribution

## CSV Fields

Each CSV contains:
- Email
- Login
- First Name
- Last Name
- Status
- Created Date
- Last Login
- Factor Types (all enrolled factors)
- Factor Count
- User ID

## Security Notes

- Never commit your API token to version control
- The API token needs read permissions for users and factors
- Consider using a service account with minimal required permissions
- Store API tokens securely using your organization's secret management solution

## Rate Limiting

The script automatically handles Okta's rate limiting:
- Monitors rate limit headers
- Pauses when approaching limits
- Retries automatically if rate limited

## Requirements

- Python 3.6+
- `requests` library
- Valid Okta API token with user/factor read permissions