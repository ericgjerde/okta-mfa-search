# Okta WebAuthn Factor Audit Tool

A Python script to audit WebAuthn authentication factors across all users in your Okta instance.

## Features

- Fetches users from your Okta instance (configurable by status)
- Checks each user for WebAuthn authentication factors
- Generates CSV reports of users with and without WebAuthn
- Creates a summary report with statistics
- Handles Okta API rate limiting automatically
- Shows other enrolled factor types for users without WebAuthn
- **Detailed mode** provides additional user fields and WebAuthn authenticator analysis
- Support for auditing different user statuses (ACTIVE, PROVISIONED, STAGED, etc.)

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

### Basic Usage

```bash
# Standard audit using environment variables
export OKTA_DOMAIN="your-domain.okta.com"
export OKTA_API_TOKEN="your-api-token-here"
python okta_webauthn_audit.py

# Interactive mode - prompts for credentials
python okta_webauthn_audit.py

# Detailed mode with additional statistics
python okta_webauthn_audit.py --detailed

# Audit all user statuses (not just ACTIVE)
python okta_webauthn_audit.py --status ALL

# Audit specific user status
python okta_webauthn_audit.py --status SUSPENDED
```

### Command Line Options

- `--detailed`, `-d`: Enable detailed output with additional user fields and statistics
- `--domain`: Specify Okta domain (alternative to OKTA_DOMAIN env var)
- `--status`: User status to audit (ACTIVE, PROVISIONED, STAGED, SUSPENDED, or ALL)
- `--help`: Show help message with all options

## Output Files

The script generates three files with timestamps:

### Standard Mode
- `users_with_webauthn_YYYYMMDD_HHMMSS.csv` - Users who have WebAuthn configured
- `users_without_webauthn_YYYYMMDD_HHMMSS.csv` - Users who need WebAuthn enrollment
- `webauthn_audit_summary_YYYYMMDD_HHMMSS.txt` - Summary statistics and factor distribution

### Detailed Mode (--detailed flag)
- `users_with_webauthn_detailed_YYYYMMDD_HHMMSS.csv` - Enhanced user data with WebAuthn details
- `users_without_webauthn_detailed_YYYYMMDD_HHMMSS.csv` - Enhanced user data for non-WebAuthn users
- `webauthn_audit_summary_detailed_YYYYMMDD_HHMMSS.txt` - Extended statistics including authenticator types

## CSV Fields

### Standard Mode
- Email, Login, First Name, Last Name
- Status, Created Date, Last Login
- Factor Types (all enrolled factors)
- Factor Count, User ID

### Detailed Mode (additional fields)
- Department
- Has WebAuthn (Yes/No)
- WebAuthn Details (authenticator name for users with WebAuthn)
- Human-readable factor names

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