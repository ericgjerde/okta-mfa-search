# Okta Security Audit Tools

A collection of Python scripts to audit security configurations across your Okta tenant. These tools help administrators track MFA enrollment, Device Trust status, and identify users who need security improvements.

**Tools included:** WebAuthn/FIDO2 audit, Device Trust enrollment tracking, and MFA adoption reports.

## 🔧 Available Tools

### 1. WebAuthn Factor Audit (`okta_webauthn_audit.py`)
Audits WebAuthn/FIDO2 authentication factor enrollment across all users.

**Use cases:**
- Track WebAuthn/FIDO2 adoption
- Identify users without phishing-resistant authentication
- Generate compliance reports for passwordless initiatives

### 2. Device Trust Audit (`okta_device_trust_audit.py`)
Audits Device Trust enrollment and categorizes users by their device security status.

**Use cases:**
- Monitor Device Trust rollout progress
- Identify users ready for device enrollment
- Track managed vs unmanaged devices
- Generate reports for zero-trust initiatives

## 🚀 Quick Start

### Prerequisites

1. Python 3.6 or higher
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create an Okta API Token:
   - Log into your Okta Admin Console
   - Navigate to Security > API > Tokens
   - Create a new token with read permissions for:
     - Users (`okta.users.read`)
     - Factors (`okta.factors.read`)
     - Devices (`okta.devices.read`) - required for Device Trust audit

### Basic Usage

Both tools support the same authentication methods:

```bash
# Set environment variables (recommended)
export OKTA_DOMAIN="your-domain.okta.com"
export OKTA_API_TOKEN="your-api-token-here"

# Run WebAuthn audit
python okta_webauthn_audit.py

# Run Device Trust audit
python okta_device_trust_audit.py

# Or use interactive mode (prompts for credentials)
python okta_webauthn_audit.py --detailed
python okta_device_trust_audit.py --detailed
```

## 📊 Output Files

Each tool generates timestamped CSV files and summary reports:

### WebAuthn Audit Output
- `users_with_webauthn_*.csv` - Users with WebAuthn configured
- `users_without_webauthn_*.csv` - Users needing WebAuthn
- `webauthn_audit_summary_*.txt` - Statistics and factor distribution

### Device Trust Audit Output
- `users_device_trust_enrolled_*.csv` - Users with Device Trust active
- `users_device_trust_pending_*.csv` - Users with Okta Verify but no devices
- `users_device_trust_not_enrolled_*.csv` - Users without Device Trust capability
- `device_trust_audit_summary_*.txt` - Statistics and recommendations

## 🎯 Common Use Cases

### Complete Security Audit
Run both tools to get a comprehensive view of your security posture:

```bash
# Audit everything with detailed output
python okta_webauthn_audit.py --detailed
python okta_device_trust_audit.py --detailed
```

### Monitor Specific User Groups
```bash
# Audit only active users (default)
python okta_device_trust_audit.py --status ACTIVE

# Audit all user statuses
python okta_device_trust_audit.py --status ALL

# Audit suspended users
python okta_webauthn_audit.py --status SUSPENDED
```

### Debugging Individual Users
Use the debug tool to troubleshoot specific users:

```bash
python debug_device_trust.py
# Enter domain, token, and user email when prompted
```

## 📋 Command Line Options

Both audit tools support these options:

- `--detailed`, `-d` - Enable detailed output with additional fields
- `--domain DOMAIN` - Specify Okta domain (alternative to env var)
- `--status STATUS` - User status to audit (ACTIVE, PROVISIONED, STAGED, SUSPENDED, ALL)
- `--help` - Show help message

## 🔐 Security Features

- **Domain Validation**: Only connects to official Okta domains (okta.com, oktapreview.com, okta-emea.com)
- **Secure Token Handling**: Uses getpass for hidden input, never logs tokens
- **Read-Only Operations**: Scripts only read data, never modify your Okta configuration
- **Rate Limit Handling**: Automatically manages Okta API rate limits

## 📈 Understanding Device Trust Results

The Device Trust audit categorizes users into three groups:

1. **ENROLLED** ✅
   - Has Okta Verify with FastPass
   - Has registered/managed devices
   - Fully compliant with Device Trust policies

2. **PENDING** ⚠️
   - Has Okta Verify installed
   - No registered devices yet
   - Ready for device enrollment

3. **NOT_ENROLLED** ❌
   - No Okta Verify
   - Cannot use Device Trust features
   - Needs Okta Verify deployment

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📝 License

MIT License - See LICENSE file for details

## ⚠️ Important Notes

- Never commit API tokens to version control
- Use service accounts with minimal required permissions
- Store tokens securely using your organization's secret management
- The scripts are read-only and safe to run in production

## 🐛 Troubleshooting

### No device data returned
Ensure your API token has device read permissions (`okta.devices.read`)

### All users show as PENDING for Device Trust
Check if Device Trust policies are properly configured in your Okta tenant

### Rate limiting errors
The scripts handle rate limiting automatically, but you can reduce load by:
- Auditing specific user groups with `--status`
- Running audits during off-peak hours

## 📚 Additional Resources

- [Okta WebAuthn Documentation](https://developer.okta.com/docs/guides/webauthn/)
- [Okta Device Trust Documentation](https://help.okta.com/en/prod/Content/Topics/Device-Trust/device-trust-overview.htm)
- [Okta API Reference](https://developer.okta.com/docs/reference/)