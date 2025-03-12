# Security Policy

## Reporting a Vulnerability

The PermaLog team takes security issues seriously. We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contributions.

To report a security vulnerability, please email:

**github@bentlybro.com**

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

## Response Process

When you report an issue, we will:

1. Confirm receipt of your vulnerability report within 48 hours
2. Provide an estimated time frame for addressing the vulnerability
3. Notify you when the vulnerability is fixed
4. Publicly acknowledge your responsible disclosure (unless you prefer to remain anonymous)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Current | :white_check_mark: |

## Security Best Practices

When deploying PermaLog, we recommend the following security best practices:

1. **Use a strong, unique SECRET_KEY**: Change the default secret key in your .env file
2. **Restrict API access**: Use API keys with appropriate permissions
3. **Deploy behind HTTPS**: Always use TLS/SSL in production
4. **Regular updates**: Keep PermaLog and its dependencies up to date
5. **Secure database**: Ensure your SQLite database file has appropriate file permissions
6. **Backup encryption keys**: Securely back up your encryption keys
7. **Monitor logs**: Regularly review access logs for suspicious activity

Thank you for helping keep PermaLog and its users safe! 
