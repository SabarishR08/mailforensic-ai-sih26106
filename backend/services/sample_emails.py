"""
Sample Email Data for Demo Mode
Realistic phishing, malware, and legitimate emails for testing
"""


SAMPLE_EMAILS = [
    {
        "id": "sample_001_banking_phish",
        "body": """URGENT: Your Bank Account Has Been Compromised

Dear Valued Customer,

We have detected suspicious activity on your account ending in ****4521. 
Your account has been temporarily limited for security purposes.

To restore full access, please verify your identity immediately:

Click here to verify: http://secure-banking-verify.com/login?id=4521&ref=urgent

You have 24 hours to respond before your account is permanently suspended.

If you did not authorize this activity, someone may have accessed your 
account without permission.

Account Status: RESTRICTED
Last Login: 2024-01-15 03:42 AM (Unknown Device - Moscow, Russia)

Please do not reply to this email. Contact us at 1-800-555-BANK.

Regards,
Security Department
National Trust Bank""",
        "headers": {
            "From": "security@nationaltrust-bank.com",
            "To": "sabarish.sec.lab@gmail.com",
            "Subject": "URGENT: Suspicious Activity Detected on Your Account",
            "Date": "Mon, 15 Jan 2024 08:30:00 +0000",
            "Message-ID": "<sample_001@phishing-samples.com>",
            "Received": "from mx.nationaltrust-bank.com (185.220.101.34) by gmail.com",
            "Return-Path": "<bounce@nationaltrust-bank.com>",
            "X-Mailer": "PHPMailer 6.1.4",
            "X-Originating-IP": "185.220.101.34"
        }
    },
    {
        "id": "sample_002_credential_harvest",
        "body": """[INTERNAL] Action Required: Password Expiration Notice

IT Security Alert - Do Not Ignore

Your corporate password will expire in 3 days. Failure to update will result 
in account lockout and potential data loss.

Employee ID: EMP-8847
Department: Engineering
Password Expires: January 18, 2024

To update your password, visit the Employee Portal:
https://corp-portal-login.microsoftonline.com/auth/signin

This is an automated message from Corporate IT Security.
Do not share this email with external parties.

For assistance, contact IT Helpdesk at ext. 4500""",
        "headers": {
            "From": "it-security@corp-portal-login.com",
            "To": "engineering-team@company.com",
            "Subject": "[INTERNAL] Password Expiration - Action Required in 3 Days",
            "Date": "Tue, 16 Jan 2024 09:15:00 +0000",
            "Message-ID": "<sample_002@phishing-samples.com>",
            "Received": "from mail.corp-portal-login.com (91.219.236.178) by gmail.com",
            "Return-Path": "<noreply@corp-portal-login.com>",
            "X-Originating-IP": "91.219.236.178"
        }
    },
    {
        "id": "sample_003_tax_scam",
        "body": """Tax Refund Notification - 2024

Congratulations! Based on your 2023 tax filing, you are eligible for a 
tax refund of $1,847.50.

To claim your refund, please complete the verification form:

https://irs-gov-refund2024.net/claim?taxpayer=sabarish

Required documents:
- Social Security Number
- Bank account details for direct deposit
- Last 4 digits of credit card

Failure to claim within 7 business days will result in forfeiture of funds.

This notification was sent by the Department of Treasury.
IRS Reference: TX-2024-8847-REF""",
        "headers": {
            "From": "refunds@irs-gov-refund2024.net",
            "To": "sabarish.sec.lab@gmail.com",
            "Subject": "Your 2024 Tax Refund of $1,847.50 is Ready",
            "Date": "Wed, 17 Jan 2024 14:22:00 +0000",
            "Message-ID": "<sample_003@phishing-samples.com>",
            "Received": "from mail.irs-gov-refund2024.net (103.43.75.12) by gmail.com",
            "Return-Path": "<bounce@irs-gov-refund2024.net>",
            "X-Originating-IP": "103.43.75.12"
        }
    },
    {
        "id": "sample_004_legitimate_newsletter",
        "body": """Weekly Security Digest - January 2024

Hi Sabarish,

Here's your weekly roundup of cybersecurity news:

1. Critical vulnerability discovered in OpenSSL 3.1.2
   - CVE-2024-0001 allows remote code execution
   - Patch available: Update immediately
   
2. New ransomware variant targeting healthcare
   - LockBit 4.0 identified in US hospital attacks
   - Backup verification recommended

3. GitHub Copilot security concerns
   - AI-generated code may contain vulnerabilities
   - Review all AI suggestions before merging

Stay secure,
The Security Team
Unsubscribe: https://security-digest.com/unsubscribe""",
        "headers": {
            "From": "digest@security-digest.com",
            "To": "sabarish.sec.lab@gmail.com",
            "Subject": "Weekly Security Digest - Critical Updates",
            "Date": "Thu, 18 Jan 2024 10:00:00 +0000",
            "Message-ID": "<sample_004@legitimate-samples.com>",
            "Received": "from mail.security-digest.com (203.0.113.42) by gmail.com",
            "Return-Path": "<noreply@security-digest.com>",
            "X-Mailer": "Mailchimp",
            "List-Unsubscribe": "<https://security-digest.com/unsubscribe>"
        }
    },
    {
        "id": "sample_005_malware_delivery",
        "body": """Invoice #INV-2024-0847 - Payment Due

Dear Accounts Payable,

Please find attached the invoice for services rendered in December 2023.

Invoice Details:
- Invoice Number: INV-2024-0847
- Amount Due: $4,250.00
- Due Date: January 31, 2024
- Payment Terms: Net 30

To download the invoice, click the secure link below:
http://docs-sharing-secure.com/dl/inv_2024_0847.pdf.exe

The document is password-protected for security. Use password: INV0847

Please process payment at your earliest convenience.

Best regards,
Sarah Johnson
Accounts Payable Department
Contoso Global Solutions""",
        "headers": {
            "From": "accounts.payable@contoso-gs.com",
            "To": "sabarish.sec.lab@gmail.com",
            "Subject": "Invoice #INV-2024-0847 - Payment Required",
            "Date": "Fri, 19 Jan 2024 16:45:00 +0000",
            "Message-ID": "<sample_005@phishing-samples.com>",
            "Received": "from smtp.contoso-gs.com (45.77.165.212) by gmail.com",
            "Return-Path": "<invoices@contoso-gs.com>",
            "X-Originating-IP": "45.77.165.212"
        }
    },
    {
        "id": "sample_006_ceo_fraud",
        "body": """Confidential - Wire Transfer Request

Hi,

I need you to process an urgent wire transfer for an acquisition we're 
closing today. Please handle this discreetly.

Transfer Details:
- Amount: $125,000.00
- Beneficiary: Horizon Ventures LLC
- Bank: First National Bank
- Account: 8847213456
- Routing: 021000021
- Reference: Project Alpha

This is time-sensitive. Reply to my personal email (john.ceo@protonmail.com) 
once completed.

Do NOT discuss this with anyone else in the company.

Thanks,
John Mitchell
CEO""",
        "headers": {
            "From": "john.ceo@protonmail.com",
            "To": "sabarish.sec.lab@gmail.com",
            "Subject": "Confidential - Urgent Wire Transfer",
            "Date": "Mon, 22 Jan 2024 07:15:00 +0000",
            "Message-ID": "<sample_006@phishing-samples.com>",
            "Received": "from mail.protonmail.ch (185.70.40.22) by gmail.com",
            "Return-Path": "<john.ceo@protonmail.com>",
            "X-Originating-IP": "185.70.40.22"
        }
    },
    {
        "id": "sample_007_legitimate_update",
        "body": """Your GitHub Pull Request Has Been Merged

Pull Request #247: Fix authentication token refresh
Repository: company/backend-api
Branch: main

Status: Merged by @sabarish

Changes:
- Fixed token refresh logic in auth middleware
- Added retry mechanism for failed token refreshes
- Updated unit tests

View the changes: https://github.com/company/backend-api/pull/247

---
You are receiving this because you were assigned.
Manage notification preferences: https://github.com/settings/notifications""",
        "headers": {
            "From": "notifications@github.com",
            "To": "sabarish.sec.lab@gmail.com",
            "Subject": "[company/backend-api] Pull Request #247 merged",
            "Date": "Tue, 23 Jan 2024 11:30:00 +0000",
            "Message-ID": "<sample_007@legitimate-samples.com>",
            "Received": "from github.com (140.82.121.3) by gmail.com",
            "Return-Path": "<notifications@github.com>",
            "X-GitHub-Request-Id": "ABC123-DEF456"
        }
    },
    {
        "id": "sample_008_sms_phishing",
        "body": """Your package delivery failed

Dear Customer,

Your package could not be delivered due to an incorrect address. 
A $2.99 re-delivery fee is required.

Track and pay now: https://dhl-delivery-track.com/pay?id=PKG884721

Package Details:
- Tracking: DHL-2024-88472134
- Status: Held at facility
- Fee: $2.99

Please complete payment within 48 hours or the package will be returned 
to sender.

DHL Express Customer Service""",
        "headers": {
            "From": "tracking@dhl-delivery-track.com",
            "To": "sabarish.sec.lab@gmail.com",
            "Subject": "Action Required: Package Delivery Failed",
            "Date": "Wed, 24 Jan 2024 15:20:00 +0000",
            "Message-ID": "<sample_008@phishing-samples.com>",
            "Received": "from mx.dhl-delivery-track.com (194.36.189.42) by gmail.com",
            "Return-Path": "<bounce@dhl-delivery-track.com>",
            "X-Originating-IP": "194.36.189.42"
        }
    }
]


def get_sample_emails(limit=None):
    """
    Get sample emails for demo mode.
    
    Args:
        limit: Maximum number of emails to return (None for all)
    
    Returns:
        List of email dictionaries formatted like Gmail API response
    """
    emails = SAMPLE_EMAILS[:limit] if limit else SAMPLE_EMAILS
    
    result = []
    for sample in emails:
        email = {
            'id': sample['id'],
            'body': sample['body'],
            'raw_body': sample['body'],
            'headers': sample.get('headers', {}),
            'raw_headers': '\n'.join(f'{k}: {v}' for k, v in sample.get('headers', {}).items())
        }
        result.append(email)
    
    return result
