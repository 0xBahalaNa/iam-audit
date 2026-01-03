# iam_audit.py

A Python tool that audits all IAM users in your AWS account for MFA compliance.

## Overview

This script checks each IAM user to determine:
1. **Console Access** — Does the user have a password to log into AWS Console?
2. **MFA Status** — If they have console access, is MFA enabled?

## Requirements

- Python 3.x
- `boto3` library
- AWS CLI configured with credentials (`aws configure`)

### Install dependencies
```bash
pip install boto3
```

## Usage

```bash
python iam_audit.py
```

**Sample output:**
```
Checking: admin-user
    [PASS] MFA enabled for console user.
Checking: developer
    [FAIL] Console access WITHOUT MFA!
Checking: lambda-role-user
    [INFO] No console access (MFA not required).

========================================
Total users: 3
Compliant (MFA enabled): 1
No console access: 1
Non-compliant: 1

Audit started: 2026-01-02T14:30:00.123456
Audit completed: 2026-01-02T14:30:02.456789
Elapsed time: 2.33 seconds
Compliance rate: 33.3%

Results exported to:
  - iam_audit_2026-01-02T14-30-00.csv
  - iam_audit_2026-01-02T14-30-00.json
```

## Output Legend

| Status | Meaning |
|--------|---------|
| `[PASS]` | Console user with MFA enabled |
| `[FAIL]` | Console user WITHOUT MFA |
| `[INFO]` | No console access (programmatic only) ℹ|

## Export Formats

The tool automatically exports audit results in two formats for compliance reporting:

### CSV Export (`iam_audit_YYYY-MM-DDTHH-MM-SS.csv`)
- Opens directly in Excel or Google Sheets
- Ideal for auditor review and compliance officers
- Contains: username, console access status, MFA status, compliance result

**Example CSV:**
```csv
username,has_console_access,mfa_enabled,compliance_status
admin-user,True,True,PASS
developer,True,False,FAIL
lambda-role-user,False,False,INFO
```

### JSON Export (`iam_audit_YYYY-MM-DDTHH-MM-SS.json`)
- Machine-readable format for automation and tool integration
- Includes audit metadata (timestamps, compliance rate, user counts)
- Ideal for SIEM integration and security dashboards

**Example JSON:**
```json
{
    "metadata": {
        "audit_start": "2026-01-02T14:30:00.123456",
        "audit_end": "2026-01-02T14:30:02.456789",
        "elapsed_seconds": 2.33,
        "total_users": 3,
        "compliance_rate": "33.3%"
    },
    "findings": [
        {
            "username": "admin-user",
            "has_console_access": true,
            "mfa_enabled": true,
            "compliance_status": "PASS"
        }
    ]
}
```

## Key Concepts Learned

### AWS IAM API
| Concept | Description |
|---------|-------------|
| `iam.list_users()` | Get all IAM users |
| `iam.list_mfa_devices()` | Check MFA status |
| `iam.get_login_profile()` | Check console access |
| Exception handling | API throws error when config doesn't exist |

### Python Features
| Concept | Description |
|---------|-------------|
| `datetime` module | Timestamp tracking and ISO 8601 formatting |
| `csv.DictWriter` | Writing structured data to CSV files |
| `json.dump()` | Exporting Python objects to JSON format |
| List of dictionaries | Structured data collection for export |
| Context managers | Safe file handling with `with open()` |
| Functions & docstrings | Code organization and documentation |

## GRC Application

This tool supports compliance and audit requirements:

### Security Controls
- **CIS AWS Benchmark** — 1.10 (MFA enabled for all IAM users with console password)
- **SOC 2** — CC6.1 (Logical Access Controls)
- **NIST 800-53** — IA-2 (Multi-Factor Authentication)

### Audit Trail & Evidence
- **SOC 2** — CC6.1 (Audit trail with timestamps for control testing)
- **NIST 800-53** — AU-12 (Audit generation with timestamps and user identification)
- **ISO 27001** — A.12.4.1 (Event logging with timestamps)

### Compliance Reporting
- **CSV exports** for auditor review and compliance officer reporting
- **JSON exports** for SIEM integration and automated compliance dashboards
- **Compliance rate metrics** for executive and board reporting
- **Timestamped filenames** for evidence preservation and historical tracking

## Future Enhancements

- Check access key age
- Flag inactive users (90+ days)
- Email alerts for non-compliant users
- Root account MFA verification
- Password policy compliance checks
