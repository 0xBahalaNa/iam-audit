"""
iam_audit.py
Audits all IAM users in your AWS account for MFA and access key compliance.
Checks performed:
    1. Console Access - Does the user have a password to log into AWS Console?
    2. MFA Status - If they have console access, is MFA enabled?
    3. Access Key Age - Are any active access keys older than 90 days?
Output:
    [PASS] - Console user with MFA enabled / Access key within rotation period
    [FAIL] - Console user WITHOUT MFA / Active access key over 90 days old
    [INFO] - No console access (programmatic only, MFA not required)
    [N/A]  - No access keys exist for the user
Usage:
    python iam_audit.py
Requirements:
    - boto3 installed (pip install boto3)
    - AWS credentials configured (aws configure)
"""

# Import associated AWS module for script.
import boto3
from datetime import datetime, timezone
import csv
import json


def export_to_csv(audit_results, timestamp):
    """
    Export audit results to CSV file with timestamp in filename.

    Args:
        audit_results: List of dictionaries containing user audit data
        timestamp: ISO 8601 timestamp string for filename

    Returns:
        filename: Name of the created CSV file
    """
    filename = f"iam_audit_{timestamp}.csv"

    fieldnames = [
        'username', 'has_console_access', 'mfa_enabled', 'compliance_status',
        'access_key_count', 'oldest_key_age_days', 'key_compliance_status'
    ]

    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(audit_results)

    return filename


def export_to_json(audit_results, metadata, timestamp):
    """
    Export audit results to JSON file with metadata.

    Args:
        audit_results: List of dictionaries containing user audit data
        metadata: Dictionary containing audit metadata (timestamps, counts, rates)
        timestamp: ISO 8601 timestamp string for filename

    Returns:
        filename: Name of the created JSON file
    """
    filename = f"iam_audit_{timestamp}.json"

    report = {
        'metadata': {
            'audit_start': metadata['start_time'],
            'audit_end': metadata['end_time'],
            'elapsed_seconds': metadata['elapsed_seconds'],
            'total_users': metadata['total_users'],
            'compliance_rate': metadata['compliance_rate'],
            'key_compliance_rate': metadata['key_compliance_rate']
        },
        'findings': audit_results
    }

    with open(filename, 'w') as jsonfile:
        json.dump(report, jsonfile, indent=4)

    return filename


# Create IAM client to interact with AWS IAM service.
iam = boto3.client('iam')

# Get a list of all IAM users in the account.
iam_users = iam.list_users()  
users = iam_users['Users']

# Counters to track compliance stats.
total_users = len(users)
compliant_count = 0
no_console_count = 0
keys_compliant_count = 0
keys_noncompliant_count = 0

# Data collection for export and audit trail.
audit_results = []
audit_start = datetime.now()

# Main loop to check each user for MFA compliance. 
for user in users:
    username = user['UserName']
    print(f"Checking: {username}")
    
    # Check returns a list of MFA devices. Empty list means no MFA.
    mfa_response = iam.list_mfa_devices(UserName=username)
    mfa_devices = mfa_response['MFADevices']

    # Check to see if user has console access. Throws except if no console access.
    try:
        iam.get_login_profile(UserName=username)
        has_console = True
    except iam.exceptions.NoSuchEntityException:
        has_console = False

    # Evaluate compliance based on both checks.
    # Console user with MFA enabled.
    if has_console and mfa_devices:
        compliant_count += 1
        print("    [PASS] MFA enabled for console user.")
        compliance_status = 'PASS'

    # Console user without MFA enabled.
    elif has_console and not mfa_devices:
        print("    [FAIL] Console access WITHOUT MFA!")
        compliance_status = 'FAIL'

    # No console access does not require MFA.
    else:
        no_console_count += 1
        print("    [INFO] No console access (MFA not required).")
        compliance_status = 'INFO'

    # Check access key age for compliance with rotation policy.
    # IA-5(1) requires periodic authenticator rotation — 90-day threshold
    # matches CIS AWS Benchmark 1.14 and common FedRAMP/CJIS expectations.
    keys_response = iam.list_access_keys(UserName=username)
    access_keys = keys_response['AccessKeyMetadata']

    # Track the oldest key and whether any active key exceeds 90 days.
    oldest_key_age = 0
    key_compliance = 'N/A'

    if access_keys:
        now_utc = datetime.now(timezone.utc)
        user_keys_compliant = True

        for key in access_keys:
            key_id = key['AccessKeyId']
            key_status = key['Status']
            # CreateDate is timezone-aware (UTC) from boto3, so we compare
            # against timezone-aware now() to avoid TypeError.
            key_age_days = (now_utc - key['CreateDate']).days
            oldest_key_age = max(oldest_key_age, key_age_days)

            # Only flag active keys — inactive keys are already disabled.
            if key_status == 'Active' and key_age_days > 90:
                print(f"    [FAIL] Access key ...{key_id[-4:]} is {key_age_days} days old (Active)")
                user_keys_compliant = False
            elif key_status == 'Active':
                print(f"    [PASS] Access key ...{key_id[-4:]} is {key_age_days} days old (Active)")
            else:
                print(f"    [INFO] Access key ...{key_id[-4:]} is {key_age_days} days old (Inactive)")

        if user_keys_compliant:
            key_compliance = 'PASS'
            keys_compliant_count += 1
        else:
            key_compliance = 'FAIL'
            keys_noncompliant_count += 1
    else:
        print("    [N/A] No access keys.")

    # Store user audit data for export.
    user_record = {
        'username': username,
        'has_console_access': has_console,
        'mfa_enabled': bool(mfa_devices),
        'compliance_status': compliance_status,
        'access_key_count': len(access_keys),
        'oldest_key_age_days': oldest_key_age,
        'key_compliance_status': key_compliance
    }
    audit_results.append(user_record)

# Capture audit completion time and calculate elapsed time.
audit_end = datetime.now()
elapsed = (audit_end - audit_start).total_seconds()

# Compliance summary of results.
print("\n" + "=" * 40)
print("MFA Compliance:")
print(f"  Total users: {total_users}")
print(f"  Compliant (MFA enabled): {compliant_count}")
print(f"  No console access: {no_console_count}")
print(f"  Non-compliant: {total_users - compliant_count - no_console_count}")

# Users with at least one access key — denominator for key compliance rate.
users_with_keys = keys_compliant_count + keys_noncompliant_count

print(f"\nAccess Key Compliance (90-day rotation):")
print(f"  Users with keys: {users_with_keys}")
print(f"  Compliant: {keys_compliant_count}")
print(f"  Non-compliant: {keys_noncompliant_count}")

# Calculate compliance rates for GRC reporting.
compliance_rate = (compliant_count / total_users * 100) if total_users > 0 else 0
key_compliance_rate = (keys_compliant_count / users_with_keys * 100) if users_with_keys > 0 else 0

# Display audit trail timestamps.
print(f"\nAudit started: {audit_start.isoformat()}")
print(f"Audit completed: {audit_end.isoformat()}")
print(f"Elapsed time: {elapsed:.2f} seconds")
print(f"MFA compliance rate: {compliance_rate:.1f}%")
print(f"Key compliance rate: {key_compliance_rate:.1f}%")

# Export results to CSV and JSON for compliance reporting.
timestamp_str = audit_start.isoformat().replace(':', '-').split('.')[0]

metadata = {
    'start_time': audit_start.isoformat(),
    'end_time': audit_end.isoformat(),
    'elapsed_seconds': elapsed,
    'total_users': total_users,
    'compliance_rate': f"{compliance_rate:.1f}%",
    'key_compliance_rate': f"{key_compliance_rate:.1f}%"
}

csv_file = export_to_csv(audit_results, timestamp_str)
json_file = export_to_json(audit_results, metadata, timestamp_str)

print(f"\nResults exported to:")
print(f"  - {csv_file}")
print(f"  - {json_file}")
