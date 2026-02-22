"""
iam_audit.py
Audits all IAM users in your AWS account for MFA compliance.
Checks performed:
    1. Console Access - Does the user have a password to log into AWS Console?
    2. MFA Status - If they have console access, is MFA enabled?
Output:
    [PASS] - Console user with MFA enabled
    [FAIL] - Console user WITHOUT MFA (security risk!)
    [INFO] - No console access (programmatic only, MFA not required)
Usage:
    python iam_audit.py
Requirements:
    - boto3 installed (pip install boto3)
    - AWS credentials configured (aws configure)
"""

# Import associated AWS module for script.
import boto3
from datetime import datetime
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

    fieldnames = ['username', 'has_console_access', 'mfa_enabled', 'compliance_status']

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
            'compliance_rate': metadata['compliance_rate']
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
    except:
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

    # Store user audit data for export.
    user_record = {
        'username': username,
        'has_console_access': has_console,
        'mfa_enabled': bool(mfa_devices),
        'compliance_status': compliance_status
    }
    audit_results.append(user_record)

# Capture audit completion time and calculate elapsed time.
audit_end = datetime.now()
elapsed = (audit_end - audit_start).total_seconds()

# Compliance summary of results.
print("\n" + "=" * 40)
print(f"Total users: {total_users}")
print(f"Compliant (MFA enabled): {compliant_count}")
print(f"No console access: {no_console_count}")
print(f"Non-compliant: {total_users - compliant_count - no_console_count}")

# Calculate compliance rate for GRC reporting.
compliance_rate = (compliant_count / total_users * 100) if total_users > 0 else 0

# Display audit trail timestamps.
print(f"\nAudit started: {audit_start.isoformat()}")
print(f"Audit completed: {audit_end.isoformat()}")
print(f"Elapsed time: {elapsed:.2f} seconds")
print(f"Compliance rate: {compliance_rate:.1f}%")

# Export results to CSV and JSON for compliance reporting.
timestamp_str = audit_start.isoformat().replace(':', '-').split('.')[0]

metadata = {
    'start_time': audit_start.isoformat(),
    'end_time': audit_end.isoformat(),
    'elapsed_seconds': elapsed,
    'total_users': total_users,
    'compliance_rate': f"{compliance_rate:.1f}%"
}

csv_file = export_to_csv(audit_results, timestamp_str)
json_file = export_to_json(audit_results, metadata, timestamp_str)

print(f"\nResults exported to:")
print(f"  - {csv_file}")
print(f"  - {json_file}")
