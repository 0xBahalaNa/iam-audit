"""
iam_audit.py
Audits all IAM users in your AWS account for MFA and access key compliance.
Checks performed:
    1. Console Access - Does the user have a password to log into AWS Console?
    2. MFA Status - If they have console access, is MFA enabled?
    3. Access Key Age - Are any active access keys older than 90 days?
    4. User Activity - Has the user been inactive for 90+ days?
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
        'access_key_count', 'oldest_key_age_days', 'key_compliance_status',
        'last_activity_date', 'days_inactive', 'activity_status'
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
            'key_compliance_rate': metadata['key_compliance_rate'],
            'activity_compliance_rate': metadata['activity_compliance_rate'],
            'inactive_users': metadata['inactive_users']
        },
        'findings': audit_results
    }

    with open(filename, 'w') as jsonfile:
        json.dump(report, jsonfile, indent=4)

    return filename


def audit_user(iam, user):
    """
    Audit a single IAM user for MFA, access key, and activity compliance.

    Checks whether the user has console access, whether MFA is enabled,
    whether any active access keys exceed the 90-day rotation threshold,
    and whether the user has been inactive for 90+ days.

    Args:
        iam: boto3 IAM client
        user: User dictionary from list_users() containing UserName,
              CreateDate, and optionally PasswordLastUsed

    Returns:
        dict containing user audit results with keys: username,
        has_console_access, mfa_enabled, compliance_status,
        access_key_count, oldest_key_age_days, key_compliance_status,
        last_activity_date, days_inactive, activity_status
    """
    username = user['UserName']
    now_utc = datetime.now(timezone.utc)
    print(f"Checking: {username}")

    # Paginate list_mfa_devices() for completeness. Empty list means no MFA.
    mfa_paginator = iam.get_paginator('list_mfa_devices')
    mfa_devices = []
    for page in mfa_paginator.paginate(UserName=username):
        mfa_devices.extend(page['MFADevices'])

    # Check to see if user has console access. Throws except if no console access.
    try:
        iam.get_login_profile(UserName=username)
        has_console = True
    except iam.exceptions.NoSuchEntityException:
        has_console = False

    # Evaluate compliance based on both checks.
    if has_console and mfa_devices:
        print("    [PASS] MFA enabled for console user.")
        compliance_status = 'PASS'
    elif has_console and not mfa_devices:
        print("    [FAIL] Console access WITHOUT MFA!")
        compliance_status = 'FAIL'
    else:
        print("    [INFO] No console access (MFA not required).")
        compliance_status = 'INFO'

    # Check access key age for compliance with rotation policy.
    # IA-5(1) requires periodic authenticator rotation — 90-day threshold
    # matches CIS AWS Benchmark 1.14 and common FedRAMP/CJIS expectations.
    keys_paginator = iam.get_paginator('list_access_keys')
    access_keys = []
    for page in keys_paginator.paginate(UserName=username):
        access_keys.extend(page['AccessKeyMetadata'])

    # Track the oldest key and whether any active key exceeds 90 days.
    oldest_key_age = 0
    key_compliance = 'N/A'

    if access_keys:
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
        else:
            key_compliance = 'FAIL'
    else:
        print("    [N/A] No access keys.")

    # Determine last activity date for inactivity detection.
    # AC-2(3) requires disabling accounts inactive beyond a defined threshold.
    # Start with CreateDate as baseline (timezone-aware UTC from boto3).
    last_activity = user['CreateDate']

    # PasswordLastUsed is only present if the user has signed in via console
    # at least once. dict.get() returns None when the key is missing (PCC3e
    # Ch. 6), avoiding a KeyError for programmatic-only users.
    password_last_used = user.get('PasswordLastUsed')
    if password_last_used and password_last_used > last_activity:
        last_activity = password_last_used

    # Check each access key's last used date for programmatic activity.
    # get_access_key_last_used() is a direct call (not paginated) since
    # it returns a single result per key.
    for key in access_keys:
        key_last_used_info = iam.get_access_key_last_used(
            AccessKeyId=key['AccessKeyId']
        )
        key_last_used = key_last_used_info['AccessKeyLastUsed'].get('LastUsedDate')
        if key_last_used and key_last_used > last_activity:
            last_activity = key_last_used

    days_inactive = (now_utc - last_activity).days

    if days_inactive > 90:
        print(f"    [FAIL] Inactive for {days_inactive} days (last activity: {last_activity.strftime('%Y-%m-%d')})")
        activity_status = 'FAIL'
    else:
        print(f"    [PASS] Active within 90 days (last activity: {last_activity.strftime('%Y-%m-%d')})")
        activity_status = 'PASS'

    return {
        'username': username,
        'has_console_access': has_console,
        'mfa_enabled': bool(mfa_devices),
        'compliance_status': compliance_status,
        'access_key_count': len(access_keys),
        'oldest_key_age_days': oldest_key_age,
        'key_compliance_status': key_compliance,
        'last_activity_date': last_activity.strftime('%Y-%m-%d'),
        'days_inactive': days_inactive,
        'activity_status': activity_status
    }


def run_audit():
    """
    Run the full IAM audit across all users.

    Creates an IAM client, checks every user for MFA and access key
    compliance, prints a summary, and exports results to CSV and JSON.
    """
    # Create IAM client to interact with AWS IAM service.
    iam = boto3.client('iam')

    # Paginate list_users() to retrieve all users regardless of account size.
    # Default API response is capped at 100 users per call.
    paginator = iam.get_paginator('list_users')
    users = []
    for page in paginator.paginate():
        users.extend(page['Users'])
    total_users = len(users)

    audit_results = []
    audit_start = datetime.now()

    # Check each user for MFA, access key, and activity compliance.
    for user in users:
        result = audit_user(iam, user)
        audit_results.append(result)

    # Capture audit completion time and calculate elapsed time.
    audit_end = datetime.now()
    elapsed = (audit_end - audit_start).total_seconds()

    # Derive compliance counts from results.
    compliant_count = sum(1 for r in audit_results if r['compliance_status'] == 'PASS')
    no_console_count = sum(1 for r in audit_results if r['compliance_status'] == 'INFO')
    keys_compliant_count = sum(1 for r in audit_results if r['key_compliance_status'] == 'PASS')
    keys_noncompliant_count = sum(1 for r in audit_results if r['key_compliance_status'] == 'FAIL')
    inactive_count = sum(1 for r in audit_results if r['activity_status'] == 'FAIL')

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

    print(f"\nUser Activity (90-day inactivity threshold):")
    print(f"  Active: {total_users - inactive_count}")
    print(f"  Inactive (90+ days): {inactive_count}")

    # Calculate compliance rates for GRC reporting.
    compliance_rate = (compliant_count / total_users * 100) if total_users > 0 else 0
    key_compliance_rate = (keys_compliant_count / users_with_keys * 100) if users_with_keys > 0 else 0
    activity_compliance_rate = ((total_users - inactive_count) / total_users * 100) if total_users > 0 else 0

    # Display audit trail timestamps.
    print(f"\nAudit started: {audit_start.isoformat()}")
    print(f"Audit completed: {audit_end.isoformat()}")
    print(f"Elapsed time: {elapsed:.2f} seconds")
    print(f"MFA compliance rate: {compliance_rate:.1f}%")
    print(f"Key compliance rate: {key_compliance_rate:.1f}%")
    print(f"Activity compliance rate: {activity_compliance_rate:.1f}%")

    # Export results to CSV and JSON for compliance reporting.
    timestamp_str = audit_start.isoformat().replace(':', '-').split('.')[0]

    metadata = {
        'start_time': audit_start.isoformat(),
        'end_time': audit_end.isoformat(),
        'elapsed_seconds': elapsed,
        'total_users': total_users,
        'compliance_rate': f"{compliance_rate:.1f}%",
        'key_compliance_rate': f"{key_compliance_rate:.1f}%",
        'activity_compliance_rate': f"{activity_compliance_rate:.1f}%",
        'inactive_users': inactive_count
    }

    csv_file = export_to_csv(audit_results, timestamp_str)
    json_file = export_to_json(audit_results, metadata, timestamp_str)

    print(f"\nResults exported to:")
    print(f"  - {csv_file}")
    print(f"  - {json_file}")


if __name__ == '__main__':
    run_audit()
