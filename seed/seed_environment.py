"""Builds the deliberately broken AWS environment inside LocalStack, and
registers the leaked/canary IAM key with the defender dashboard.

Run this AFTER `docker-compose up` and AFTER the defender (`python defender/main.py`)
is already running, so /register-canary succeeds immediately.
"""
import json
import os
import time
from pathlib import Path

import boto3
import requests
from botocore.exceptions import ClientError

# Automatically load .env if present
env_file = Path(__file__).resolve().parent.parent / ".env"
if env_file.exists():
    with open(env_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
DEFENDER_URL = os.environ.get("DEFENDER_URL", "http://localhost:8000")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

PUBLIC_BUCKET = "public-conf-bucket-demo"
INTERNAL_BUCKET = "internal-customer-data"
PII_TABLE = "CustomerPII"
LEAKED_USER = "leaked-service-user"

LEAKED_ACCESS_KEY = os.environ.get("LEAKED_ACCESS_KEY", "CANARY_KEY_ID_DEMO_123")
LEAKED_SECRET_KEY = os.environ.get("LEAKED_SECRET_KEY", "demoLeakedSecretKeyValueNotReal1234567890")


def client(service):
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name=REGION,
    )


def create_public_bucket(s3):
    print(f"[seed] creating public bucket: {PUBLIC_BUCKET}")
    try:
        s3.create_bucket(Bucket=PUBLIC_BUCKET)
    except ClientError as e:
        print(f"  (bucket may already exist: {e})")
    s3.put_bucket_acl(Bucket=PUBLIC_BUCKET, ACL="public-read")

    leaked_config = f"""# db_config.yaml.bak
# accidentally committed backup config -- DO NOT SHIP TO PROD
aws:
  access_key_id: {LEAKED_ACCESS_KEY}
  secret_access_key: {LEAKED_SECRET_KEY}
  region: {REGION}
database:
  host: internal-db.demo.local
  user: svc_backup
"""
    s3.put_object(Bucket=PUBLIC_BUCKET, Key="backup/db_config.yaml.bak", Body=leaked_config.encode())
    s3.put_object(
        Bucket=PUBLIC_BUCKET,
        Key="README.txt",
        Body=b"Public assets bucket. Nothing sensitive here (allegedly).",
    )
    print("  uploaded backup/db_config.yaml.bak (contains leaked credentials) + README.txt")


def create_leaked_iam_user(iam):
    print(f"[seed] creating IAM user: {LEAKED_USER}")
    try:
        iam.create_user(UserName=LEAKED_USER)
    except ClientError as e:
        print(f"  (user may already exist: {e})")

    # Create the access key with our fixed, "leaked" credential pair.
    # LocalStack allows specifying the key id via community-friendly create_access_key
    # is normally random; to guarantee a deterministic canary we instead register
    # whatever LocalStack returns AND additionally register our fixed constant as the
    # canary so detection works even though the wire is the same value.
    try:
        resp = iam.create_access_key(UserName=LEAKED_USER)
        real_key_id = resp["AccessKey"]["AccessKeyId"]
        real_secret = resp["AccessKey"]["SecretAccessKey"]
    except ClientError as e:
        print(f"  create_access_key failed: {e}")
        real_key_id, real_secret = LEAKED_ACCESS_KEY, LEAKED_SECRET_KEY

    broad_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["dynamodb:*"], "Resource": "*"},
        ],
    }
    policy_name = "OverlyBroadDemoPolicy"
    try:
        iam.put_user_policy(
            UserName=LEAKED_USER,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(broad_policy),
        )
        print(f"  attached overly broad inline policy '{policy_name}' to {LEAKED_USER}")
    except ClientError as e:
        print(f"  put_user_policy failed: {e}")

    return real_key_id, real_secret


def rewrite_leaked_config_with_real_key(s3, key_id, secret):
    """Overwrite the leaked config object with the ACTUAL usable access key/secret
    LocalStack issued, so the attacker's stage-2 script gets working credentials."""
    leaked_config = f"""# db_config.yaml.bak
# accidentally committed backup config -- DO NOT SHIP TO PROD
aws:
  access_key_id: {key_id}
  secret_access_key: {secret}
  region: {REGION}
database:
  host: internal-db.demo.local
  user: svc_backup
"""
    s3.put_object(Bucket=PUBLIC_BUCKET, Key="backup/db_config.yaml.bak", Body=leaked_config.encode())


def create_internal_resources(s3, dynamodb):
    print(f"[seed] creating internal bucket: {INTERNAL_BUCKET}")
    try:
        s3.create_bucket(Bucket=INTERNAL_BUCKET)
    except ClientError as e:
        print(f"  (bucket may already exist: {e})")
    for i in range(5):
        s3.put_object(
            Bucket=INTERNAL_BUCKET,
            Key=f"reports/confidential_report_{i}.txt",
            Body=("CONFIDENTIAL customer report #%d\n" % i).encode() * 200,
        )
    print("  uploaded 5 confidential report objects")

    print(f"[seed] creating DynamoDB table: {PII_TABLE}")
    try:
        dynamodb.create_table(
            TableName=PII_TABLE,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        waiter = dynamodb.get_waiter("table_exists")
        waiter.wait(TableName=PII_TABLE)
    except ClientError as e:
        print(f"  (table may already exist: {e})")

    for i in range(25):
        dynamodb.put_item(
            TableName=PII_TABLE,
            Item={
                "id": {"S": f"cust-{i:04d}"},
                "name": {"S": f"Fake Customer {i}"},
                "email": {"S": f"fakecustomer{i}@example.com"},
                "ssn_like": {"S": f"000-00-{1000 + i}"},
            },
        )
    print("  wrote 25 fake customer PII rows")


def register_canary_with_defender(access_key_id):
    print(f"[seed] registering canary key with defender: {access_key_id}")
    for attempt in range(5):
        try:
            r = requests.post(f"{DEFENDER_URL}/register-canary", json={"access_key_id": access_key_id}, timeout=3)
            r.raise_for_status()
            print("  registered.")
            return
        except Exception as e:
            print(f"  attempt {attempt + 1} failed ({e}); is defender/main.py running? retrying in 2s...")
            time.sleep(2)
    print("  WARNING: could not register canary with defender. Start defender/main.py first.")


def main():
    s3 = client("s3")
    iam = client("iam")
    dynamodb = client("dynamodb")

    create_public_bucket(s3)
    key_id, secret = create_leaked_iam_user(iam)
    rewrite_leaked_config_with_real_key(s3, key_id, secret)
    create_internal_resources(s3, dynamodb)
    register_canary_with_defender(key_id)

    print("\n=== Seed summary ===")
    print(f"Public bucket:   {PUBLIC_BUCKET} (public-read, contains leaked creds)")
    print(f"Leaked IAM user: {LEAKED_USER} (access_key_id={key_id})")
    print(f"Internal bucket: {INTERNAL_BUCKET}")
    print(f"PII table:       {PII_TABLE}")
    print("Environment ready. Run attacker/1_recon_bucket_enum.py to begin the demo.")


if __name__ == "__main__":
    main()
