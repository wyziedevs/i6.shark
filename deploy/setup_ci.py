#!/usr/bin/env python3
"""One-time setup so a push to main deploys i6.shark (.github/workflows/deploy.yml).

Makes an SSH key just for GitHub Actions, installs its public half on the VPS
(this one login uses the root password), checks the key can
log in, stores host, user and private key as repo secrets with the GitHub CLI,
deletes the local copy of the key, and starts a first deploy.

  I6_HOST=<server ip> I6_PASS=... python deploy/setup_ci.py

Reads I6_HOST, I6_USER (default root) and I6_PASS. Needs paramiko, ssh-keygen
and gh (logged in, with access to the repo). Safe to re-run: the key line is
only added once, and the secrets are overwritten with the new key.
"""
import os
import shutil
import subprocess
import sys
import tempfile

import paramiko

REPO = "wyziedevs/i6.shark"


def main():
    host = os.environ.get("I6_HOST")
    user = os.environ.get("I6_USER", "root")
    password = os.environ.get("I6_PASS")
    if not password:
        sys.exit("I6_PASS not set (the proxy server's root password, used this once).")
    if not host:
        sys.exit("I6_HOST not set (the proxy server's address, not the Cloudflare hostname).")
    for tool in ("ssh-keygen", "gh"):
        if not shutil.which(tool):
            sys.exit(f"{tool} not found on PATH.")

    tmp = tempfile.mkdtemp()
    key_path = os.path.join(tmp, "i6shark_ci")
    try:
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "github-actions@i6.shark", "-f", key_path],
            check=True,
        )
        pub = open(key_path + ".pub", encoding="utf-8").read().strip()

        print(f"Installing the deploy key on {user}@{host} ...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=user, password=password, timeout=30)
        cmd = (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && "
            f"(grep -qxF '{pub}' ~/.ssh/authorized_keys || echo '{pub}' >> ~/.ssh/authorized_keys) && "
            "chmod 600 ~/.ssh/authorized_keys"
        )
        _, out, err = client.exec_command(cmd, timeout=60)
        if out.channel.recv_exit_status() != 0:
            sys.exit(f"Couldn't install the key: {err.read().decode(errors='replace')}")
        client.close()

        print("Checking the key can log in ...")
        check = paramiko.SSHClient()
        check.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        check.connect(host, username=user, key_filename=key_path, look_for_keys=False, allow_agent=False, timeout=30)
        _, out, _ = check.exec_command("command -v git >/dev/null && command -v openssl >/dev/null && command -v curl >/dev/null && (command -v go || test -x /usr/local/go/bin/go) >/dev/null && systemctl list-unit-files --type=service | grep -qi shark && echo ok", timeout=60)
        if out.read().decode().strip() != "ok":
            sys.exit("Key login worked, but the server is missing git, openssl, curl, Go or the i6.shark service.")
        check.close()

        print(f"Saving repo secrets on {REPO} ...")
        secrets = {"I6_VPS_HOST": host, "I6_VPS_USER": user}
        for name, value in secrets.items():
            subprocess.run(["gh", "secret", "set", name, "-R", REPO, "--body", value], check=True)
        with open(key_path, "rb") as f:
            subprocess.run(["gh", "secret", "set", "I6_VPS_SSH_KEY", "-R", REPO], stdin=f, check=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    subprocess.run(["gh", "workflow", "run", "deploy.yml", "-R", REPO, "--ref", "main"], check=False)
    print("Done. Every push to main now deploys; the first deploy is running:")
    print(f"  gh run list -R {REPO} --workflow deploy.yml --limit 1")


if __name__ == "__main__":
    main()
