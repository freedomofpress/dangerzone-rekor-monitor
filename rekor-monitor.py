#!/usr/bin/env python3
"""Detect and report uses of the Dangerzone container signing key in Rekor."""

import argparse
import base64
import datetime
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import urllib.request

REKOR_URL = "https://rekor.sigstore.dev"
SEARCH_URL = "https://search.sigstore.dev/?logIndex={log_index}"
PUBKEY_URL = (
    "https://raw.githubusercontent.com/freedomofpress/dangerzone-image"
    "/main/freedomofpress-dangerzone.pub"
)
GHCR_SIGNER_REPO = "https://github.com/freedomofpress/ghcr-signer"
PUBKEY_PATH = pathlib.Path(__file__).parent / "freedomofpress-dangerzone.pub"
STATE_PATH = pathlib.Path(__file__).parent / "rekor-seen.txt"
RETRIEVE_BATCH_SIZE = 10


def fetch(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"content-type": "application/json"} if payload is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def check_pubkey(pubkey):
    remote = fetch(PUBKEY_URL)
    if remote.strip() != pubkey.strip():
        sys.exit(f"{PUBKEY_PATH} does not match {PUBKEY_URL}")


def search_entries(pubkey):
    """Return the UUIDs of entries signed with this key."""
    content = base64.b64encode(pubkey).decode()
    payload = {"publicKey": {"format": "x509", "content": content}}
    return set(json.loads(fetch(f"{REKOR_URL}/api/v1/index/retrieve", payload)))


def parse_entry(uuid, entry):
    body = json.loads(base64.b64decode(entry["body"]))
    spec = body.get("spec", {})
    if body["kind"] == "hashedrekord":
        digest = spec["data"]["hash"]["value"]
    elif body["kind"] == "dsse":
        digest = spec.get("payloadHash", {}).get("value", "?")
    else:
        digest = "?"
    return {
        "uuid": uuid,
        "log_index": entry["logIndex"],
        "integrated_time": datetime.datetime.fromtimestamp(
            entry["integratedTime"], tz=datetime.UTC
        ),
        "kind": body["kind"],
        "digest": digest,
    }


def fetch_entries(uuids):
    """Fetch log entries for these UUIDs."""
    uuids = sorted(uuids)
    entries = []
    for i in range(0, len(uuids), RETRIEVE_BATCH_SIZE):
        resp = json.loads(
            fetch(
                f"{REKOR_URL}/api/v1/log/entries/retrieve",
                {"entryUUIDs": uuids[i : i + RETRIEVE_BATCH_SIZE]},
            )
        )
        entries += [parse_entry(u, e) for item in resp for u, e in item.items()]
    return entries


def ghcr_index():
    """Map Rekor logIndex to (date, image_ref) by reading ghcr-signer manifests."""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", GHCR_SIGNER_REPO, tmp],
            check=True,
        )
        index = {}
        for mf in (pathlib.Path(tmp) / "SIGNATURES").glob("*/*/MANIFEST"):
            manifest = json.loads(mf.read_text())
            image = (mf.parent / "IMAGE").read_text().strip()
            for layer in manifest["layers"]:
                bundle = layer.get("annotations", {}).get("dev.sigstore.cosign/bundle")
                if not bundle:
                    continue
                log_index = json.loads(bundle)["Payload"]["logIndex"]
                index[log_index] = (mf.parent.parent.name, image)
        return index


def format_entry(entry, ghcr):
    match = ghcr.get(entry["log_index"])
    suffix = f"  → {match[1]} ({match[0]})" if match else "  → !! Unknown Signer !!"
    return (
        f"{entry['integrated_time']:%Y-%m-%d %H:%M:%S UTC}"
        f"  logIndex={entry['log_index']}"
        f"  {entry['kind']}"
        f"  sha256:{entry['digest']}"
        f"  {SEARCH_URL.format(log_index=entry['log_index'])}"
        f"{suffix}"
    )


def slack_message(entries, ghcr):
    lines = "\n".join(format_entry(e, ghcr) for e in entries)
    unmatched = sum(1 for e in entries if e["log_index"] not in ghcr)
    warning = (
        f" *{unmatched} not found in the ghcr-signer repo. Treat as suspicious.*"
        if unmatched
        else ""
    )
    return (
        f":key: {len(entries)} new Rekor entries signed with the Dangerzone key!\n"
        f"{warning}"
        f"Please mark this message as checked once"
        f" reviewed.\n```{lines}```"
    )


def write_state(uuids):
    STATE_PATH.write_text("\n".join(sorted(uuids)) + "\n")


def main():
    parser = argparse.ArgumentParser("dangerzone-rekor-monitor")
    parser.add_argument(
        "--slack",
        action="store_true",
        help="Report entries to the Slack webhook in $SLACK_WEBHOOK_URL",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the Slack message to stdout instead of posting it",
    )
    args = parser.parse_args()

    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if args.slack and not args.dry_run and not webhook_url:
        parser.error("Please set the SLACK_WEBHOOK_URL environment variable")

    pubkey = PUBKEY_PATH.read_bytes()
    check_pubkey(pubkey)
    current = search_entries(pubkey)
    print(f"Found {len(current)} Rekor entries for the Dangerzone key")

    if not STATE_PATH.exists():
        write_state(current)
        print(f"Initialized {STATE_PATH.name} — no notification sent")
        return 0

    new = current - set(STATE_PATH.read_text().split())
    if not new:
        write_state(current)
        print("No new entries since last run")
        return 0

    entries = fetch_entries(new)
    ghcr = ghcr_index()
    print(f"{len(entries)} new entries:")
    for entry in entries:
        print(format_entry(entry, ghcr))

    if args.slack:
        text = slack_message(entries, ghcr)
        if args.dry_run:
            print("--- Slack message ---")
            print(text)
        else:
            fetch(webhook_url, {"text": text})
            print("Notified Slack")
    write_state(current)
    return 1


if __name__ == "__main__":
    sys.exit(main())
