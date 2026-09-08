"""
Verify every address in extracted_emails.txt against a self-hosted Reacher
instance WITHOUT any proxy -- SMTP connections leave from this machine's own IP.

This is the baseline to compare test_reacher_socks5.py against. Two caveats:

  1. It must point at a Reacher container that has NO RCH__PROXY__* env vars
     set, otherwise every verification is silently proxied and the comparison
     is meaningless. The `reacher_direct` service in docker-compose.yml
     (port 8081) is that container. This script warns if the server reports a
     proxy anyway.

  2. Most ISPs and cloud providers block outbound port 25, which is what
     Reacher needs for SMTP verification. If this run returns mostly
     is_reachable="unknown" with can_connect_smtp=false, that block is the
     reason -- and it is exactly the problem the proxy exists to solve.

Usage:
    python3 test_reacher_direct.py                 # all 484 emails
    python3 test_reacher_direct.py --limit 10      # smoke test first
"""

import argparse
import json
import os
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import requests

DEFAULT_URL = "http://localhost:8081/v1/check_email"
DEFAULT_INPUT = "extracted_emails-02.txt"
DEFAULT_OUTPUT = "results_direct.json"

# Deliberately unset by default. On a direct connection the HELO hostname
# should match this machine's own reverse DNS -- reusing the proxy's domain
# (proxy4smtp.com) here would misrepresent the connecting IP and hurt results.
# Set these only if this host has a real rDNS-backed domain.
HELLO_NAME = os.environ.get("REACHER_HELLO_NAME")
FROM_EMAIL = os.environ.get("REACHER_FROM_EMAIL")


def load_emails(path, limit=None):
    if not os.path.exists(path):
        sys.exit(f"Input file {path} not found.")
    seen, emails = set(), []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            email = line.strip()
            if email and "@" in email and email not in seen:
                seen.add(email)
                emails.append(email)
    if limit:
        emails = emails[:limit]
    return emails


def find_proxy_used(debug):
    """Pull the proxy Reacher actually used out of the debug blob.

    Should always be None here. If it isn't, the container has a global proxy
    configured and this is not an unproxied baseline.
    """
    stack = [debug]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "proxy" in node:
                return node["proxy"]
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


def format_error_message(message):
    """Render smtp.error.message as one printable line.

    It is not always a string: Reacher serialises some variants as a nested
    object -- Timeout as {"secs", "nanos"}, HeadlessError as {"Cmd": "..."} --
    and slicing one of those to truncate it raises KeyError.
    """
    if message is None:
        return "(no message)"
    if isinstance(message, dict):
        if len(message) == 1:
            key, value = next(iter(message.items()))
            return f"{key}: {format_error_message(value)}"
        return ", ".join(f"{k}={v}" for k, v in message.items())
    return str(message)


def check_email(email, url, timeout, secret):
    payload = {"to_email": email}
    if HELLO_NAME:
        payload["hello_name"] = HELLO_NAME
    if FROM_EMAIL:
        payload["from_email"] = FROM_EMAIL
    headers = {"content-type": "application/json"}
    if secret:
        headers["x-reacher-secret"] = secret

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=timeout)
    except requests.exceptions.Timeout:
        return {"email": email, "status": "timeout", "error": f"no response in {timeout}s"}
    except requests.exceptions.RequestException as exc:
        return {"email": email, "status": "exception", "error": str(exc)}

    if response.status_code == 429:
        return {"email": email, "status": "throttled", "error": response.text[:200]}
    if response.status_code != 200:
        return {
            "email": email,
            "status": f"failed_http_{response.status_code}",
            "error": response.text[:200],
        }

    data = response.json()
    smtp = data.get("smtp") or {}
    mx = data.get("mx") or {}
    debug = data.get("debug") or {}

    # When verification fails, Reacher replaces the smtp result fields with an
    # {"error": {"type", "message"}} object. Without pulling that out, every
    # field below reads as null and the actual cause is invisible.
    smtp_error = smtp.get("error") or {}

    # secs alone truncates sub-second failures to 0, which reads like "instant
    # success" rather than "bailed immediately".
    duration = debug.get("duration") or {}
    secs = duration.get("secs") or 0
    nanos = duration.get("nanos") or 0

    return {
        "email": email,
        "status": "success",
        "is_reachable": data.get("is_reachable"),
        "error_type": smtp_error.get("type"),
        "error_message": smtp_error.get("message"),
        "is_deliverable": smtp.get("is_deliverable"),
        "is_catch_all": smtp.get("is_catch_all"),
        "is_disabled": smtp.get("is_disabled"),
        "can_connect_smtp": smtp.get("can_connect_smtp"),
        "accepts_mail": mx.get("accepts_mail"),
        "mx_records": mx.get("records"),
        "proxy_used": find_proxy_used(debug),
        "duration_secs": round(secs + nanos / 1e9, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="Reacher run WITHOUT a proxy.")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, help="only verify the first N emails")
    parser.add_argument("--concurrency", type=int, default=30)
    parser.add_argument(
        "--timeout",
        type=int,
        default=90,
        help="per-request timeout; /v1 queues behind the server throttle "
        "(default 60/min), so keep this generous",
    )
    args = parser.parse_args()

    emails = load_emails(args.input, args.limit)
    secret = os.environ.get("REACHER_SECRET")

    print("=" * 62)
    print("Reacher verification  --  NO proxy (direct from this host)")
    print("=" * 62)
    print(f"  endpoint    : {args.url}")
    print(f"  hello_name  : {HELLO_NAME or '(Reacher default)'}")
    print(f"  from_email  : {FROM_EMAIL or '(Reacher default)'}")
    print(f"  emails      : {len(emails)}")
    print(f"  concurrency : {args.concurrency}   timeout: {args.timeout}s")
    print("=" * 62)

    start = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = executor.map(
            lambda e: check_email(e, args.url, args.timeout, secret), emails
        )
        for i, result in enumerate(futures, start=1):
            results.append(result)
            if i % 25 == 0 or i == len(emails):
                elapsed = time.time() - start
                print(f"  {i}/{len(emails)} done  ({elapsed:.0f}s elapsed)")
    total = time.time() - start

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    statuses = Counter(r["status"] for r in results)
    reachable = Counter(
        r.get("is_reachable") for r in results if r["status"] == "success"
    )
    successes = [r for r in results if r["status"] == "success"]
    no_smtp = sum(1 for r in successes if r.get("can_connect_smtp") is False)
    leaked = sum(1 for r in results if r.get("proxy_used"))

    print("-" * 62)
    rate = len(emails) / total * 60 if total > 0 else 0.0
    print(f"Finished in {total:.1f}s  ({rate:.1f} emails/min)")
    print(f"Results written to {args.output}")
    print("\nRequest status:")
    for status, count in statuses.most_common():
        print(f"  {status:<22} {count}")
    print("\nis_reachable:")
    for value, count in reachable.most_common():
        print(f"  {value:<22} {count}")

    errors = Counter(r["error_type"] for r in results if r.get("error_type"))
    if errors:
        print("\nSMTP errors (these are why is_reachable is unknown):")
        for etype, count in errors.most_common():
            example = next(
                r["error_message"] for r in results if r.get("error_type") == etype
            )
            print(f"  {etype:<14} {count:>4}  e.g. {format_error_message(example)[:110]}")

    if leaked:
        print(
            f"\n  WARNING: the server reported a proxy on {leaked} verifications.\n"
            "  This container has RCH__PROXY__* set, so this is NOT an unproxied\n"
            "  baseline. Point --url at the reacher_direct service (port 8081)."
        )
    if successes and no_smtp == len(successes):
        print(
            "\n  NOTE: can_connect_smtp was false for every email. Outbound port 25\n"
            "  is almost certainly blocked on this host -- see the Debugging Reacher\n"
            "  page for how to confirm. Compare with test_reacher_socks5.py."
        )
    if statuses.get("throttled"):
        print(
            "\n  NOTE: got HTTP 429. Raise RCH__THROTTLE__MAX_REQUESTS_PER_MINUTE "
            "or lower --concurrency."
        )


if __name__ == "__main__":
    main()
