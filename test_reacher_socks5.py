"""
Verify every address in extracted_emails.txt against a self-hosted Reacher
instance, routing all SMTP conversations THROUGH the SOCKS5 proxy.

The proxy is passed per-request in the `proxy` field of the /v1/check_email
body, so this script does not depend on RCH__PROXY__* being set on the
container. All configuration comes from .env (MAIL_FLEET_*), which is
gitignored -- nothing here is hardcoded.

WHY RETRIES: the proxied path fails transiently. Observed against this setup,
the same address returned smtp.error.type="Socks5" ("failed to lookup address
information") on one attempt and is_reachable="safe" on the next three. The
proxy host is a round-robin pool of 15+ A/AAAA records, so an occasional cold
resolve inside the container is normal. A single-attempt run records that blip
as a permanent is_reachable="unknown", which is indistinguishable from a real
inconclusive verdict. Transient failures are therefore retried, the attempt
count is reported per address, and addresses that never resolved cleanly are
reported as "transient_exhausted" -- never mixed in with genuine "unknown".

NOTE ON THE BASELINE: do not treat test_reacher_direct.py as ground truth.
Outbound port 25 is open from this host, but Microsoft-hosted domains degrade
this IP: the same address that reads "safe" through the proxy has come back
"invalid" (a confident false negative), then IOError, then Timeout, direct.

Usage:
    python3 test_reacher_socks5.py                  # every address in the input
    python3 test_reacher_socks5.py --limit 10       # smoke test first
    python3 test_reacher_socks5.py --max-attempts 5 # stubborn transient errors
"""

import argparse
import json
import os
import random
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import requests

DEFAULT_URL = "http://localhost:8080/v1/check_email"
DEFAULT_INPUT = "extracted_emails-02.txt"
DEFAULT_OUTPUT = "results_socks5.json"

# Fallbacks used only when the corresponding .env key is absent.
FALLBACK_CONCURRENCY = 30
FALLBACK_MAX_ATTEMPTS = 3

# smtp.error.type values that mean "the network hiccuped", not "this mailbox is
# bad". Confirmed against this deployment: Socks5 is a proxy-side DNS/connect
# failure, IOError and Timeout are the mail server dropping or stalling us.
# Anything outside this set is treated as a real verdict and is NOT retried.
TRANSIENT_SMTP_ERRORS = {
    "Socks5",
    "IOError",
    "Timeout",
    "Connection",
    "ConnectionError",
    "Network",
    "TlsError",
}

# Reacher's own throttle (429) and any 5xx are worth another attempt; other 4xx
# mean the request itself is wrong, so retrying just wastes the throttle budget.
RETRYABLE_HTTP = {429, 500, 502, 503, 504}


def load_env(path=".env"):
    """Minimal .env reader so we don't need python-dotenv."""
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def build_settings(env_path=".env"):
    """Resolve every knob from .env, with the real environment taking priority.

    Previously HELO/FROM/concurrency were literals in this file while .env
    carried MAIL_FLEET_HELO_DOMAIN, MAIL_FLEET_FROM_EMAIL and
    MAIL_FLEET_GLOBAL_CONCURRENT_LIMIT -- editing .env changed nothing. They
    are read here so .env is the single source of truth.
    """
    env = {**load_env(env_path), **os.environ}

    host = env.get("MAIL_FLEET_PROXY_HOST")
    port = env.get("MAIL_FLEET_PROXY_PORT")
    if not host or not port:
        sys.exit(
            "MAIL_FLEET_PROXY_HOST / MAIL_FLEET_PROXY_PORT not found in .env.\n"
            "This script is the proxied run -- use test_reacher_direct.py for "
            "the unproxied baseline."
        )

    try:
        proxy = {"host": host, "port": int(port)}
    except ValueError:
        sys.exit(f"MAIL_FLEET_PROXY_PORT must be a number, got {port!r}.")

    username = env.get("MAIL_FLEET_PROXY_USERNAME")
    password = env.get("MAIL_FLEET_PROXY_PASSWORD")
    if username:
        proxy["username"] = username
    if password:
        proxy["password"] = password

    concurrency = env.get("MAIL_FLEET_GLOBAL_CONCURRENT_LIMIT")
    try:
        concurrency = int(concurrency) if concurrency else FALLBACK_CONCURRENCY
    except ValueError:
        concurrency = FALLBACK_CONCURRENCY

    return {
        "proxy": proxy,
        # This Reacher version ignores hello_name/from_email in the request body
        # and uses RCH__HELLO_NAME / RCH__FROM_EMAIL from docker-compose.yml.
        # They are still sent for forward compatibility; the run summary prints
        # what the server actually used so a mismatch is visible.
        "hello_name": env.get("MAIL_FLEET_HELO_DOMAIN"),
        "from_email": env.get("MAIL_FLEET_FROM_EMAIL"),
        "concurrency": max(1, concurrency),
        "secret": env.get("REACHER_SECRET"),
    }


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
    if not emails:
        sys.exit(f"No addresses found in {path}.")
    if limit:
        emails = emails[:limit]
    return emails


def verif_method(debug):
    """The inner verif_method block, confirmed against a live response.

    Path is debug.smtp.verif_method.verif_method -- the nesting really does
    repeat the key. It carries proxy, hello_name and from_email as the server
    applied them, which is the only way to tell whether our proxy and
    RCH__HELLO_NAME took effect or Reacher quietly fell back to localhost.
    """
    return (
        ((debug.get("smtp") or {}).get("verif_method") or {}).get("verif_method")
        or {}
    )


def classify(response_json):
    """Split a 200 response into (is_transient, error_type, error_message).

    On failure Reacher replaces the smtp result fields with an
    {"error": {"type", "message"}} object, so without pulling that out every
    smtp field reads as null and the cause is invisible.
    """
    smtp = response_json.get("smtp") or {}
    error = smtp.get("error") or {}
    error_type = error.get("type")
    if not error_type:
        return False, None, None
    return error_type in TRANSIENT_SMTP_ERRORS, error_type, error.get("message")


def extract(email, response_json, attempts):
    smtp = response_json.get("smtp") or {}
    mx = response_json.get("mx") or {}
    misc = response_json.get("misc") or {}
    syntax = response_json.get("syntax") or {}
    debug = response_json.get("debug") or {}
    vm = verif_method(debug)
    _, error_type, error_message = classify(response_json)

    # secs alone truncates sub-second failures to 0, which reads like "instant
    # success" rather than "bailed immediately".
    duration = debug.get("duration") or {}
    secs = duration.get("secs") or 0
    nanos = duration.get("nanos") or 0

    return {
        "email": email,
        "status": "success",
        "attempts_used": attempts,
        "is_reachable": response_json.get("is_reachable"),
        "error_type": error_type,
        "error_message": error_message,
        "is_deliverable": smtp.get("is_deliverable"),
        "is_catch_all": smtp.get("is_catch_all"),
        "is_disabled": smtp.get("is_disabled"),
        "has_full_inbox": smtp.get("has_full_inbox"),
        "can_connect_smtp": smtp.get("can_connect_smtp"),
        "accepts_mail": mx.get("accepts_mail"),
        "mx_records": mx.get("records"),
        "is_disposable": misc.get("is_disposable"),
        "is_role_account": misc.get("is_role_account"),
        "is_valid_syntax": syntax.get("is_valid_syntax"),
        "proxy_used": vm.get("proxy"),
        "effective_helo": vm.get("hello_name"),
        "effective_from": vm.get("from_email"),
        "duration_secs": round(secs + nanos / 1e9, 2),
    }


def check_email(email, url, settings, timeout, max_attempts, base_delay):
    """Verify one address, retrying only failures that look transient."""
    payload = {"to_email": email, "proxy": settings["proxy"]}
    if settings["hello_name"]:
        payload["hello_name"] = settings["hello_name"]
    if settings["from_email"]:
        payload["from_email"] = settings["from_email"]

    headers = {"content-type": "application/json"}
    if settings["secret"]:
        headers["x-reacher-secret"] = settings["secret"]

    last_type = last_message = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        except requests.exceptions.Timeout:
            last_type, last_message = "HttpTimeout", f"no response in {timeout}s"
        except requests.exceptions.RequestException as exc:
            last_type, last_message = "HttpException", str(exc)
        else:
            if response.status_code == 200:
                body = response.json()
                transient, error_type, error_message = classify(body)
                if not transient:
                    return extract(email, body, attempt)
                last_type, last_message = error_type, error_message
            elif response.status_code in RETRYABLE_HTTP:
                last_type = f"http_{response.status_code}"
                last_message = response.text[:200]
            else:
                return {
                    "email": email,
                    "status": f"failed_http_{response.status_code}",
                    "attempts_used": attempt,
                    "error_type": f"http_{response.status_code}",
                    "error_message": response.text[:200],
                }

        if attempt < max_attempts:
            # Exponential backoff, jittered so 30 workers don't retry in lockstep
            # and re-trigger the same throttle or DNS stampede.
            time.sleep(base_delay * (2 ** (attempt - 1)) * (0.5 + random.random()))

    return {
        "email": email,
        "status": "transient_exhausted",
        "attempts_used": max_attempts,
        "error_type": last_type,
        "error_message": last_message,
    }


def print_summary(results, emails, args, settings, total):
    statuses = Counter(r["status"] for r in results)
    successes = [r for r in results if r["status"] == "success"]
    reachable = Counter(r.get("is_reachable") for r in successes)

    print("-" * 62)
    rate = len(emails) / total * 60 if total > 0 else 0.0
    print(f"Finished in {total:.1f}s  ({rate:.1f} emails/min)")
    print(f"Results written to {args.output}")

    print("\nRequest status:")
    for status, count in statuses.most_common():
        print(f"  {status:<22} {count}")

    print("\nis_reachable (conclusive runs only):")
    for value, count in reachable.most_common():
        print(f"  {str(value):<22} {count}")

    retried = [r for r in results if r.get("attempts_used", 1) > 1]
    recovered = [r for r in retried if r["status"] == "success"]
    print(f"\nRetries: {len(retried)}/{len(results)} addresses needed more than one "
          f"attempt; {len(recovered)} recovered on a later attempt.")
    if recovered:
        print("  Those would have been recorded as bogus 'unknown' verdicts "
              "without retries.")

    errors = Counter(r["error_type"] for r in results if r.get("error_type"))
    if errors:
        print("\nErrors seen (including ones a retry later recovered from):")
        for etype, count in errors.most_common():
            example = next(
                (r["error_message"] for r in results
                 if r.get("error_type") == etype and r.get("error_message")),
                "",
            )
            print(f"  {etype:<14} {count:>4}  e.g. {str(example)[:100]}")

    exhausted = statuses.get("transient_exhausted", 0)
    if exhausted:
        print(f"\n  {exhausted} address(es) never got a clean answer in "
              f"{args.max_attempts} attempts. These are NOT bad addresses -- "
              "re-run just those before judging them.")

    proxied = sum(1 for r in successes if r.get("proxy_used"))
    if successes:
        print(f"\nServer reported a proxy on {proxied}/{len(successes)} "
              "conclusive verifications.")
    if successes and not proxied:
        print("  WARNING: no proxy reported. The per-request proxy may have been "
              "ignored -- these results may be coming from this host's own IP.")

    helo = next((r["effective_helo"] for r in successes if r.get("effective_helo")), None)
    frm = next((r["effective_from"] for r in successes if r.get("effective_from")), None)
    if helo:
        print(f"Effective HELO/FROM used by the server: {helo} / {frm}")
        if settings["hello_name"] and helo != settings["hello_name"]:
            print(f"  WARNING: .env asks for {settings['hello_name']!r} but the "
                  f"server used {helo!r}. Request-body values are ignored by this "
                  "version -- fix RCH__HELLO_NAME in docker-compose.yml.")


def main():
    parser = argparse.ArgumentParser(description="Reacher run WITH SOCKS5 proxy.")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, help="only verify the first N emails")
    parser.add_argument(
        "--concurrency",
        type=int,
        help="overrides MAIL_FLEET_GLOBAL_CONCURRENT_LIMIT from .env",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=FALLBACK_MAX_ATTEMPTS,
        help="attempts per address before giving up on transient errors",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="base backoff in seconds; doubles each attempt, with jitter",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=90,
        help="per-request timeout; /v1 queues behind the server throttle "
        "(default 60/min), so keep this generous",
    )
    args = parser.parse_args()

    settings = build_settings()
    if args.concurrency:
        settings["concurrency"] = args.concurrency
    emails = load_emails(args.input, args.limit)
    proxy = settings["proxy"]

    print("=" * 62)
    print("Reacher verification  --  WITH SOCKS5 proxy")
    print("=" * 62)
    print(f"  endpoint    : {args.url}")
    print(f"  proxy       : {proxy['host']}:{proxy['port']}"
          f"{' (authenticated)' if proxy.get('username') else ''}")
    print(f"  hello_name  : {settings['hello_name'] or '(Reacher default)'}")
    print(f"  from_email  : {settings['from_email'] or '(Reacher default)'}")
    print(f"  emails      : {len(emails)}")
    print(f"  concurrency : {settings['concurrency']}   timeout: {args.timeout}s")
    print(f"  attempts    : up to {args.max_attempts} per address "
          f"(base backoff {args.retry_delay}s)")
    print("=" * 62)

    start = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=settings["concurrency"]) as executor:
        futures = executor.map(
            lambda e: check_email(
                e, args.url, settings, args.timeout, args.max_attempts, args.retry_delay
            ),
            emails,
        )
        for i, result in enumerate(futures, start=1):
            results.append(result)
            if i % 25 == 0 or i == len(emails):
                print(f"  {i}/{len(emails)} done  ({time.time() - start:.0f}s elapsed)")
    total = time.time() - start

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print_summary(results, emails, args, settings, total)


if __name__ == "__main__":
    main()
