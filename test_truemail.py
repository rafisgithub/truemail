"""
Verify every address in extracted_emails-02.txt against the self-hosted
Truemail server defined in docker-compose.yml.

Truemail's HTTP API takes one address per GET request and returns a single
boolean, so this script adds the two things a lead-list pass actually needs:

  1. CONCURRENCY ACROSS REPLICAS. There is no batch endpoint (GET /?email=),
     so 497 addresses means 497 requests -- and each container runs thin in
     single-process mode, handling them SERIALLY. Measured here, 12 concurrent
     requests against one container each returned in ~11.0s (they queued)
     while total wall time barely moved versus a single worker. Client threads
     alone therefore buy almost nothing; they just convert per-request time
     into queue wait, which is what makes a short timeout fire on requests the
     server has not reached yet.

     Real concurrency comes from running more containers. This script
     auto-detects the healthy replicas of the chosen layer and spreads
     requests across them round-robin, so --workers matches actual capacity.
     Measured on 30 cold addresses at 10 workers: 1 replica 48.3s,
     4 replicas 20.2s. To scale up, set MX_REPLICAS in .env and re-run
     docker compose up -d.

  2. A CATCH-ALL PROBE. This is the important one. Truemail reports no
     catch-all signal at all -- there is no is_catch_all in its response, only
     success true/false. Verified against this setup:

         definitely-not-a-real-user-xyz123@monster.com  ->  success: true

     monster.com accepts every recipient, so "success" there means nothing.
     Before validating, this script sends one deliberately nonexistent local
     part per unique domain. If that passes, the domain is catch-all and every
     "success" verdict on it is downgraded to "catch_all_unreliable" rather
     than being reported as valid.

WHICH LAYER: the validation layer is server-side configuration -- the API
accepts only ?email=, so it cannot be chosen per request. docker-compose.yml
therefore runs two servers, and --layer picks which one to talk to:

    --layer mx    (:9292)  DNS/MX only. No SMTP session, so no outbound port 25
                           and no dependence on this host's IP reputation.
                           Cheap pre-filter to drop dead domains. A catch-all
                           probe is meaningless here (any local part passes),
                           so it is skipped automatically.

    --layer smtp  (:9293)  Full pipeline including the RCPT TO probe. Needs
                           outbound port 25 and a PTR record for this host
                           resolving to VERIFIER_DOMAIN. Truemail has no proxy
                           support (truemail-rb/truemail#238, frozen), so this
                           probe always leaves from this machine's own IP.

Usage:
    python3 test_truemail.py                          # mx pre-filter, all 497
    python3 test_truemail.py --limit 10               # smoke test first
    python3 test_truemail.py --layer smtp             # full SMTP pass
    python3 test_truemail.py --layer smtp --no-catch-all-probe
"""

import argparse
import json
import os
import random
import string
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

import requests

# Base published port per layer; replica N listens on base + N - 1, matching
# the port ranges in docker-compose.yml.
LAYER_BASE_PORTS = {"mx": 9292, "smtp": 9302}
MAX_REPLICAS = 10
DEFAULT_INPUT = "extracted_emails-02.txt"
ENV_FILE = ".env"

# Retried; anything else is reported as-is.
TRANSIENT_EXCEPTIONS = (requests.ConnectionError, requests.Timeout)


def load_env(path=ENV_FILE):
    """Minimal .env reader -- avoids a python-dotenv dependency."""
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


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


def validate(session, url, token, email, timeout, max_attempts):
    """One address. Returns a result dict; never raises for network trouble."""
    started = time.monotonic()
    last_error = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = session.get(
                url,
                params={"email": email},
                headers={"Authorization": token, "Accept": "application/json"},
                timeout=timeout,
            )
        except TRANSIENT_EXCEPTIONS as error:
            last_error = f"{type(error).__name__}: {error}"
            if attempt < max_attempts:
                time.sleep(random.uniform(0.2, 0.6) * attempt)
            continue
        except requests.RequestException as error:
            return {
                "email": email,
                "status": "error",
                "http_status": None,
                "error_message": f"{type(error).__name__}: {error}",
                "attempts": attempt,
                "duration_secs": round(time.monotonic() - started, 2),
            }

        # 401 and 422 are configuration faults, not per-address results.
        # Retrying them 497 times would only bury the real problem.
        if response.status_code in (401, 422):
            detail = response.text.strip()[:200]
            sys.exit(
                f"\nServer returned {response.status_code} for {email}: {detail}\n"
                "401 means ACCESS_TOKENS in .env does not match the running "
                "container (restart it after editing .env).\n"
                "422 means the email parameter was rejected."
            )

        if response.status_code >= 500 and attempt < max_attempts:
            last_error = f"HTTP {response.status_code}"
            time.sleep(random.uniform(0.2, 0.6) * attempt)
            continue

        try:
            payload = response.json()
        except ValueError:
            return {
                "email": email,
                "status": "error",
                "http_status": response.status_code,
                "error_message": f"non-JSON response: {response.text.strip()[:200]}",
                "attempts": attempt,
                "duration_secs": round(time.monotonic() - started, 2),
            }

        return {
            "email": email,
            "status": "success",
            "http_status": response.status_code,
            "validation_type": payload.get("validation_type"),
            "success": payload.get("success"),
            "errors": payload.get("errors"),
            "smtp_debug": payload.get("smtp_debug"),
            "attempts": attempt,
            "duration_secs": round(time.monotonic() - started, 2),
        }

    return {
        "email": email,
        "status": "transient_exhausted",
        "http_status": None,
        "error_message": last_error,
        "attempts": max_attempts,
        "duration_secs": round(time.monotonic() - started, 2),
    }


def discover_servers(session, layer, replicas, timeout=3.0):
    """
    Probe base_port .. base_port+MAX_REPLICAS-1 for replicas answering
    /healthcheck. Compose assigns one published port per replica from the range
    declared in docker-compose.yml, so a contiguous scan finds them all.
    """
    base = LAYER_BASE_PORTS[layer]
    limit = replicas or MAX_REPLICAS
    found = []
    for offset in range(limit):
        url = f"http://localhost:{base + offset}"
        try:
            if session.get(f"{url}/healthcheck", timeout=timeout).status_code == 200:
                found.append(url)
            elif replicas:
                sys.exit(f"{url} did not answer /healthcheck but --replicas "
                         f"{replicas} was requested.")
        except requests.RequestException:
            if replicas:
                sys.exit(
                    f"{url} is not reachable but --replicas {replicas} was "
                    f"requested.\nStart more servers with: "
                    f"{layer.upper()}_REPLICAS={replicas} docker compose up -d"
                )
            break  # ports are assigned contiguously; first gap ends the scan
    return found


def domain_of(email):
    return email.rpartition("@")[2].lower()


def probe_catch_all(session, servers, token, domains, timeout, max_attempts, workers):
    """
    One nonexistent-local-part request per domain. A domain that accepts it
    accepts anything, which makes every success verdict on that domain
    unreliable rather than valid.
    """
    def probe(indexed):
        index, domain = indexed
        nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        result = validate(
            session, servers[index % len(servers)], token,
            f"truemail-probe-{nonce}@{domain}", timeout, max_attempts,
        )
        return domain, result

    catch_all = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for domain, result in pool.map(probe, enumerate(domains)):
            # Only a clean 200 tells us anything. Network trouble leaves the
            # catch-all question genuinely unanswered, so record None.
            catch_all[domain] = (
                bool(result.get("success")) if result.get("status") == "success" else None
            )
    return catch_all


def classify(result, catch_all_domain):
    if result.get("status") != "success":
        return "error"
    if not result.get("success"):
        return "invalid"
    if catch_all_domain is True:
        return "catch_all_unreliable"
    return "valid"


def preflight(session, servers, token, expected_layer):
    """
    Check every replica: reachable, token accepted, and configured for the
    layer we think we are querying. A mixed set (say, an mx port and an smtp
    port) would silently produce two kinds of verdict in one result file.
    """
    headers = {"Authorization": token, "Accept": "application/json"}
    layers = {}

    for url in servers:
        try:
            health = session.get(f"{url}/healthcheck", timeout=10)
        except requests.RequestException as error:
            sys.exit(
                f"Cannot reach Truemail at {url}: {error}\n"
                "Start it with:  docker compose up -d"
            )
        if health.status_code != 200:
            sys.exit(f"{url}/healthcheck returned HTTP {health.status_code}")

        version = session.get(f"{url}/version", headers=headers, timeout=10)
        if version.status_code == 401:
            sys.exit(
                f"{url} rejected the access token.\n"
                "ACCESS_TOKENS in .env must match the running containers; "
                "re-run 'docker compose up -d' after editing .env."
            )

        # canary@example.com has no MX record, so this never opens an SMTP
        # session -- but validation_type still reports the configured layer.
        canary = session.get(
            url, params={"email": "canary@example.com"}, headers=headers, timeout=15
        )
        layers[url] = canary.json().get("validation_type") if canary.ok else None

    info = session.get(f"{servers[0]}/version", headers=headers, timeout=10).json()
    print(
        f"Truemail server {info.get('version', '?')} (core {info.get('core', '?')}), "
        f"{len(servers)} replica(s): {', '.join(u.rsplit(':', 1)[-1] for u in servers)}"
    )

    distinct = {layer for layer in layers.values() if layer}
    if len(distinct) > 1:
        detail = ", ".join(f"{u}={layer}" for u, layer in layers.items())
        sys.exit(
            f"Replicas disagree on validation layer ({detail}).\n"
            "Point --url at one layer's ports only."
        )

    actual = distinct.pop() if distinct else None
    if actual and actual != expected_layer:
        print(
            f"WARNING: --layer {expected_layer} was requested but these servers "
            f"run DEFAULT_VALIDATION_TYPE={actual}.\n"
            f"         Results will be {actual} verdicts. Check "
            f"docker-compose.yml and the ports in --url.",
            file=sys.stderr,
        )
    return actual or expected_layer


def summarize(results, catch_all, layer, elapsed, probed):
    verdicts = Counter(r["verdict"] for r in results)
    total = len(results)

    print(f"\n{'=' * 62}")
    print(f"  Truemail {layer} pass -- {total} addresses in {elapsed:.1f}s")
    print(f"{'=' * 62}")

    for verdict in ("valid", "catch_all_unreliable", "invalid", "error"):
        count = verdicts.get(verdict, 0)
        if count:
            print(f"  {verdict:<22} {count:>5}  ({count / total:.1%})")

    errors = Counter()
    for r in results:
        if r["verdict"] == "invalid" and isinstance(r.get("errors"), dict):
            for layer_name, message in r["errors"].items():
                errors[f"{layer_name}: {message}"] += 1
    if errors:
        print("\n  Failure reasons:")
        for reason, count in errors.most_common(10):
            print(f"    {count:>5}  {reason}")

    failures = Counter(
        r["status"] for r in results if r["status"] != "success"
    )
    if failures:
        print("\n  Non-result statuses (not verdicts):")
        for status, count in failures.most_common():
            print(f"    {count:>5}  {status}")

    if probed:
        confirmed = sum(1 for v in catch_all.values() if v is True)
        unknown = sum(1 for v in catch_all.values() if v is None)
        print(f"\n  Domains probed for catch-all: {len(catch_all)}")
        print(f"    catch-all:      {confirmed}")
        print(f"    not catch-all:  {len(catch_all) - confirmed - unknown}")
        if unknown:
            print(f"    undetermined:   {unknown}  (probe hit network trouble)")
        if confirmed:
            affected = defaultdict(int)
            for r in results:
                if r["verdict"] == "catch_all_unreliable":
                    affected[domain_of(r["email"])] += 1
            print("\n  Top catch-all domains by affected addresses:")
            for domain, count in sorted(
                affected.items(), key=lambda kv: -kv[1]
            )[:10]:
                print(f"    {count:>5}  {domain}")
            print(
                f"\n  NOTE: {verdicts.get('catch_all_unreliable', 0)} addresses "
                "passed SMTP validation on a domain that accepts every\n"
                "        recipient. Truemail reports these as success; they are "
                "not evidence the mailbox exists."
            )
    elif layer == "mx":
        print(
            "\n  Catch-all probe skipped: meaningless on the MX layer, where "
            "every local part\n  on a live domain passes. Use --layer smtp for "
            "mailbox-level verdicts."
        )

    slowest = sorted(results, key=lambda r: r.get("duration_secs") or 0, reverse=True)[:3]
    if slowest:
        print("\n  Slowest lookups:")
        for r in slowest:
            print(f"    {r['duration_secs']:>6.2f}s  {r['email']}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Verify a list of emails against the self-hosted Truemail server.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", default=DEFAULT_INPUT, help="one email per line")
    parser.add_argument("--output", help="JSON results file (default: results_truemail_<layer>.json)")
    parser.add_argument("--layer", choices=sorted(LAYER_BASE_PORTS), default="mx",
                        help="which server to query")
    parser.add_argument("--url",
                        help="comma-separated server URLs, overriding auto-detection")
    parser.add_argument("--replicas", type=int,
                        help=f"require exactly N replicas of the layer "
                             f"(max {MAX_REPLICAS}); default is to auto-detect "
                             f"however many are running")
    parser.add_argument("--token", help="access token (default: ACCESS_TOKENS from .env)")
    parser.add_argument("--limit", type=int, help="only the first N addresses")
    parser.add_argument("--workers", type=int, default=4,
                        help="concurrent requests; the server is serial, so "
                             "raising this mostly lengthens the queue")
    parser.add_argument("--timeout", type=float, default=90.0,
                        help="per-request timeout (s); must absorb queue wait, "
                             "not just lookup time")
    parser.add_argument("--max-attempts", type=int, default=3,
                        help="attempts per address on transient network errors")
    parser.add_argument("--catch-all-probe", dest="catch_all_probe",
                        action=argparse.BooleanOptionalAction, default=None,
                        help="probe each domain with a nonexistent local part "
                             "(default: on for --layer smtp, off for mx)")
    args = parser.parse_args()

    env = load_env()
    token = args.token or env.get("ACCESS_TOKENS", "").split(",")[0].strip()
    if not token:
        sys.exit(
            "No access token. Set ACCESS_TOKENS in .env (see .env.example) "
            "or pass --token."
        )

    output = args.output or f"results_truemail_{args.layer}.json"

    emails = load_emails(args.input, args.limit)
    if not emails:
        sys.exit(f"No usable addresses in {args.input}.")

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=args.workers, pool_maxsize=args.workers
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if args.url:
        servers = [u.strip().rstrip("/") for u in args.url.split(",") if u.strip()]
    else:
        servers = discover_servers(session, args.layer, args.replicas)
    if not servers:
        base = LAYER_BASE_PORTS[args.layer]
        sys.exit(
            f"No Truemail server answering on port {base}.\n"
            f"Start one with:  docker compose up -d"
        )

    layer = preflight(session, servers, token, args.layer)

    probe_enabled = (
        args.catch_all_probe if args.catch_all_probe is not None else layer == "smtp"
    )
    if probe_enabled and layer == "mx":
        print(
            "WARNING: a catch-all probe on the MX layer tells you nothing -- "
            "every local part\n         on a live domain passes. Probing anyway "
            "because it was requested.",
            file=sys.stderr,
        )

    verifier = env.get("VERIFIER_EMAIL", "")
    if layer == "smtp" and (not verifier or verifier.endswith("@example.com")):
        print(
            f"WARNING: VERIFIER_EMAIL is {verifier or 'unset'!r}, a placeholder. "
            "The SMTP layer sends it\n         as MAIL FROM; receiving servers "
            "will distrust the probe. Set a real\n         address on a "
            "PTR-backed domain in .env before trusting these results.",
            file=sys.stderr,
        )

    domains = sorted({domain_of(e) for e in emails})
    print(f"{len(emails)} addresses across {len(domains)} domains, "
          f"{args.workers} workers, layer={layer}")
    if args.workers > len(servers):
        print(
            f"NOTE: {args.workers} workers against {len(servers)} replica(s). "
            f"Each replica is serial, so\n"
            f"      only ~{len(servers)} request(s) are really in flight; the "
            f"rest queue. Raise {layer.upper()}_REPLICAS\n"
            f"      in .env (max {MAX_REPLICAS}) and re-run "
            f"'docker compose up -d' to match capacity to workers."
        )

    started = time.monotonic()

    catch_all = {}
    if probe_enabled:
        print(f"Probing {len(domains)} domains for catch-all behaviour...")
        catch_all = probe_catch_all(
            session, servers, token, domains,
            args.timeout, args.max_attempts, args.workers,
        )

    print(f"Validating {len(emails)} addresses...")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(
            pool.map(
                lambda indexed: validate(
                    session, servers[indexed[0] % len(servers)], token,
                    indexed[1], args.timeout, args.max_attempts,
                ),
                enumerate(emails),
            )
        )

    for result in results:
        domain = domain_of(result["email"])
        result["domain"] = domain
        result["catch_all_domain"] = catch_all.get(domain)
        result["verdict"] = classify(result, result["catch_all_domain"])

    elapsed = time.monotonic() - started

    with open(output, "w", encoding="utf-8") as f:
        json.dump(
            {
                "meta": {
                    "layer": layer,
                    "servers": servers,
                    "input": args.input,
                    "verifier_email": verifier or None,
                    "catch_all_probe": probe_enabled,
                    "addresses": len(results),
                    "domains": len(domains),
                    "elapsed_secs": round(elapsed, 1),
                    "finished_at": time.strftime("%Y-%m-%d %H:%M:%S %z"),
                },
                "catch_all_domains": catch_all,
                "results": results,
            },
            f,
            indent=2,
        )

    summarize(results, catch_all, layer, elapsed, probe_enabled)
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
