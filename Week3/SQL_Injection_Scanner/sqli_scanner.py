#!/usr/bin/env python3
"""
Syntecxhub Internship - Project 1
SQL Injection Scanner

IMPORTANT:
This tool is intentionally restricted to local/private test targets.
Use it only against applications you own or are explicitly authorized to test.
It does NOT extract data, bypass authentication, or modify databases.
"""

import argparse
import csv
import ipaddress
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests


SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysqli_",
    "pdoexception",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "sqlite error",
    "sqlite3.operationalerror",
    "postgresql",
    "pg_query",
    "ora-009",
    "oracle error",
    "microsoft sql server",
    "odbc sql server",
]

PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "') OR ('1'='1",
]


@dataclass
class Finding:
    url: str
    parameter: str
    payload: str
    status: int
    indicator: str
    evidence: str


class RateLimiter:
    def __init__(self, requests_per_second: float):
        self.interval = 1.0 / max(requests_per_second, 0.1)
        self.lock = threading.Lock()
        self.next_allowed = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            if now < self.next_allowed:
                time.sleep(self.next_allowed - now)
            self.next_allowed = time.monotonic() + self.interval


def is_local_or_private_target(hostname: str) -> bool:
    """Allow localhost and RFC1918/private/loopback IPs only."""
    if not hostname:
        return False

    hostname = hostname.lower().strip("[]")
    if hostname in {"localhost", "localhost.localdomain"}:
        return True

    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_loopback or ip.is_private
    except ValueError:
        pass

    # Resolve DNS names and allow them only if every resolved address is private/loopback.
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
        return bool(addresses) and all(
            ipaddress.ip_address(addr).is_loopback
            or ipaddress.ip_address(addr).is_private
            for addr in addresses
        )
    except (socket.gaierror, ValueError):
        return False


def validate_target(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be a complete http:// or https:// URL.")

    if not is_local_or_private_target(parsed.hostname):
        raise ValueError(
            "Safety check blocked this target. Use localhost or a private/local "
            "test target such as DVWA running on 127.0.0.1."
        )

    return url


def build_test_url(base_url: str, parameter: str, value: str) -> str:
    parsed = urlparse(base_url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)

    updated = []
    replaced = False
    for key, old_value in pairs:
        if key == parameter:
            updated.append((key, value))
            replaced = True
        else:
            updated.append((key, old_value))

    if not replaced:
        updated.append((parameter, value))

    new_query = urlencode(updated, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def get_error_indicator(text: str) -> Optional[str]:
    lower = text.lower()
    for pattern in SQL_ERROR_PATTERNS:
        if pattern in lower:
            return pattern
    return None


def extract_evidence(text: str, indicator: str, radius: int = 100) -> str:
    lower = text.lower()
    pos = lower.find(indicator.lower())
    if pos == -1:
        return ""
    start = max(0, pos - radius)
    end = min(len(text), pos + len(indicator) + radius)
    return " ".join(text[start:end].split())


def test_parameter(
    base_url: str,
    parameter: str,
    session: requests.Session,
    limiter: RateLimiter,
    timeout: float,
) -> List[Finding]:
    findings = []

    try:
        baseline_url = build_test_url(base_url, parameter, "syntecxhub_baseline_123")
        limiter.wait()
        baseline = session.get(baseline_url, timeout=timeout, allow_redirects=True)
        baseline_len = len(baseline.text)

        for payload in PAYLOADS:
            test_url = build_test_url(base_url, parameter, payload)
            limiter.wait()

            try:
                response = session.get(test_url, timeout=timeout, allow_redirects=True)
            except requests.RequestException as exc:
                logging.warning("Request failed for %s=%r: %s", parameter, payload, exc)
                continue

            indicator = get_error_indicator(response.text)
            if indicator:
                findings.append(
                    Finding(
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        status=response.status_code,
                        indicator=f"SQL error pattern: {indicator}",
                        evidence=extract_evidence(response.text, indicator),
                    )
                )
                continue

            # A large response-size change is only a warning signal, not proof.
            if baseline_len:
                change = abs(len(response.text) - baseline_len) / baseline_len
                if change >= 0.50:
                    findings.append(
                        Finding(
                            url=test_url,
                            parameter=parameter,
                            payload=payload,
                            status=response.status_code,
                            indicator=f"Response-size anomaly ({change:.0%} change)",
                            evidence=(
                                "Response length changed substantially compared "
                                "with the baseline; manual verification is required."
                            ),
                        )
                    )

    except requests.RequestException as exc:
        logging.warning("Could not establish baseline for %s: %s", parameter, exc)

    return findings


def save_csv(findings: List[Finding], path: str):
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(
            ["url", "parameter", "payload", "status", "indicator", "evidence"]
        )
        for item in findings:
            writer.writerow(
                [
                    item.url,
                    item.parameter,
                    item.payload,
                    item.status,
                    item.indicator,
                    item.evidence,
                ]
            )


def main():
    parser = argparse.ArgumentParser(
        description="Local/private SQL injection indicator scanner for authorized testing."
    )
    parser.add_argument(
        "url",
        help="Local/private test URL, e.g. http://127.0.0.1/vulnerabilities/sqli/?id=1",
    )
    parser.add_argument(
        "--params",
        nargs="+",
        help="Query-string parameters to test. If omitted, parameters from the URL are used.",
    )
    parser.add_argument("--threads", type=int, default=3, help="Worker threads (default: 3)")
    parser.add_argument(
        "--rate",
        type=float,
        default=2.0,
        help="Maximum requests per second across workers (default: 2)",
    )
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    parser.add_argument("--output", default="results.csv", help="CSV output file")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for local HTTPS test setups.",
    )
    args = parser.parse_args()

    if args.threads < 1 or args.threads > 10:
        parser.error("--threads must be between 1 and 10")

    try:
        target = validate_target(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    parsed = urlparse(target)
    url_params = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    parameters = args.params or list(dict.fromkeys(url_params))

    if not parameters:
        parser.error(
            "No query parameters found. Add one to the URL or use --params PARAM."
        )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

    session = requests.Session()
    session.headers.update({"User-Agent": "Syntecxhub-Local-SQLi-Scanner/1.0"})
    session.verify = not args.insecure

    limiter = RateLimiter(args.rate)
    findings: List[Finding] = []

    print("\nSyntecxhub SQL Injection Scanner")
    print("Authorized local/private testing only.")
    print(f"Target: {target}")
    print(f"Parameters: {', '.join(parameters)}")
    print(f"Threads: {args.threads} | Rate limit: {args.rate} req/s\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                test_parameter, target, param, session, limiter, args.timeout
            ): param
            for param in parameters
        }

        for future in as_completed(futures):
            param = futures[future]
            try:
                result = future.result()
                findings.extend(result)
                logging.info("Finished parameter '%s' — %d indicator(s)", param, len(result))
            except Exception as exc:
                logging.exception("Unexpected error while testing '%s': %s", param, exc)

    save_csv(findings, args.output)

    print("\nScan complete.")
    print(f"Indicators found: {len(findings)}")
    print(f"Results saved to: {args.output}")
    print("Remember: an indicator is not proof of SQL injection; manually verify findings.")


if __name__ == "__main__":
    main()
