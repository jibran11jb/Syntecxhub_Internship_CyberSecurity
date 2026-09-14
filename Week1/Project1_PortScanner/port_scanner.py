import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def scan_port(host, port, timeout):
    """Check whether a TCP port is open, closed, or timed out."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((host, port))

        if result == 0:
            return port, "OPEN"

        return port, "CLOSED"

    except socket.timeout:
        return port, "TIMEOUT"

    except socket.error as error:
        return port, f"ERROR: {error}"

    finally:
        sock.close()


def scan_host(host, start_port, end_port, workers=50, timeout=0.5):

    try:
        ip_address = socket.gethostbyname(host)

    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {host}")

    results = []

    # Thread pool provides concurrency
    with ThreadPoolExecutor(max_workers=workers) as executor:

        futures = {
            executor.submit(
                scan_port,
                ip_address,
                port,
                timeout
            ): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            results.append(future.result())

    return ip_address, sorted(results)


def save_log(filename, host, ip_address, results):

    with open(filename, "w", encoding="utf-8") as file:

        file.write("TCP PORT SCANNER RESULTS\n")
        file.write("========================\n")
        file.write(f"Host: {host}\n")
        file.write(f"IP Address: {ip_address}\n")
        file.write(
            f"Scan Time: "
            f"{datetime.now().isoformat(timespec='seconds')}\n\n"
        )

        for port, status in results:
            file.write(f"Port {port}: {status}\n")


def main():

    parser = argparse.ArgumentParser(
        description="TCP Port Scanner"
    )

    parser.add_argument(
        "host",
        help="Hostname or IP address to scan"
    )

    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Starting port (default: 1)"
    )

    parser.add_argument(
        "--end",
        type=int,
        default=1024,
        help="Ending port (default: 1024)"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Number of concurrent threads"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout for each port in seconds"
    )

    parser.add_argument(
        "--log",
        default="scan_results.txt",
        help="Log file name"
    )

    args = parser.parse_args()

    # Validate port numbers
    if not (1 <= args.start <= 65535):
        parser.error("Starting port must be between 1 and 65535.")

    if not (1 <= args.end <= 65535):
        parser.error("Ending port must be between 1 and 65535.")

    if args.start > args.end:
        parser.error("Starting port cannot be greater than ending port.")

    if args.workers < 1:
        parser.error("Workers must be at least 1.")

    if args.timeout <= 0:
        parser.error("Timeout must be greater than 0.")

    try:

        ip_address, results = scan_host(
            args.host,
            args.start,
            args.end,
            args.workers,
            args.timeout
        )

    except ValueError as error:
        parser.error(str(error))

    print()
    print("====================================")
    print("       TCP PORT SCANNER")
    print("====================================")
    print(f"Host: {args.host}")
    print(f"IP:   {ip_address}")
    print(
        f"Ports: {args.start} - {args.end}"
    )
    print("====================================")
    print()

    for port, status in results:

        print(
            f"Port {port:5} -> {status}"
        )

    save_log(
        args.log,
        args.host,
        ip_address,
        results
    )

    print()
    print(f"Results saved to: {args.log}")


if __name__ == "__main__":
    main()