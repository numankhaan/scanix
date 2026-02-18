# Copyright (c) 2026 Nouman Ali Khan

import argparse
from .core import utils


def run_cli():
    parser = argparse.ArgumentParser(prog="scanix", description="Scanix - Multi-purpose Port Scanner")
    parser.add_argument("--version", action="store_true", help="Show version")

    sub = parser.add_subparsers(dest="command")

    scan_cmd = sub.add_parser("scan", help="Run TCP connect scan (and optional banner grabbing)")
    scan_cmd.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    scan_cmd.add_argument("-p", "--ports", required=True, help="Port range (e.g., 1-1000)")
    scan_cmd.add_argument("--banner", action="store_true", help="Attempt banner grabbing")
    scan_cmd.add_argument("--udp", action="store_true", help="Run UDP probe on ports as well")
    scan_cmd.add_argument("--syn", action="store_true", help="Run SYN scan using raw packets (requires root and scapy)")
    scan_cmd.add_argument("--out", choices=["json", "csv", "html"], help="Save output format")
    scan_cmd.add_argument("--out-file", help="Output filename (defaults to scan_results.*)")

    # NEW: timeout tuning
    scan_cmd.add_argument("--timeout", type=float, default=1.0, help="TCP connect timeout in seconds")
    scan_cmd.add_argument("--banner-timeout", type=float, default=None, help="Banner grab timeout (defaults to --timeout)")
    scan_cmd.add_argument("--udp-timeout", type=float, default=2.0, help="UDP probe timeout in seconds")
    scan_cmd.add_argument("--syn-timeout", type=float, default=1.0, help="SYN scan timeout in seconds")

    disc_cmd = sub.add_parser("discover", help="Host discovery (ping sweep) for a network, e.g. 192.168.1.0/24")
    disc_cmd.add_argument("-n", "--network", required=True, help="Network CIDR (e.g., 192.168.1.0/24)")

    trace_cmd = sub.add_parser("traceroute", help="Run traceroute to target")
    trace_cmd.add_argument("-t", "--target", required=True, help="Target hostname or IP")

    args = parser.parse_args()

    if args.version:
        print("Scanix 2.0 (development build)")
        return

    utils.color_init()

    try:
        if args.command == "scan":
            from .core.scanner import scan_ports
            from .modules import udp_scan, syn_scan

            start_port, end_port = map(int, args.ports.split("-"))

            results = scan_ports(
                args.target,
                start_port,
                end_port,
                banner=args.banner,
                timeout=args.timeout,
                banner_timeout=args.banner_timeout,
            )

            if args.udp:
                udp_results = udp_scan.scan_udp_range(
                    args.target,
                    start_port,
                    end_port,
                    timeout=args.udp_timeout,
                )
                results.extend(udp_results)

            if args.syn:
                syn_results = syn_scan.syn_scan_range(
                    args.target,
                    start_port,
                    end_port,
                    timeout=args.syn_timeout,
                )
                results.extend(syn_results)

            if args.out:
                filename = args.out_file or f"scan_results.{args.out}"
                if args.out == "json":
                    from .output.save_json import save_json
                    save_json(results, filename)
                elif args.out == "csv":
                    from .output.save_csv import save_csv
                    save_csv(results, filename)
                elif args.out == "html":
                    from .output.save_html import save_html
                    save_html(results, filename)

        elif args.command == "discover":
            from .modules.discovery import ping_sweep

            alive = ping_sweep(args.network)
            print("\nAlive hosts:")
            for h in alive:
                print(" -", h)

        elif args.command == "traceroute":
            from .modules.traceroute import traceroute

            hops = traceroute(args.target)
            print("\nTraceroute result:")
            for i, hop in enumerate(hops, start=1):
                print(f"{i}\t{hop}")

        else:
            parser.print_help()

    except KeyboardInterrupt:
        from .core.utils import safe_print

        safe_print("\nInterrupted by user. Exiting cleanly.", warn=True)
