"""Read an identified device's local router capture and emit JSON Lines on stdout."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from .observations import Coverage, Device, observations, summarize_flows


def main():
    parser = argparse.ArgumentParser(prog="python -m shared_traffic", description=__doc__)
    parser.add_argument("capture", type=Path, help="classic PCAP (Ethernet, SLL or SLL2)")
    parser.add_argument("--device", required=True, help="device identifier in the output")
    parser.add_argument("--ip", action="append", default=[], help="registered IP address (repeatable)")
    parser.add_argument("--mac", action="append", default=[], help="registered Ethernet MAC (repeatable)")
    parser.add_argument("--flows", action="store_true", help="emit directional totals for each connection")
    parser.add_argument("--summary", action="store_true", help="write capture and output counts to stderr")
    args = parser.parse_args()
    device = Device(args.device, tuple(args.ip), tuple(args.mac))
    counts = Coverage()
    output_rows = 0
    try:
        with args.capture.open("rb") as stream:
            records = observations(stream, [device], coverage=counts)
            for row in summarize_flows(records) if args.flows else records:
                print(json.dumps(row, separators=(",", ":")))
                output_rows += 1
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
    if args.summary:
        print(json.dumps({**asdict(counts), "output_rows": output_rows}), file=sys.stderr)
    elif not output_rows:
        print(f"No output rows ({counts.matched_frames} matching IP frames out of "
              f"{counts.input_frames} capture frames).", file=sys.stderr)


if __name__ == "__main__":
    main()
