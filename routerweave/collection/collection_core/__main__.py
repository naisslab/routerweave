"""Inspect collection evidence without contacting devices or writing files."""

import argparse
import json
from pathlib import Path

from .iot_operations import operation_evidence
from .mobile_windows import network_windows_from_mobile_events, verified_activity_intervals
from .windows_intervals import reconcile_foreground_evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    mobile = modes.add_parser("mobile", help="inspect playbook events")
    mobile.add_argument("events", type=Path)
    mobile.add_argument("--sustain-only", action="store_true")
    windows = modes.add_parser("windows", help="recheck foreground activity windows")
    windows.add_argument("usage_windows", type=Path)
    windows.add_argument("foreground_csv", type=Path)
    windows.add_argument("--capture-end", required=True, type=float)
    windows.add_argument("--minimum-ratio", required=True, type=float)
    iot = modes.add_parser("iot", help="inspect an original operation evidence record")
    iot.add_argument("sample", type=Path)
    iot.add_argument("--contract", help="evidence contract from the collection manifest")
    args = parser.parse_args()
    try:
        if args.mode == "mobile":
            reader = verified_activity_intervals if args.sustain_only else network_windows_from_mobile_events
            result = reader(args.events)
        elif args.mode == "windows":
            with args.usage_windows.open(encoding="utf-8-sig") as handle:
                rows = [json.loads(line) for line in handle if line.strip()]
            result = reconcile_foreground_evidence(rows, args.foreground_csv,
                       capture_ended_epoch=args.capture_end, minimum_ratio=args.minimum_ratio)
        else:
            row = json.loads(args.sample.read_text(encoding="utf-8-sig"))
            result = operation_evidence(row, contract=args.contract)
    except (KeyError, OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"invalid evidence: {exc}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
