"""Adapt one timestamp-ordered packet recording to numerical baseline inputs."""

import argparse
from bisect import bisect_left, bisect_right
import json
import math
from pathlib import Path


def adapt(dataset, recording, taxonomy):
    packets = recording["packets"]
    times = packets["t"]
    if not all(math.isfinite(t) for t in times) or times != sorted(times):
        raise ValueError("Expected finite, ordered packet times")
    if set(packets) != {"t", "flow", "size", "direction", "local"} or any(
        len(c) != len(times) for c in packets.values()
    ):
        raise ValueError("Expected five aligned packet columns")

    def unit(key, indices, group, label):
        row = {
            "id": key,
            "group": group,
            "packets": {k: [c[i] for i in indices] for k, c in packets.items()},
        }
        if label is not None:
            row["label"] = label
        return row

    if dataset == "app":
        return [
            unit(
                w["id"],
                range(bisect_right(times, w["end"] - 30), bisect_right(times, w["end"])),
                recording["platform"],
                w.get("label"),
            )
            for w in recording["windows"]
        ]
    if dataset == "iot":
        units = []
        for candidate in recording["candidates"]:
            members = candidate["members"]
            if members != sorted(set(members)) or any(i < 0 or i >= len(times) for i in members):
                raise ValueError("Candidate contains invalid member positions")
            units.append(
                unit(candidate["id"], members, recording["device"], candidate.get("label"))
            )
        return units
    if dataset == "behaviot":
        label = None
        if "action" in recording:
            category = taxonomy["device_categories"][recording["device"]]
            operation = taxonomy["operation_families"][recording["action"]]
            label = f"{category}/{operation}"
        return [unit(recording["id"], range(len(times)), recording["device"], label)]
    if not times:
        return []
    app = recording.get("app")
    if app is not None and app not in taxonomy["app_purposes"]:
        return []
    # Anchor at the first eligible packet in this capture, retaining the last nonempty partial window.
    result = []
    for j in range(math.floor((times[-1] - times[0]) / 30) + 1):
        end = times[0] + 30 * (j + 1)
        ids = range(bisect_left(times, end - 30), bisect_left(times, end))
        if ids:
            result.append(
                unit(
                    f"{recording['id']}:{j:04d}", ids, "android", taxonomy["app_purposes"].get(app)
                )
            )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", choices=["app", "iot", "behaviot", "itc"])
    parser.add_argument("recording", type=Path)
    args = parser.parse_args()
    config = Path(__file__).with_name("taxonomy.json")
    print(
        json.dumps(
            adapt(
                args.dataset,
                json.loads(args.recording.read_text(encoding="utf-8")),
                json.loads(config.read_text(encoding="utf-8")),
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
