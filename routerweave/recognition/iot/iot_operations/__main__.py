"""Read one normalized device trace and print its classified candidates."""

import argparse
import json
from pathlib import Path

from . import Recognizer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--localizer", type=Path, required=True)
    parser.add_argument("--classifier", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    with args.input.open(encoding="utf-8") as stream:
        trace = json.load(stream)
    recognizer = Recognizer(args.localizer, args.classifier)
    print(json.dumps(recognizer.recognize(trace["packets"], trace["device_id"]), allow_nan=False))


if __name__ == "__main__":
    main()
