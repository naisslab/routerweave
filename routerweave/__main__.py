"""Run a Routerweave experiment from the repository root."""

import argparse
from pathlib import Path
import runpy
import sys


COMMANDS = {
    "ground-truth": ("collection", "collection_core", "Read collection evidence and verified intervals"),
    "traffic": ("traffic", "shared_traffic", "Extract device packets or aggregate flows"),
    "activity-prepare": ("recognition/activity", "activity.prepare", "Extract labelled activity windows"),
    "activity-train": ("recognition/activity", "activity.train", "Fit an application activity classifier"),
    "activity-predict": ("recognition/activity", "activity.predict", "Predict activity on a recording"),
    "iot-train": ("recognition/iot", "iot_operations.train", "Fit a localizer and operation classifier"),
    "iot-predict": ("recognition/iot", "iot_operations", "Locate and classify IoT operations"),
    "case-study": ("applications", "case_studies", "Evaluate Screen Time or appliance energy"),
    "evaluate": ("evaluation", "score", "Score predictions and router measurements"),
}


def main():
    parser = argparse.ArgumentParser(prog="python -m routerweave", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, (_, _, description) in COMMANDS.items():
        commands.add_parser(name, help=description)
    command = parser.parse_args(sys.argv[1:2]).command
    directory, module, _ = COMMANDS[command]
    sys.path.insert(0, str(Path(__file__).resolve().parent / directory))
    del sys.argv[1]
    runpy.run_module(module, run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    main()
