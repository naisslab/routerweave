"""Build the three router replay programs locally with Zig 0.14.1."""

import argparse
import subprocess
from pathlib import Path
from shutil import which
from tempfile import TemporaryDirectory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", default="zig", help="Zig executable path or command on PATH")
    parser.add_argument("--output", required=True, type=Path, help="New binary directory")
    parser.add_argument(
        "--target",
        choices=["aarch64-linux-musl", "x86_64-linux-musl"],
        default="aarch64-linux-musl",
    )
    args = parser.parse_args()
    executable = which(args.zig)
    if executable is None:
        parser.error("Zig compiler not found")
    zig = Path(executable).resolve(strict=True)
    output = args.output.resolve()
    if output.exists():
        parser.error("Choose a new output directory")
    source = Path(__file__).resolve().parent
    flags = ["-target", args.target, "-O3", "-ffp-contract=off", "-pthread"]
    if args.target == "aarch64-linux-musl":
        flags.append("-mcpu=cortex_a53")

    def compile_units(compiler, files, extra):
        objects = []
        for name in files:
            obj = temp / (name + ".o")
            subprocess.run(
                [zig, compiler, *flags, *extra, "-c", source / name, "-o", obj], check=True
            )
            objects.append(obj)
        return objects

    with TemporaryDirectory(dir=output.parent) as folder:
        temp = Path(folder)
        stage = temp / "bin"
        stage.mkdir()
        common = compile_units("cc", ["iot_math.c", "app_api.c"], ["-std=c11", "-DRF_NATIVE_NEON"])
        common += compile_units(
            "c++", ["online_transport.cpp", "native_features.cpp", "inference.cpp"], ["-std=c++17"]
        )

        def link(name, entry, objects, defines=()):
            subprocess.run(
                [
                    zig,
                    "c++",
                    *flags,
                    "-std=c++17",
                    "-static",
                    *defines,
                    source / entry,
                    *objects,
                    "-o",
                    stage / name,
                ],
                check=True,
            )

        link("capacity", "capacity.cpp", common)
        baseline = compile_units("cc", ["rf_infer.c"], ["-std=c11"])
        baseline += compile_units(
            "c++",
            ["flow_online.cpp", "native_behaviot.cpp", "native_flowprint.cpp"],
            ["-std=c++17"],
        )
        link("latency", "latency.cpp", common + baseline)
        link("latency-rf-window", "latency.cpp", common + baseline, ["-DRF_WINDOW"])
        stage.rename(output)


if __name__ == "__main__":
    main()
