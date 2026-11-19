#!/usr/bin/env python3
"""Windows strategy registry and validation CLI.

Mobile app tasks intentionally do not pass through this module. Android and
iOS use ``collection.runtime.mobile_control`` and its independent validator.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_STRATEGY_FILE = REPO_ROOT / "configs" / "control_strategies.json"


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    ok: bool
    detail: str = ""
    value: Any = None

    def as_dict(self) -> dict[str, Any]:
        row: dict[str, Any] = {"name": self.name, "ok": self.ok}
        if self.detail:
            row["detail"] = self.detail
        if self.value is not None:
            row["value"] = self.value
        return row


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_stdout_json(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=True, indent=2))


def load_registry(path: Path = DEFAULT_STRATEGY_FILE) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("profiles"), dict):
        raise ValueError(f"Invalid strategy registry: {path}")
    return payload


def get_profile(registry: dict[str, Any], name: str) -> dict[str, Any]:
    profiles = registry.get("profiles", {})
    if name not in profiles:
        available = ", ".join(sorted(profiles))
        raise KeyError(f"Unknown profile '{name}'. Available profiles: {available}")
    profile = profiles[name]
    if not isinstance(profile, dict):
        raise ValueError(f"Profile must be an object: {name}")
    if profile.get("platform") != "windows":
        raise ValueError(
            f"Strategy profiles are Windows-only; use collection.runtime.mobile_control for {name}"
        )
    return profile


def resolve_repo_path(value: str | Path, root: Path = REPO_ROOT) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _required_file_checks(
    run_dir: Path, validation: dict[str, Any], checks: list[Check]
) -> None:
    for relative in validation.get("required_files", []):
        path = run_dir / str(relative)
        checks.append(Check(f"file:{relative}", path.is_file(), str(path)))


def _append_validation(
    checks: list[Check], metrics: dict[str, Any], prefix: str, result: dict[str, Any]
) -> None:
    for row in result.get("checks", []):
        checks.append(
            Check(
                f"{prefix}:{row.get('name', 'check')}",
                bool(row.get("ok")),
                str(row.get("detail", "")),
                row.get("value"),
            )
        )
    metrics[prefix] = result.get("metrics", {})


def validate_run(
    profile_name: str,
    profile: dict[str, Any],
    run_dir: Path,
) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    validation = profile.get("validation") or {}
    checks = [Check("run_dir:exists", run_dir.is_dir(), str(run_dir))]
    metrics: dict[str, Any] = {}
    if not run_dir.is_dir():
        return _validation_result(profile_name, profile, run_dir, checks, metrics)

    _required_file_checks(run_dir, validation, checks)
    if isinstance(validation.get("windows_capture"), dict):
        from collection.runtime.windows.validation import validate_windows_run

        _append_validation(
            checks, metrics, "windows", validate_windows_run(run_dir)
        )
    else:
        checks.append(
            Check(
                "validation:supported",
                False,
                "profile must declare windows_capture",
            )
        )
    return _validation_result(profile_name, profile, run_dir, checks, metrics)


def _validation_result(
    profile_name: str,
    profile: dict[str, Any],
    run_dir: Path,
    checks: list[Check],
    metrics: dict[str, Any],
) -> dict[str, Any]:
    return {
        "profile": profile_name,
        "platform": profile.get("platform"),
        "run_dir": str(run_dir),
        "ok": all(check.ok for check in checks),
        "checks": [check.as_dict() for check in checks],
        "metrics": metrics,
    }


def render_command(
    profile: dict[str, Any], command_name: str, overrides: dict[str, str]
) -> str:
    commands = profile.get("commands") or {}
    if command_name not in commands:
        available = ", ".join(sorted(commands))
        raise KeyError(f"Unknown command '{command_name}'. Available commands: {available}")
    context = dict(profile.get("defaults") or {})
    context.update(overrides)
    return "\n".join(
        rendered
        for line in commands[command_name]
        if (rendered := str(line).format(**context).strip())
    )


def check_profile(
    profile_name: str, profile: dict[str, Any], root: Path = REPO_ROOT
) -> dict[str, Any]:
    checks: list[Check] = []
    for script in profile.get("owner_scripts", []):
        path = resolve_repo_path(script, root)
        checks.append(Check(f"script:{script}", path.is_file(), str(path)))
    stable_plan = profile.get("stable_plan")
    if stable_plan:
        path = resolve_repo_path(stable_plan, root)
        checks.append(Check(f"stable_plan:{stable_plan}", path.is_file(), str(path)))
    checks.append(
        Check(
            "validation:present",
            isinstance(profile.get("validation"), dict),
            "validation object is required",
        )
    )
    return {
        "profile": profile_name,
        "ok": all(check.ok for check in checks),
        "checks": [check.as_dict() for check in checks],
    }


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if not (line := raw.strip()):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
            if isinstance(row, dict):
                rows.append(row)
    return rows


def validate_batch(
    profile_name: str, profile: dict[str, Any], manifest_path: Path
) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    if manifest_path.suffix.lower() == ".jsonl":
        rows = load_jsonl(manifest_path)
    else:
        payload = read_json(manifest_path)
        if isinstance(payload, dict) and isinstance(payload.get("runs"), list):
            rows = [row for row in payload["runs"] if isinstance(row, dict)]
        elif isinstance(payload, list):
            rows = [row for row in payload if isinstance(row, dict)]
        else:
            raise ValueError("Batch validation expects JSONL, a JSON list, or runs[].")

    results: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        out_dir = row.get("out_dir") or row.get("run_out") or row.get("sample_out")
        if not out_dir:
            results.append({"index": index, "ok": False, "error": "missing out_dir"})
            continue
        run_path = Path(str(out_dir))
        if not run_path.is_absolute():
            run_path = (manifest_path.parent / run_path).resolve()
            if not run_path.exists():
                run_path = resolve_repo_path(str(out_dir))
        result = validate_run(profile_name, profile, run_path)
        result["index"] = index
        results.append(result)
    passed = sum(item.get("ok") is True for item in results)
    return {
        "profile": profile_name,
        "manifest": str(manifest_path),
        "ok": passed == len(results),
        "runs": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
    }


def parse_key_values(values: list[str] | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in values or []:
        if "=" not in raw:
            raise ValueError(f"--set expects KEY=VALUE, got: {raw}")
        key, value = raw.split("=", 1)
        if not (key := key.strip()):
            raise ValueError(f"--set key cannot be empty: {raw}")
        parsed[key] = value
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List, print, and validate Windows control strategies."
    )
    parser.add_argument("--strategy-file", default=str(DEFAULT_STRATEGY_FILE))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    show = sub.add_parser("show")
    show.add_argument("profile")
    check = sub.add_parser("check-profile")
    check.add_argument("profile")
    command = sub.add_parser("print-command")
    command.add_argument("profile")
    command.add_argument("name")
    command.add_argument("--set", action="append", default=[])
    validate = sub.add_parser("validate-run")
    validate.add_argument("profile")
    validate.add_argument("run_dir")
    batch = sub.add_parser("validate-batch")
    batch.add_argument("profile")
    batch.add_argument("manifest")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        registry = load_registry(Path(args.strategy_file))
        if args.command == "list":
            write_stdout_json(
                {
                    "profiles": [
                        {
                            "name": name,
                            "platform": profile.get("platform"),
                            "summary": profile.get("summary"),
                        }
                        for name, profile in sorted(registry["profiles"].items())
                    ]
                }
            )
            return 0
        profile = get_profile(registry, args.profile)
        if args.command == "show":
            write_stdout_json(profile)
            return 0
        if args.command == "check-profile":
            result = check_profile(args.profile, profile)
        elif args.command == "print-command":
            print(render_command(profile, args.name, parse_key_values(args.set)))
            return 0
        elif args.command == "validate-run":
            result = validate_run(args.profile, profile, resolve_repo_path(args.run_dir))
        else:
            result = validate_batch(
                args.profile, profile, resolve_repo_path(args.manifest)
            )
        write_stdout_json(result)
        return 0 if result["ok"] else 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
