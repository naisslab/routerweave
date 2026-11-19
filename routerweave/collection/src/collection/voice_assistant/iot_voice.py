#!/usr/bin/env python3
"""Offline voice stimuli for acoustic IoT assistant experiments.

The workstation synthesizes WAV files before router capture and plays those
files through the Windows default output device during a sample.  This keeps
assistant wake-word and ASR traffic inside the observed assistant/device path
instead of adding an online TTS request to the capture.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import wave
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from collection.runtime.artifacts import EventLog
from collection.runtime.errors import DemoError


SUPPORTED_ACTIONS = (
    "power_on",
    "power_off",
    "lock",
    "unlock",
    "change_color",
    "brightness_up",
    "brightness_down",
)


def _slug(value: object) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value).strip()).strip("-.")
    return text.lower() or "value"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DemoError(f"Unable to read voice JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DemoError(f"Voice JSON root must be an object: {path}")
    return value


def normalize_target(action: str, target: str | int | None) -> str | int | None:
    if target is None:
        return None
    if action in {"brightness_up", "brightness_down"}:
        try:
            value = int(target)
        except (TypeError, ValueError) as exc:
            raise DemoError(f"Brightness target must be an integer: {target!r}") from exc
        if not 0 <= value <= 100:
            raise DemoError(f"Brightness target must be inside 0..100: {value}")
        return value
    return target


def validate_profile(profile: dict[str, Any]) -> None:
    if int(profile.get("schema_version", 0)) != 1:
        raise DemoError("Voice profile schema_version must be 1")
    templates = profile.get("command_templates") or {}
    missing = set(SUPPORTED_ACTIONS) - set(templates)
    if missing:
        raise DemoError(f"Voice profile is missing action templates: {sorted(missing)}")
    assistants = profile.get("assistants") or {}
    if not assistants:
        raise DemoError("Voice profile must define assistants")
    for assistant, config in assistants.items():
        if not str(config.get("wake_phrase") or "").strip():
            raise DemoError(f"Assistant {assistant!r} has no wake_phrase")
        utterance = str(config.get("utterance_template") or "")
        if "{wake_phrase}" not in utterance or "{command}" not in utterance:
            raise DemoError(
                f"Assistant {assistant!r} utterance_template must contain "
                "{wake_phrase} and {command}"
            )


@dataclass(frozen=True)
class VoiceCommand:
    assistant: str
    device_name: str
    action: str
    target_value: str | int | None
    command_text: str
    utterance_text: str
    voice_name: str
    asset_path: str
    sha256: str
    duration_seconds: float


class WindowsSapiSynthesizer:
    """Use installed Windows SAPI voices without a network service."""

    SCRIPT = r"""
Add-Type -AssemblyName System.Speech
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
try {
  $voice = [Environment]::GetEnvironmentVariable('IOT_VOICE_SAPI_NAME')
  if ($voice) { $synth.SelectVoice($voice) }
  $synth.Rate = [int][Environment]::GetEnvironmentVariable('IOT_VOICE_SAPI_RATE')
  $output = [Environment]::GetEnvironmentVariable('IOT_VOICE_WAV_PATH')
  $text = [Environment]::GetEnvironmentVariable('IOT_VOICE_TEXT')
  $synth.SetOutputToWaveFile($output)
  $synth.Speak($text)
} finally {
  $synth.Dispose()
}
"""

    LIST_SCRIPT = r"""
Add-Type -AssemblyName System.Speech
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
try {
  $rows = $synth.GetInstalledVoices() | ForEach-Object {
    [PSCustomObject]@{
      name = $_.VoiceInfo.Name
      culture = $_.VoiceInfo.Culture.Name
      gender = [string]$_.VoiceInfo.Gender
      enabled = $_.Enabled
    }
  }
  $rows | ConvertTo-Json -Compress
} finally {
  $synth.Dispose()
}
"""

    @staticmethod
    def _powershell() -> str:
        if platform.system() != "Windows":
            raise DemoError("Windows SAPI synthesis is available only on Windows")
        return "powershell"

    def _run_script(
        self,
        script: str,
        *,
        env: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess[str]:
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        return subprocess.run(
            [self._powershell(), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout,
        )

    def installed_voices(self) -> list[dict[str, Any]]:
        proc = self._run_script(self.LIST_SCRIPT)
        if proc.returncode:
            raise DemoError(f"Unable to list SAPI voices: {proc.stderr.strip()}")
        raw = proc.stdout.strip()
        if not raw:
            return []
        value = json.loads(raw)
        return value if isinstance(value, list) else [value]

    def synthesize(self, text: str, output: Path, voice_name: str, rate: int = 0) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary_name = tempfile.mkstemp(prefix="iot-voice-", suffix=".wav")
        os.close(handle)
        temporary = Path(temporary_name)
        temporary.unlink(missing_ok=True)
        env = os.environ.copy()
        env.update(
            {
                "IOT_VOICE_TEXT": text,
                # Windows PowerShell 5 / System.Speech can mis-handle a WAV
                # destination below a non-ASCII working-directory path.  SAPI
                # writes to the system temp directory and Python moves the
                # completed file to the requested artifact path.
                "IOT_VOICE_WAV_PATH": str(temporary),
                "IOT_VOICE_SAPI_NAME": voice_name,
                "IOT_VOICE_SAPI_RATE": str(rate),
            }
        )
        proc = self._run_script(self.SCRIPT, env=env, timeout=120)
        if proc.returncode or not temporary.is_file():
            temporary.unlink(missing_ok=True)
            raise DemoError(
                f"SAPI synthesis failed for {output}: "
                f"exit={proc.returncode}; {proc.stderr.strip() or proc.stdout.strip()}"
            )
        shutil.move(str(temporary), str(output))


class WindowsWavePlayer:
    """Synchronously play a WAV on the current Windows default output."""

    def play(self, path: Path) -> None:
        if platform.system() != "Windows":
            raise DemoError("Built-in WAV playback is available only on Windows")
        import winsound

        # PlaySound is synchronous unless SND_ASYNC is explicitly requested.
        winsound.PlaySound(str(path.resolve()), winsound.SND_FILENAME)


class VoiceSystem:
    def __init__(
        self,
        profile_path: Path,
        asset_root: Path,
        *,
        synthesizer: WindowsSapiSynthesizer | None = None,
        player: WindowsWavePlayer | None = None,
    ) -> None:
        self.profile_path = profile_path.resolve()
        self.profile = _read_json(self.profile_path)
        validate_profile(self.profile)
        self.asset_root = asset_root.resolve()
        self.synthesizer = synthesizer or WindowsSapiSynthesizer()
        self.player = player or WindowsWavePlayer()

    def assistant_config(self, assistant: str) -> dict[str, Any]:
        config = (self.profile.get("assistants") or {}).get(assistant)
        if not isinstance(config, dict):
            raise DemoError(f"Unknown voice assistant {assistant!r}")
        return config

    def render(
        self,
        assistant: str,
        device_name: str,
        action: str,
        target_value: str | int | None = None,
        *,
        voice_name: str | None = None,
    ) -> dict[str, Any]:
        if action not in SUPPORTED_ACTIONS:
            raise DemoError(f"Unsupported voice action {action!r}")
        assistant_config = self.assistant_config(assistant)
        templates = dict(self.profile["command_templates"])
        templates.update(assistant_config.get("command_templates") or {})
        target_spoken: str | int | None = target_value
        spoken_values = self.profile.get("spoken_values") or {}
        if target_value is not None:
            target_spoken = spoken_values.get(str(target_value), target_value)
        values = {
            "device_name": device_name,
            "target": target_spoken,
            "target_percent": target_spoken,
        }
        try:
            command = str(templates[action]).format(**values)
            utterance = str(assistant_config["utterance_template"]).format(
                wake_phrase=assistant_config["wake_phrase"],
                command=command,
            )
        except KeyError as exc:
            raise DemoError(f"Voice template for {action!r} needs missing value {exc}") from exc
        selected_voice = voice_name or str(assistant_config.get("voice_name") or "")
        if not selected_voice:
            raise DemoError(f"Assistant {assistant!r} has no voice_name")
        return {
            "assistant": assistant,
            "device_name": device_name,
            "action": action,
            "target_value": target_value,
            "command_text": command,
            "utterance_text": utterance,
            "voice_name": selected_voice,
            "rate": int(assistant_config.get("rate", 0)),
        }

    def asset_path(self, rendered: dict[str, Any]) -> Path:
        identity = json.dumps(
            {
                key: rendered[key]
                for key in (
                    "assistant",
                    "device_name",
                    "action",
                    "target_value",
                    "utterance_text",
                    "voice_name",
                    "rate",
                )
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256(identity).hexdigest()[:12]
        target = "" if rendered["target_value"] is None else f"-{_slug(rendered['target_value'])}"
        filename = f"{_slug(rendered['action'])}{target}-{digest}.wav"
        return self.asset_root / _slug(rendered["assistant"]) / _slug(rendered["device_name"]) / filename

    @staticmethod
    def _wav_duration(path: Path) -> float:
        try:
            with wave.open(str(path), "rb") as wav:
                frames, rate = wav.getnframes(), wav.getframerate()
                if frames <= 0 or rate <= 0:
                    raise DemoError(f"WAV has no audio frames: {path}")
                return frames / rate
        except (OSError, wave.Error) as exc:
            raise DemoError(f"Invalid WAV asset {path}: {exc}") from exc

    def prepare(
        self,
        assistant: str,
        device_name: str,
        action: str,
        target_value: str | int | None = None,
        *,
        voice_name: str | None = None,
        overwrite: bool = False,
    ) -> VoiceCommand:
        rendered = self.render(assistant, device_name, action, target_value, voice_name=voice_name)
        path = self.asset_path(rendered)
        if overwrite or not path.is_file():
            self.synthesizer.synthesize(
                rendered["utterance_text"],
                path,
                rendered["voice_name"],
                rendered["rate"],
            )
        duration = self._wav_duration(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        command = VoiceCommand(
            assistant=assistant,
            device_name=device_name,
            action=action,
            target_value=target_value,
            command_text=rendered["command_text"],
            utterance_text=rendered["utterance_text"],
            voice_name=rendered["voice_name"],
            asset_path=str(path),
            sha256=digest,
            duration_seconds=duration,
        )
        metadata = path.with_suffix(".json")
        metadata.write_text(
            json.dumps(
                {
                    **asdict(command),
                    "profile": str(self.profile_path),
                    "generated_at_epoch": time.time(),
                    "backend": "windows_sapi",
                },
                ensure_ascii=False,
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
        return command

    def prepared(
        self,
        assistant: str,
        device_name: str,
        action: str,
        target_value: str | int | None = None,
        *,
        voice_name: str | None = None,
    ) -> VoiceCommand:
        rendered = self.render(assistant, device_name, action, target_value, voice_name=voice_name)
        path = self.asset_path(rendered)
        if not path.is_file():
            raise DemoError(
                f"Prepared voice asset is missing: {path}. Run iot_voice prepare-plan before capture."
            )
        duration = self._wav_duration(path)
        return VoiceCommand(
            assistant=assistant,
            device_name=device_name,
            action=action,
            target_value=target_value,
            command_text=rendered["command_text"],
            utterance_text=rendered["utterance_text"],
            voice_name=rendered["voice_name"],
            asset_path=str(path),
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            duration_seconds=duration,
        )

    def play(self, command: VoiceCommand, log: EventLog | None = None) -> dict[str, Any]:
        path = Path(command.asset_path)
        started = time.time()
        if log:
            log.write(
                "voice_audio_start",
                assistant=command.assistant,
                device_name=command.device_name,
                action=command.action,
                target_value=command.target_value,
                utterance_text=command.utterance_text,
                voice_name=command.voice_name,
                asset_path=command.asset_path,
                sha256=command.sha256,
                expected_duration_seconds=command.duration_seconds,
            )
        self.player.play(path)
        ended = time.time()
        if log:
            log.write(
                "voice_audio_end",
                assistant=command.assistant,
                action=command.action,
                elapsed_seconds=ended - started,
            )
        return {
            "command_mode": "host_audio",
            "voice_assistant": command.assistant,
            "voice_device_name": command.device_name,
            "voice_command_text": command.command_text,
            "voice_utterance_text": command.utterance_text,
            "voice_name": command.voice_name,
            "voice_audio_path": command.asset_path,
            "voice_audio_sha256": command.sha256,
            "voice_audio_duration_seconds": command.duration_seconds,
            "voice_audio_start_epoch": started,
            "voice_audio_end_epoch": ended,
            "voice_audio_output": "windows_default",
        }


class VoiceStimulus:
    """Resolve plan-level acoustic commands and expose capture metadata."""

    def __init__(self, config: dict[str, Any]) -> None:
        if config.get("mode") != "host_audio":
            raise DemoError("Voice command_input mode must be host_audio")
        self.assistant = str(config.get("assistant") or "")
        if not self.assistant:
            raise DemoError("Voice command_input requires assistant")
        profile = Path(str(config.get("profile") or "configs/voice_assistant_profiles.json"))
        asset_root = Path(str(config.get("asset_root") or "runs/collection/voice/voice-assets"))
        self.system = VoiceSystem(profile, asset_root)
        self.voice_name = str(config.get("voice_name") or "") or None
        self.require_prepared = bool(config.get("require_prepared_audio", True))

    def command(
        self,
        device: dict[str, Any],
        action: str,
        target_value: str | int | None,
    ) -> VoiceCommand:
        device_name = str(device.get("voice_name") or device.get("name") or "").strip()
        if not device_name:
            raise DemoError(f"Device {device.get('id')!r} has no voice_name or name")
        if self.require_prepared:
            return self.system.prepared(
                self.assistant, device_name, action, target_value, voice_name=self.voice_name
            )
        return self.system.prepare(
            self.assistant, device_name, action, target_value, voice_name=self.voice_name
        )

    def play(
        self,
        device: dict[str, Any],
        action: str,
        target_value: str | int | None,
        log: EventLog,
    ) -> dict[str, Any]:
        return self.system.play(self.command(device, action, target_value), log)

    def preflight(self, plan: dict[str, Any]) -> list[VoiceCommand]:
        commands: list[VoiceCommand] = []
        seen: set[tuple[str, str, str]] = set()
        for device, action, target in iter_plan_commands(plan):
            device_name = str(device.get("voice_name") or device.get("name") or "")
            key = (device_name, action, str(target))
            if key in seen:
                continue
            seen.add(key)
            commands.append(self.command(device, action, target))
        return commands


def apply_voice_override(
    plan: dict[str, Any],
    assistant: str | None,
    profile: str,
    asset_root: str,
    voice_name: str | None,
    allow_generate: bool,
) -> None:
    if not assistant:
        return
    plan["command_input"] = {
        "mode": "host_audio",
        "assistant": assistant,
        "profile": profile,
        "asset_root": asset_root,
        "voice_name": voice_name,
        "require_prepared_audio": not allow_generate,
    }


def apply_voice_device_names(plan: dict[str, Any], overrides: list[str] | None) -> None:
    if not overrides:
        return
    devices = {str(device.get("id") or ""): device for device in plan.get("devices") or []}
    for raw in overrides:
        device_id, separator, voice_name = raw.partition("=")
        device_id, voice_name = device_id.strip(), voice_name.strip()
        if not separator or not device_id or not voice_name:
            raise DemoError("Voice device-name overrides must use DEVICE_ID=ASSISTANT_NAME")
        if device_id not in devices:
            raise DemoError(f"Unknown device id in voice name override: {device_id}")
        devices[device_id]["voice_name"] = voice_name


def iter_plan_commands(plan: dict[str, Any]) -> Iterable[tuple[dict[str, Any], str, str | int | None]]:
    enabled = tuple(plan.get("enabled_actions") or ())
    colors = list(plan.get("supported_colors") or [])
    brightness_targets = list(plan.get("voice_brightness_targets") or range(10, 95, 5))
    for device in plan.get("devices") or []:
        if device.get("actions"):
            for action in device["actions"]:
                yield device, str(action["name"]), action.get("to")
            continue
        actions = enabled or ("power_on", "change_color", "brightness_up", "brightness_down", "power_off")
        for action in actions:
            if action == "change_color":
                for color in colors:
                    yield device, action, color
            elif action in {"brightness_up", "brightness_down"}:
                for target in brightness_targets:
                    yield device, action, int(target)
            else:
                yield device, action, "on" if action == "power_on" else "off"


def validate_assets(asset_root: Path) -> dict[str, Any]:
    root = asset_root.resolve()
    errors: list[str] = []
    wavs = sorted(root.rglob("*.wav")) if root.is_dir() else []
    if not wavs:
        errors.append(f"No WAV assets found under {root}")
    total_bytes = 0
    for wav_path in wavs:
        total_bytes += wav_path.stat().st_size
        try:
            VoiceSystem._wav_duration(wav_path)
        except DemoError as exc:
            errors.append(str(exc))
            continue
        metadata_path = wav_path.with_suffix(".json")
        if not metadata_path.is_file():
            errors.append(f"Missing metadata for {wav_path}")
            continue
        try:
            metadata = _read_json(metadata_path)
        except DemoError as exc:
            errors.append(str(exc))
            continue
        actual_hash = hashlib.sha256(wav_path.read_bytes()).hexdigest()
        if metadata.get("sha256") != actual_hash:
            errors.append(f"SHA-256 mismatch for {wav_path}")
        if metadata.get("asset_path") and Path(str(metadata["asset_path"])).name != wav_path.name:
            errors.append(f"Metadata asset name mismatch for {wav_path}")
    return {
        "valid": not errors,
        "asset_root": str(root),
        "wav_count": len(wavs),
        "total_bytes": total_bytes,
        "errors": errors,
    }


def _build_system(args: argparse.Namespace) -> VoiceSystem:
    return VoiceSystem(Path(args.profile), Path(args.asset_root))


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare and play offline acoustic assistant commands")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-voices")

    validate = sub.add_parser("validate-profile")
    validate.add_argument("--profile", default="configs/voice_assistant_profiles.json")

    validate_audio = sub.add_parser("validate-assets")
    validate_audio.add_argument("--asset-root", default="runs/collection/voice/voice-assets")

    render = sub.add_parser("render")
    render.add_argument("--profile", default="configs/voice_assistant_profiles.json")
    render.add_argument("--asset-root", default="runs/collection/voice/voice-assets")
    render.add_argument("--assistant", required=True)
    render.add_argument("--device-name", required=True)
    render.add_argument("--action", choices=SUPPORTED_ACTIONS, required=True)
    render.add_argument("--target")
    render.add_argument("--voice-name")

    prepare = sub.add_parser("prepare-plan")
    prepare.add_argument("--profile", default="configs/voice_assistant_profiles.json")
    prepare.add_argument("--asset-root", default="runs/collection/voice/voice-assets")
    prepare.add_argument("--assistant", required=True)
    prepare.add_argument("--plan", required=True)
    prepare.add_argument("--voice-name")
    prepare.add_argument("--voice-device-name", action="append", default=[])
    prepare.add_argument("--overwrite", action="store_true")

    play = sub.add_parser("play")
    play.add_argument("--profile", default="configs/voice_assistant_profiles.json")
    play.add_argument("--asset-root", default="runs/collection/voice/voice-assets")
    play.add_argument("--assistant", required=True)
    play.add_argument("--device-name", required=True)
    play.add_argument("--action", choices=SUPPORTED_ACTIONS, required=True)
    play.add_argument("--target")
    play.add_argument("--voice-name")
    play.add_argument("--allow-generate", action="store_true")

    args = parser.parse_args()
    if args.command == "list-voices":
        print(json.dumps(WindowsSapiSynthesizer().installed_voices(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "validate-profile":
        profile = _read_json(Path(args.profile))
        validate_profile(profile)
        print(json.dumps({"valid": True, "assistants": sorted(profile["assistants"])}, ensure_ascii=False))
        return 0
    if args.command == "validate-assets":
        result = validate_assets(Path(args.asset_root))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["valid"] else 2
    system = _build_system(args)
    if args.command == "render":
        target = normalize_target(args.action, args.target)
        print(
            json.dumps(
                system.render(
                    args.assistant, args.device_name, args.action, target, voice_name=args.voice_name
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if args.command == "prepare-plan":
        plan = _read_json(Path(args.plan))
        apply_voice_device_names(plan, args.voice_device_name)
        prepared: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for device, action, target in iter_plan_commands(plan):
            device_name = str(device.get("voice_name") or device.get("name") or "")
            key = (device_name, action, str(target))
            if key in seen:
                continue
            seen.add(key)
            command = system.prepare(
                args.assistant,
                device_name,
                action,
                target,
                voice_name=args.voice_name,
                overwrite=args.overwrite,
            )
            prepared.append(asdict(command))
        print(json.dumps({"prepared": len(prepared), "commands": prepared}, ensure_ascii=False, indent=2))
        return 0
    target = normalize_target(args.action, args.target)
    command = (
        system.prepare(
            args.assistant,
            args.device_name,
            args.action,
            target,
            voice_name=args.voice_name,
        )
        if args.allow_generate
        else system.prepared(
            args.assistant,
            args.device_name,
            args.action,
            target,
            voice_name=args.voice_name,
        )
    )
    print(json.dumps(system.play(command), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
