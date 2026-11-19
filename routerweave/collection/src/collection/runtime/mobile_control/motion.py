"""Local frame-motion evidence without a runtime vision Agent."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from typing import Callable


@dataclass(frozen=True, slots=True)
class FrameMotionConfig:
    """Sampling policy for deciding whether a video surface is moving."""

    sample_interval_seconds: float = 0.75
    portrait_crop: tuple[float, float, float, float] = (0.05, 0.17, 0.95, 0.48)
    landscape_crop: tuple[float, float, float, float] = (0.15, 0.12, 0.75, 0.75)
    pixel_delta_threshold: int = 8
    mean_delta_threshold: float = 1.5
    changed_fraction_threshold: float = 0.03

    def validate(self) -> None:
        if self.sample_interval_seconds <= 0:
            raise ValueError("motion sample interval must be positive")
        if not 0 <= self.pixel_delta_threshold <= 255:
            raise ValueError("pixel delta threshold must be between 0 and 255")
        if self.mean_delta_threshold < 0:
            raise ValueError("mean delta threshold cannot be negative")
        if not 0 <= self.changed_fraction_threshold <= 1:
            raise ValueError("changed fraction threshold must be between 0 and 1")
        for crop in (self.portrait_crop, self.landscape_crop):
            left, top, right, bottom = crop
            if not (0 <= left < right <= 1 and 0 <= top < bottom <= 1):
                raise ValueError(f"invalid relative motion crop {crop!r}")


@dataclass(frozen=True, slots=True)
class FrameMotionSample:
    playback: str
    mean_abs_delta: float
    changed_fraction: float
    frame_size: tuple[int, int]
    crop_bounds: tuple[int, int, int, int]
    sample_interval_seconds: float

    def as_state(self) -> dict[str, object]:
        return {
            "playback": self.playback,
            "mean_abs_delta": self.mean_abs_delta,
            "changed_fraction": self.changed_fraction,
            "frame_size": self.frame_size,
            "crop_bounds": self.crop_bounds,
            "sample_interval_seconds": self.sample_interval_seconds,
        }


def sample_frame_motion(
    capture: Callable[[], bytes],
    sleep: Callable[[float], None],
    config: FrameMotionConfig | None = None,
    *,
    crop_bounds: tuple[int, int, int, int] | None = None,
) -> FrameMotionSample:
    """Capture two frames and classify motion in a relative player region."""

    policy = config or FrameMotionConfig()
    policy.validate()
    try:
        from PIL import Image, ImageChops, ImageStat
    except ImportError as exc:  # pragma: no cover - depends on host packaging
        raise RuntimeError("Pillow is required for frame-motion observation") from exc

    first = Image.open(BytesIO(capture())).convert("RGB")
    sleep(policy.sample_interval_seconds)
    second = Image.open(BytesIO(capture())).convert("RGB")
    if first.size != second.size:
        raise ValueError(f"motion frames have different sizes: {first.size} and {second.size}")

    width, height = first.size
    if crop_bounds is None:
        ratios = policy.landscape_crop if width > height else policy.portrait_crop
        left, top, right, bottom = ratios
        bounds = (
            round(width * left), round(height * top),
            round(width * right), round(height * bottom),
        )
    else:
        bounds = crop_bounds
        left, top, right, bottom = bounds
        if not (0 <= left < right <= width and 0 <= top < bottom <= height):
            raise ValueError(f"native player bounds are outside the frame: {bounds!r}")
    difference = ImageChops.difference(first.crop(bounds), second.crop(bounds))
    mean_abs_delta = sum(ImageStat.Stat(difference).mean) / 3
    histogram = difference.convert("L").histogram()
    total_pixels = sum(histogram)
    changed_pixels = sum(histogram[policy.pixel_delta_threshold + 1 :])
    changed_fraction = changed_pixels / total_pixels if total_pixels else 0.0
    moving = (
        mean_abs_delta >= policy.mean_delta_threshold
        and changed_fraction >= policy.changed_fraction_threshold
    )
    return FrameMotionSample(
        "playing" if moving else "paused",
        round(mean_abs_delta, 6),
        round(changed_fraction, 6),
        (width, height),
        bounds,
        policy.sample_interval_seconds,
    )


def frame_fingerprint(frame: bytes) -> str:
    """Return a cheap content fingerprint without invoking a visual Agent.

    The top and bottom chrome are excluded before downsampling so clock,
    battery, and navigation-bar changes do not dominate page-change checks.
    """

    try:
        from PIL import Image
    except ImportError as exc:  # pragma: no cover - depends on host packaging
        raise RuntimeError("Pillow is required for frame fingerprinting") from exc

    image = Image.open(BytesIO(frame)).convert("L")
    width, height = image.size
    if width < 2 or height < 2:
        raise ValueError(f"frame is too small for fingerprinting: {image.size}")
    cropped = image.crop((0, round(height * 0.04), width, round(height * 0.94)))
    reduced = cropped.resize((48, 48), Image.Resampling.BILINEAR)
    return sha256(reduced.tobytes()).hexdigest()
