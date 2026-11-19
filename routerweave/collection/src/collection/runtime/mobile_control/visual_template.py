"""Local template matching for semantic visual element queries.

This module deliberately performs only bounded, deterministic image matching.
It does not invoke OCR, a remote model, or a runtime visual Agent.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class VisualTemplateMatch:
    bounds: tuple[int, int, int, int]
    score: float
    frame_size: tuple[int, int]
    search_bounds: tuple[int, int, int, int]
    template_size: tuple[int, int]


def match_visual_template(
    frame_png: bytes,
    parameters: Mapping[str, Any],
) -> VisualTemplateMatch | None:
    """Match one app-owned template inside a bounded current-frame region."""

    try:
        import cv2
        import numpy as np
        from PIL import Image
    except ImportError as exc:  # pragma: no cover - host packaging failure
        raise RuntimeError("OpenCV, NumPy, and Pillow are required for template queries") from exc

    template_path = Path(str(parameters.get("template_path") or "")).resolve()
    if not template_path.is_file():
        raise ValueError(f"visual template does not exist: {template_path}")
    threshold = float(parameters.get("threshold", 0.78))
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("visual template threshold must be between zero and one")

    frame = Image.open(BytesIO(frame_png)).convert("RGB")
    template = Image.open(template_path).convert("RGB")
    frame_width, frame_height = frame.size
    reference_size = parameters.get("reference_size", (frame_width, frame_height))
    if not isinstance(reference_size, (list, tuple)) or len(reference_size) != 2:
        raise ValueError("reference_size must contain width and height")
    reference_width, reference_height = (int(reference_size[0]), int(reference_size[1]))
    if reference_width <= 0 or reference_height <= 0:
        raise ValueError("reference_size values must be positive")
    scale_x = frame_width / reference_width
    scale_y = frame_height / reference_height
    template_width = max(1, round(template.width * scale_x))
    template_height = max(1, round(template.height * scale_y))
    if template.size != (template_width, template_height):
        template = template.resize(
            (template_width, template_height),
            Image.Resampling.BILINEAR,
        )

    ratios = parameters.get("search_region", (0.0, 0.0, 1.0, 1.0))
    if not isinstance(ratios, (list, tuple)) or len(ratios) != 4:
        raise ValueError("search_region must contain four relative bounds")
    left_ratio, top_ratio, right_ratio, bottom_ratio = map(float, ratios)
    if not (0 <= left_ratio < right_ratio <= 1 and 0 <= top_ratio < bottom_ratio <= 1):
        raise ValueError("search_region must be inside the current viewport")
    search_bounds = (
        round(frame_width * left_ratio),
        round(frame_height * top_ratio),
        round(frame_width * right_ratio),
        round(frame_height * bottom_ratio),
    )
    search = frame.crop(search_bounds)
    comparison = str(parameters.get("comparison") or "grayscale").casefold()
    if comparison == "color":
        search_array = np.asarray(search)
    elif comparison in {"grayscale", "edges"}:
        search_array = cv2.cvtColor(np.asarray(search), cv2.COLOR_RGB2GRAY)
    else:
        raise ValueError("comparison must be grayscale, edges, or color")
    if comparison == "edges":
        search_array = cv2.Canny(search_array, 60, 160)
    raw_scales = parameters.get("template_scales", (1.0,))
    if not isinstance(raw_scales, (list, tuple)) or not raw_scales:
        raise ValueError("template_scales must contain at least one scale")
    scales = tuple(dict.fromkeys(float(value) for value in raw_scales))
    if any(value <= 0 for value in scales):
        raise ValueError("template_scales values must be positive")

    best: tuple[float, tuple[int, int], tuple[int, int]] | None = None
    for scale in scales:
        candidate_size = (
            max(1, round(template.width * scale)),
            max(1, round(template.height * scale)),
        )
        if candidate_size[0] > search.width or candidate_size[1] > search.height:
            continue
        candidate = template
        if candidate.size != candidate_size:
            candidate = candidate.resize(candidate_size, Image.Resampling.BILINEAR)
        if comparison == "color":
            template_array = np.asarray(candidate)
        else:
            template_array = cv2.cvtColor(np.asarray(candidate), cv2.COLOR_RGB2GRAY)
        if comparison == "edges":
            template_array = cv2.Canny(template_array, 60, 160)
        result = cv2.matchTemplate(
            search_array,
            template_array,
            cv2.TM_CCOEFF_NORMED,
        )
        _, candidate_score, _, candidate_location = cv2.minMaxLoc(result)
        if best is None or candidate_score > best[0]:
            best = (float(candidate_score), candidate_location, candidate_size)
    if best is None:
        raise ValueError("all visual template scales are larger than the search region")
    score, location, matched_template_size = best
    if score < threshold:
        return None
    left = search_bounds[0] + int(location[0])
    top = search_bounds[1] + int(location[1])
    return VisualTemplateMatch(
        (
            left,
            top,
            left + matched_template_size[0],
            top + matched_template_size[1],
        ),
        round(float(score), 6),
        frame.size,
        search_bounds,
        matched_template_size,
    )
