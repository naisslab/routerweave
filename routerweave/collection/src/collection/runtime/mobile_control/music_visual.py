"""Local visual evidence for inaccessible bottom music players."""

from __future__ import annotations

from hashlib import sha256
from io import BytesIO
from typing import Any

from PIL import Image


def bottom_music_player_state(frame: bytes) -> dict[str, Any]:
    """Recognize a portrait bottom player without exposing an action coordinate.

    The detector reads the conventional mini-player band relative to the current
    screenshot.  It never returns a hit point and is used only as a postcondition
    for platform media commands.  A pause glyph means playback is active; a play
    glyph means playback is paused.
    """

    image = Image.open(BytesIO(frame)).convert("L")
    width, height = image.size
    if width <= 0 or height <= width:
        return {"playback": "unknown", "recognized": False}

    # The control is located from the current portrait mini-player layout.  All
    # measurements scale with the live viewport and are never used for tapping.
    center_x = round(width * 0.749)
    center_y = round(height * 0.886)
    half_size = max(6, round(width * 0.016))
    left = max(0, center_x - half_size)
    top = max(0, center_y - half_size)
    right = min(width, center_x + half_size + 1)
    bottom = min(height, center_y + half_size + 1)
    dark = {
        (x, y)
        for y in range(top, bottom)
        for x in range(left, right)
        if image.getpixel((x, y)) < 140
    }
    components: list[list[tuple[int, int]]] = []
    while dark:
        pending = [dark.pop()]
        component: list[tuple[int, int]] = []
        while pending:
            point = pending.pop()
            component.append(point)
            x, y = point
            for neighbor in ((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)):
                if neighbor in dark:
                    dark.remove(neighbor)
                    pending.append(neighbor)
        components.append(component)

    shapes: list[tuple[int, int, int]] = []
    for component in sorted(components, key=len, reverse=True)[:3]:
        xs = [point[0] for point in component]
        ys = [point[1] for point in component]
        shapes.append((len(component), max(xs) - min(xs) + 1, max(ys) - min(ys) + 1))

    scale = width / 750.0
    playing = (
        len(shapes) >= 2
        and all(size >= 70 * scale * scale for size, _, _ in shapes[:2])
        and all(tall >= 14 * scale for _, _, tall in shapes[:2])
        and all(wide <= 9 * scale for _, wide, _ in shapes[:2])
    )
    paused = (
        bool(shapes)
        and shapes[0][0] >= 100 * scale * scale
        and shapes[0][1] >= 11 * scale
        and shapes[0][2] >= 14 * scale
        and not playing
    )
    playback = "playing" if playing else "paused" if paused else "unknown"
    if playback == "unknown":
        return {
            "playback": playback,
            "recognized": False,
            "glyph_components": tuple(shapes),
        }

    identity_crop = image.crop(
        (
            round(width * 0.18),
            round(height * 0.86),
            round(width * 0.68),
            round(height * 0.91),
        )
    ).resize((33, 8))
    pixels = list(identity_crop.get_flattened_data())
    difference_bits = bytes(
        1 if pixels[row * 33 + column] > pixels[row * 33 + column + 1] else 0
        for row in range(8)
        for column in range(32)
    )
    return {
        "playback": playback,
        "recognized": True,
        "identity": sha256(difference_bits).hexdigest(),
        "glyph_components": tuple(shapes),
    }
