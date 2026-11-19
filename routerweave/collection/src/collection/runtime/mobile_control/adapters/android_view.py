"""Read-only resource evidence from Android's focused Activity view dump.

Unlike UIAutomator's command-line dump this does not wait for accessibility
events to become idle. It cannot supply accessibility text or tap targets.
"""

from __future__ import annotations

import re

from ..observation import ElementNode


_ACTIVITY = re.compile(r"^\s*ACTIVITY (\S+) .*?pid=(\d+)\b", re.MULTILINE)
_VIEW = re.compile(
    r"^(\s*)([\w.$]+)\{([0-9a-fA-F]+)\s+([VIG.][A-Z.]{8})\s+[A-Z.]{8}"
    r"\s+(-?\d+),(-?\d+)-(-?\d+),(-?\d+)([^}]*)\}"
)
_RESOURCE = re.compile(r"\s([\w.]+):id/([\w]+)\b")
_FRESCO_IMAGE_DIAGNOSTIC = re.compile(
    r"^\s*[A-Za-z_$][\w.$]*View\{holder=DraweeHolder\{.*\}\}\s*$"
)


def focused_activity_views(
    output: str,
    app_id: str,
    *, include_class_nodes: bool = False,
) -> tuple[ElementNode, ...]:
    """Reject stale activities, hidden ancestors, off-screen and partial trees."""

    headers = list(_ACTIVITY.finditer(output))
    candidates: list[str] = []
    for index, header in enumerate(headers):
        if not header.group(1).startswith(app_id + "/"):
            continue
        end = headers[index + 1].start() if index + 1 < len(headers) else len(output)
        section = output[header.end():end]
        prefix = section.split("View Hierarchy:", 1)[0]
        if (
            re.search(r"mResumed=true\s+mStopped=false\s+mFinished=false", prefix)
            and "mHasWindowFocus=true" in prefix
            and "mWindowVisibility=0" in prefix
        ):
            candidates.append(section)
    if len(candidates) != 1:
        raise ValueError("expected one resumed, focused target Activity")

    lines = candidates[0].splitlines()
    marker = next((i for i, line in enumerate(lines) if line.strip() == "View Hierarchy:"), None)
    if marker is None:
        raise ValueError("focused Activity has no view hierarchy")
    marker_indent = len(lines[marker]) - len(lines[marker].lstrip())
    # indent, effective visibility, absolute origin, clipped bounds
    stack: list[tuple[int, bool, int, int, tuple[int, int, int, int]]] = []
    nodes: list[ElementNode] = []
    node_count = 0
    terminated = False
    for line in lines[marker + 1:]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= marker_indent:
            terminated = True
            break
        match = _VIEW.match(line)
        if match is None:
            # Fresco-backed image and avatar views append a holder diagnostic
            # beneath the actual Android view row.  It is not a child view and
            # carries no bounds or resource identity, so it must not affect the
            # visibility stack.  Keep every other unexpected row fail-closed.
            if _FRESCO_IMAGE_DIAGNOSTIC.fullmatch(line):
                continue
            raise ValueError("unrecognized Activity view row")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1] if stack else None
        left, top, right, bottom = (int(match.group(i)) for i in range(5, 9))
        origin_x = parent[2] if parent else 0
        origin_y = parent[3] if parent else 0
        rect = (left + origin_x, top + origin_y, right + origin_x, bottom + origin_y)
        clip = (
            (max(rect[0], parent[4][0]), max(rect[1], parent[4][1]),
             min(rect[2], parent[4][2]), min(rect[3], parent[4][3]))
            if parent else rect
        )
        visible = (
            match.group(4)[0] == "V" and (parent is None or parent[1])
            and clip[2] > clip[0] and clip[3] > clip[1]
        )
        stack.append((indent, visible, rect[0], rect[1], clip))
        node_count += 1
        resource = _RESOURCE.search(match.group(9))
        if not visible or (not resource and not include_class_nodes):
            continue
        namespace = (app_id if resource.group(1) == "app" else resource.group(1)) if resource else ""
        nodes.append(ElementNode(
            "android-view:" + match.group(3),
            role=match.group(2).rsplit(".", 1)[-1].casefold(),
            resource_id=f"{namespace}:id/{resource.group(2)}" if resource else "",
            enabled=match.group(4)[2] == "E",
            attributes={"package": app_id, "class": match.group(2), "source": "focused_activity_view", "read_only": True},
            bounds=None,
        ))
    if not terminated or not node_count:
        raise ValueError("incomplete Activity view hierarchy")
    return tuple(nodes)
