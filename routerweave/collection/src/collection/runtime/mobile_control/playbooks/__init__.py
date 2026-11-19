"""Reusable task-family playbooks composed from semantic actions."""

from .browsing import BrowsingTask, BrowsingVerification, build_browsing_playbook
from .live_stream import (
    LiveStreamPreparation,
    LiveStreamTask,
    LiveStreamVerification,
    build_live_stream_playbook,
)
from .lifecycle import build_lifecycle_binding, build_lifecycle_smoke
from .long_video import (
    LongVideoPreparation,
    LongVideoTask,
    LongVideoVerification,
    build_long_video_playbook,
)
from .music import MusicTask, MusicVerification, build_music_playbook
from .short_video import ShortVideoTask, ShortVideoVerification, build_short_video_playbook

__all__ = [
    "BrowsingTask",
    "BrowsingVerification",
    "LiveStreamTask",
    "LiveStreamPreparation",
    "LiveStreamVerification",
    "LongVideoTask",
    "LongVideoPreparation",
    "LongVideoVerification",
    "MusicTask",
    "MusicVerification",
    "ShortVideoTask",
    "ShortVideoVerification",
    "build_browsing_playbook",
    "build_lifecycle_binding",
    "build_lifecycle_smoke",
    "build_live_stream_playbook",
    "build_long_video_playbook",
    "build_music_playbook",
    "build_short_video_playbook",
]
