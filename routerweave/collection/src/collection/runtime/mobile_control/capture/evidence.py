from pathlib import Path
from typing import Any, Protocol
from collection_core.evidence import PlatformEvidenceResult


class PlatformEvidence(Protocol):
    def prepare(self) -> None: ...

    def start(self) -> None: ...

    def stop(self) -> PlatformEvidenceResult: ...

    def finalize(
        self,
        *,
        capture_path: Path,
        network_windows: list[dict[str, Any]],
        phone_ip: str,
    ) -> PlatformEvidenceResult: ...
