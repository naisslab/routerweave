"""Semantic element selection without task-owned coordinates."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping

from .observation import ElementNode, Observation


def _normal(value: str) -> str:
    return " ".join(value.casefold().split())


@dataclass(frozen=True, slots=True)
class SemanticSelector:
    resource_ids: tuple[str, ...] = ()
    accessibility_ids: tuple[str, ...] = ()
    exact_texts: tuple[str, ...] = ()
    text_patterns: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)
    exclude_text_patterns: tuple[str, ...] = ()
    require_visible: bool = True
    require_enabled: bool = True
    require_clickable: bool = False
    minimum_score: int = 40
    ambiguity_margin: int = 10

    def validate(self) -> None:
        if not (
            self.resource_ids
            or self.accessibility_ids
            or self.exact_texts
            or self.text_patterns
            or self.roles
            or self.attributes
        ):
            raise ValueError("semantic selector must contain semantic criteria")
        if self.minimum_score < 0 or self.ambiguity_margin < 0:
            raise ValueError("selector scores cannot be negative")
        for pattern in (*self.text_patterns, *self.exclude_text_patterns):
            re.compile(pattern)


@dataclass(frozen=True, slots=True)
class Candidate:
    element: ElementNode
    score: int
    evidence: tuple[str, ...]


class FindStatus(StrEnum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class FindResult:
    status: FindStatus
    selected: ElementNode | None = None
    candidates: tuple[Candidate, ...] = ()
    detail: str = ""


class ElementFinder:
    """Ranks semantic evidence and refuses unsafe ambiguous matches."""

    def find(self, observation: Observation, selector: SemanticSelector) -> FindResult:
        selector.validate()
        candidates = tuple(
            sorted(
                filter(None, (self._score(node, selector) for node in observation.elements)),
                key=lambda item: (-item.score, item.element.handle),
            )
        )
        if not candidates:
            return FindResult(FindStatus.NOT_FOUND, detail="no semantic candidate matched")

        top = candidates[0]
        if len(candidates) > 1 and top.score - candidates[1].score < selector.ambiguity_margin:
            return FindResult(
                FindStatus.AMBIGUOUS,
                candidates=candidates,
                detail=f"top candidates differ by less than {selector.ambiguity_margin}",
            )
        return FindResult(FindStatus.FOUND, top.element, candidates, "semantic target resolved")

    def _score(self, node: ElementNode, selector: SemanticSelector) -> Candidate | None:
        if selector.require_visible and not node.visible:
            return None
        if selector.require_enabled and not node.enabled:
            return None
        if selector.require_clickable and not node.clickable:
            return None

        node_text = _normal(node.semantic_text)
        if any(re.search(pattern, node_text, re.IGNORECASE) for pattern in selector.exclude_text_patterns):
            return None
        if selector.roles and _normal(node.role) not in {_normal(role) for role in selector.roles}:
            return None
        for name, expected in selector.attributes.items():
            if node.attributes.get(name) != expected:
                return None

        evidence: list[str] = []
        score = 0
        identity_groups = 0
        identity_matches = 0

        if selector.resource_ids:
            identity_groups += 1
            if node.resource_id in selector.resource_ids:
                score += 120
                identity_matches += 1
                evidence.append(f"resource_id={node.resource_id}")
        if selector.accessibility_ids:
            identity_groups += 1
            if node.accessibility_id in selector.accessibility_ids:
                score += 110
                identity_matches += 1
                evidence.append(f"accessibility_id={node.accessibility_id}")
        if selector.exact_texts:
            identity_groups += 1
            exact = {_normal(text) for text in selector.exact_texts}
            if node_text in exact:
                score += 80
                identity_matches += 1
                evidence.append(f"text={node.semantic_text!r}")
        if selector.text_patterns:
            identity_groups += 1
            matching = [
                pattern
                for pattern in selector.text_patterns
                if re.search(pattern, node.semantic_text, re.IGNORECASE)
            ]
            if matching:
                score += 55
                identity_matches += 1
                evidence.append(f"text_pattern={matching[0]!r}")

        # Identity fields are aliases across app/platform versions. At least one
        # must match, while role and attributes are mandatory refinements.
        if identity_groups and not identity_matches:
            return None
        if selector.roles:
            score += 20
            evidence.append(f"role={node.role}")
        if selector.attributes:
            score += 25 * len(selector.attributes)
            evidence.extend(f"attribute:{name}={value!r}" for name, value in selector.attributes.items())

        if score < selector.minimum_score:
            return None
        return Candidate(node, score, tuple(evidence))


@dataclass(frozen=True, slots=True)
class PageDefinition:
    required: tuple[str, ...] = ()
    any_of: tuple[str, ...] = ()
    forbidden: tuple[str, ...] = ()

    def validate(self) -> None:
        if not (self.required or self.any_of):
            raise ValueError("page definition requires positive required or any_of evidence")


@dataclass(frozen=True, slots=True)
class PageResult:
    matched: bool
    detail: str
    evidence: Mapping[str, FindStatus] = field(default_factory=dict)


class PageRecognizer:
    def __init__(self, finder: ElementFinder | None = None) -> None:
        self._finder = finder or ElementFinder()

    def recognize(
        self,
        observation: Observation,
        page: PageDefinition,
        selectors: Mapping[str, SemanticSelector],
    ) -> PageResult:
        page.validate()
        keys = (*page.required, *page.any_of, *page.forbidden)
        missing = [key for key in keys if key not in selectors]
        if missing:
            return PageResult(False, f"page references unknown selectors: {missing}")
        results = {key: self._finder.find(observation, selectors[key]).status for key in keys}
        required_ok = all(results[key] is FindStatus.FOUND for key in page.required)
        any_ok = not page.any_of or any(results[key] is FindStatus.FOUND for key in page.any_of)
        forbidden_ok = all(results[key] is FindStatus.NOT_FOUND for key in page.forbidden)
        matched = required_ok and any_ok and forbidden_ok
        return PageResult(matched, "page matched" if matched else "page conditions not met", results)
