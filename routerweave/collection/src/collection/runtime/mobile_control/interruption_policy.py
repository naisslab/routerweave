"""Conservative cross-app popup classification derived from the old runtime."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from .interruption import InterruptionKind
from .observation import ElementNode, Observation


class GatekeeperAction(StrEnum):
    NONE = "none"
    RESOLVE = "resolve"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class GatekeeperDecision:
    action: GatekeeperAction
    rule_id: str
    kind: InterruptionKind
    detail: str
    target: ElementNode | None = None


_DENY_TEXTS = ("不允许", "禁止", "拒绝", "暂不允许", "取消", "Don’t Allow", "Don't Allow")
_ALLOW_TEXTS = ("仅在使用中允许", "使用 App 时允许", "允许", "同意", "Allow")
_PRIVACY_KEYWORDS = ("隐私政策", "隐私权政策", "用户协议", "服务协议", "法律声明", "条款")
_LOGIN_KEYWORDS = ("登录", "验证码", "账号密码", "手机号", "Sign In", "Log In")
_LOGIN_ACTION_TEXTS = ("登录", "重新登录", "立即登录", "Sign In", "Log In")
_CAPTCHA_KEYWORDS = ("安全验证", "拖动滑块", "人机验证", "图形验证码", "CAPTCHA")
_PAYMENT_KEYWORDS = ("支付", "付款", "确认付款", "确认支付", "免密支付", "开通免密", "Pay Now")
_PAYMENT_ACTION_TEXTS = (
    "支付",
    "付款",
    "立即支付",
    "确认付款",
    "确认支付",
    "Pay Now",
)
_SKIP_LOGIN_TEXTS = (
    "暂不登录",
    "跳过",
    "以后再说",
    "稍后再说",
    "关闭",
    "返回",
    "取消",
    "Not Now",
    "Skip",
    "Later",
    "Cancel",
)
_POPUP_CLOSE_TEXTS = (
    "关闭",
    "跳过",
    "以后再说",
    "稍后再说",
    "知道了",
    "我知道了",
    "取消",
    "Close",
    "Skip",
    "Not Now",
    "Got It",
    "Cancel",
)
_PROMO_KEYWORDS = ("领取", "红包", "礼包", "优惠", "会员", "限时", "promotion", "reward")
_UPDATE_KEYWORDS = (
    "发现新版本",
    "版本更新",
    "立即安装",
    "立即更新",
    "update available",
    "install now",
    "update now",
)
_UPDATE_LATER_TEXTS = (
    "以后再说",
    "稍后再说",
    "暂不更新",
    "取消",
    "Later",
    "Not Now",
    "Cancel",
)
_BLOCKING_ROLES = {"alert", "dialog", "sheet", "popover"}
_BLOCKING_ID_HINTS = ("alert", "dialog", "modal", "popup", "splash")
_SYSTEM_DIALOG_PACKAGES = {
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.systemui",
}


def is_blocking_surface(node: ElementNode) -> bool:
    """Recognize modal/system surfaces without treating every app window as a popup."""

    if not node.visible:
        return False
    if node.role.casefold() in _BLOCKING_ROLES:
        return True
    if str(node.attributes.get("package") or "") in _SYSTEM_DIALOG_PACKAGES:
        return True
    identity = " ".join(
        part.casefold()
        for part in (node.resource_id, node.accessibility_id)
        if part
    )
    matched_hints = tuple(hint for hint in _BLOCKING_ID_HINTS if hint in identity)
    if not matched_hints:
        return False
    if "splash" in matched_hints:
        return True
    descendant_text = str(node.attributes.get("descendant_text") or "").strip()
    return bool(node.semantic_text.strip() or descendant_text or node.clickable)


class ConservativeGatekeeperPolicy:
    """Resolve only explicit low-risk exits; block consequential surfaces."""

    def __init__(self, *, nonblocking_login_banner: Mapping[str, str] | None = None,
                 inline_containers: Mapping[str, object] | None = None) -> None:
        self._nonblocking_login_banner = dict(nonblocking_login_banner or {})
        self._inline_containers = dict(inline_containers or {})

    def blocking_surfaces(self, observation: Observation) -> tuple[ElementNode, ...]:
        """Exempt registered inline containers and messages on their player page.

        Descendants remain independently classified, including real dialogs and
        authentication/payment controls inside an otherwise inline container.
        """
        spec = self._inline_containers
        package = str(spec.get("package") or "")
        activity = str(observation.state.get("device", {}).get("foreground_activity_class") or "")
        resources = spec.get("resource_ids") or ()
        text_resources = spec.get("text_resource_ids") or ()
        page_context = bool(
            not observation.errors and package and observation.app_id == package
            and observation.state.get("device", {}).get("foreground_app") == package
            and activity == spec.get("activity_class")
        )
        context = page_context and any(
            n.visible and n.enabled and n.resource_id == spec.get("marker_resource_id")
            and n.attributes.get("package") == package for n in observation.elements)
        return tuple(n for n in observation.elements if n.enabled and is_blocking_surface(n) and not (
            page_context and n.attributes.get("package") == package and (
                (context and n.resource_id in resources
                 and n.role.casefold() == "framelayout" and not n.clickable
                 and not n.semantic_text.strip() and not n.accessibility_id.strip())
                or (n.resource_id in text_resources and n.role.casefold() == "textview"
                    and not n.accessibility_id.strip())
            )
        ))

    def decide(self, observation: Observation) -> GatekeeperDecision:
        visible = tuple(node for node in observation.elements if node.visible and node.enabled)
        text = "\n".join(self._node_text(node) for node in visible)
        blocker_surface = bool(self.blocking_surfaces(observation))

        payment_action = self._find_exact(visible, _PAYMENT_ACTION_TEXTS)
        if self._contains(text, _PAYMENT_KEYWORDS) and (
            blocker_surface or payment_action is not None
        ):
            return self._block("payment-surface", InterruptionKind.PAYMENT, "payment surface detected")
        if self._contains(text, _CAPTCHA_KEYWORDS):
            return self._block(
                "captcha-surface",
                InterruptionKind.CAPTCHA,
                "captcha or security verification detected",
            )

        deny = self._find_exact(visible, _DENY_TEXTS)
        allow = self._find_exact(visible, _ALLOW_TEXTS)
        if deny is not None and allow is not None:
            return GatekeeperDecision(
                GatekeeperAction.RESOLVE,
                "permission-deny",
                InterruptionKind.PERMISSION,
                "permission request denied by conservative default policy",
                deny,
            )

        agree = self._find_exact(visible, ("同意", "我同意", "同意并继续", "Agree"))
        if self._contains(text, _PRIVACY_KEYWORDS) and agree is not None:
            return self._block(
                "privacy-terms",
                InterruptionKind.UNKNOWN,
                "privacy terms require explicit operator policy",
            )

        if "未成年人模式" in text:
            acknowledge = self._find_exact(visible, ("我知道了", "知道了", "Got It"))
            if acknowledge is not None:
                return GatekeeperDecision(
                    GatekeeperAction.RESOLVE,
                    "minor-mode-acknowledge",
                    InterruptionKind.BENIGN,
                    "minor-mode notice acknowledged",
                    acknowledge,
                )

        update_later = self._find_exact(visible, _UPDATE_LATER_TEXTS)
        if self._contains(text, _UPDATE_KEYWORDS) and update_later is not None:
            return GatekeeperDecision(
                GatekeeperAction.RESOLVE,
                "update-later",
                InterruptionKind.BENIGN,
                "application update deferred through an explicit safe exit",
                update_later,
            )

        if blocker_surface and self._contains(text, _LOGIN_KEYWORDS):
            skip = self._find_exact(visible, _SKIP_LOGIN_TEXTS)
            if skip is not None:
                return GatekeeperDecision(
                    GatekeeperAction.RESOLVE,
                    "login-skip",
                    InterruptionKind.BENIGN,
                    "login overlay skipped through an explicit non-authentication exit",
                    skip,
                )
            return self._block(
                "login-required",
                InterruptionKind.AUTHENTICATION,
                "login surface has no safe skip action",
            )

        # Some apps render authentication takeover notices as ordinary views
        # instead of accessibility alerts. An explicit login action plus login
        # wording is still consequential and must never be auto-activated.
        login_action = self._find_exact(visible, _LOGIN_ACTION_TEXTS)
        banner = self._nonblocking_login_banner
        inline_login = bool(
            not blocker_surface
            and login_action is not None
            and banner.get("action_resource_id") == login_action.resource_id
            and banner.get("context_resource_id")
            and banner.get("context_text")
            and any(node.resource_id == banner["context_resource_id"]
                    and node.text == banner["context_text"] for node in visible)
        )
        if login_action is not None and not inline_login and self._contains(text, _LOGIN_KEYWORDS):
            return self._block(
                "login-required",
                InterruptionKind.AUTHENTICATION,
                "authentication takeover has no safe skip action",
            )

        if self._contains(text, _PROMO_KEYWORDS):
            close = self._find_exact(visible, _POPUP_CLOSE_TEXTS)
            if close is not None:
                return GatekeeperDecision(
                    GatekeeperAction.RESOLVE,
                    "promotion-close",
                    InterruptionKind.BENIGN,
                    "promotion overlay closed",
                    close,
                )

        if blocker_surface:
            close = self._find_exact(visible, _POPUP_CLOSE_TEXTS)
            if close is not None:
                return GatekeeperDecision(
                    GatekeeperAction.RESOLVE,
                    "blocking-surface-safe-exit",
                    InterruptionKind.BENIGN,
                    "blocking surface closed through an explicit low-risk exit",
                    close,
                )

        if blocker_surface:
            return self._block(
                "unclassified-blocking-ui",
                InterruptionKind.UNKNOWN,
                "unclassified alert or system dialog blocks the task",
            )
        return GatekeeperDecision(
            GatekeeperAction.NONE,
            "no-gatekeeper",
            InterruptionKind.BENIGN,
            "no blocking UI detected",
        )
    @staticmethod
    def _node_text(node: ElementNode) -> str:
        return " ".join(
            part
            for part in (
                node.semantic_text,
                node.accessibility_id,
                node.resource_id,
            )
            if part
        )

    @classmethod
    def _find_exact(
        cls,
        nodes: tuple[ElementNode, ...],
        candidates: tuple[str, ...],
    ) -> ElementNode | None:
        normalized = {cls._normal(candidate) for candidate in candidates}
        matches = [
            node
            for node in nodes
            if node.clickable
            and cls._normal(node.semantic_text or node.accessibility_id) in normalized
        ]
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _contains(text: str, candidates: tuple[str, ...]) -> bool:
        folded = text.casefold()
        return any(candidate.casefold() in folded for candidate in candidates)

    @staticmethod
    def _normal(text: str) -> str:
        return " ".join(text.casefold().split())

    @staticmethod
    def _block(
        rule_id: str,
        kind: InterruptionKind,
        detail: str,
    ) -> GatekeeperDecision:
        return GatekeeperDecision(GatekeeperAction.BLOCK, rule_id, kind, detail)
