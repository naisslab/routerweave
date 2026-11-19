"""Privacy-preserving browser media playback evidence over local Edge CDP."""

from __future__ import annotations

import json
import math
import threading
import time
import urllib.request
import urllib.error
from contextlib import contextmanager
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any

from .connection_state import (
    EdgeCommandTimeout, _BROWSER_CONNECTIONS, _RETAINED_CONNECTIONS, _SESSION_ENDPOINTS,
)


MEDIA_STATE_EXPRESSION = r"""
(() => Array.from(document.querySelectorAll('audio,video')).map((element, index) => ({
  key: `${element.tagName.toLowerCase()}:${index}`,
  kind: element.tagName.toLowerCase(),
  current_time: Number(element.currentTime || 0),
  paused: Boolean(element.paused),
  ended: Boolean(element.ended),
  muted: Boolean(element.muted),
  volume: Number(element.volume || 0),
  ready_state: Number(element.readyState || 0)
})))()
"""


def _read_json_url(url: str, timeout_seconds: float) -> Any:
    with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


class _BrowserCdp:
    """One operator-approved browser connection for a collection lifecycle."""

    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.connection = None
        self.sessions = {}
        self.sequence = 0
        self.failed = False
        self.ever_connected = False
        self.reconnect_attempts = 0
        self.lock = threading.RLock()

    def close(self):
        with self.lock:
            if self.connection is not None:
                self.connection.close()
            self.connection = None
            self.sessions.clear()

    def _exchange(self, method, params, timeout, session_id=None):
        import websocket

        self.sequence += 1
        message_id = self.sequence
        try:
            self.connection.settimeout(timeout)
            self.connection.send(json.dumps({"id": message_id, "method": method, "params": params,
                                            **({"sessionId": session_id} if session_id else {})}))
        except Exception:
            self.failed = True
            self.close()
            raise
        try:
            deadline = time.monotonic() + timeout
            response = None
            while time.monotonic() < deadline:
                self.connection.settimeout(max(0.01, deadline - time.monotonic()))
                response = json.loads(self.connection.recv())
                if response.get("method") == "Target.detachedFromTarget":
                    detached = response.get("params", {}).get("sessionId")
                    self.sessions = {key: value for key, value in self.sessions.items() if value != detached}
                if response.get("id") == message_id:
                    break
            else:
                raise EdgeCommandTimeout(f"Edge command {method} timed out; reply discarded")
        except EdgeCommandTimeout:
            self._retain_after_timeout()
            raise
        except (websocket.WebSocketTimeoutException, TimeoutError):
            self._retain_after_timeout()
            raise EdgeCommandTimeout(f"Edge command {method} timed out; reply discarded") from None
        except Exception:
            self.failed = True
            self.close()
            raise
        if response.get("error"):
            raise RuntimeError(str(response["error"].get("message", "Edge browser command failed")))
        return response.get("result", {})

    def _retain_after_timeout(self) -> None:
        """Keep the connection only while the browser still answers a probe."""

        if not self._probe_liveness():
            self.failed = True
            self.close()

    def _probe_liveness(self, timeout: float = 5.0) -> bool:
        """Confirm a timed-out socket still returns well-framed browser replies."""

        import websocket

        try:
            self.sequence += 1
            message_id = self.sequence
            self.connection.settimeout(timeout)
            self.connection.send(json.dumps({"id": message_id, "method": "Browser.getVersion",
                                             "params": {}}))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                self.connection.settimeout(max(0.01, deadline - time.monotonic()))
                try:
                    response = json.loads(self.connection.recv())
                except websocket.WebSocketTimeoutException:
                    return False
                if response.get("method") == "Target.detachedFromTarget":
                    detached = response.get("params", {}).get("sessionId")
                    self.sessions = {key: value for key, value in self.sessions.items() if value != detached}
                if response.get("id") == message_id:
                    return "result" in response
            return False
        except Exception:
            return False

    def command(self, method, params, timeout, *, target_id=None, before_send=None):
        import websocket
        with self.lock:
            if self.failed:
                raise RuntimeError("Edge debugger connection was lost; start a new explicit attachment")
            if before_send is not None:
                before_send()
            if self.connection is None:
                try:
                    self.connection = websocket.create_connection(self.endpoint, timeout=timeout, suppress_origin=True)
                    self.ever_connected = True
                except Exception:
                    self.failed = True
                    raise
            if target_id and target_id not in self.sessions:
                attached = self._exchange("Target.attachToTarget", {"targetId": target_id, "flatten": True}, timeout)
                if not attached.get("sessionId"):
                    raise RuntimeError("Edge target attachment failed")
                self.sessions[target_id] = attached["sessionId"]
            if before_send is not None:
                before_send()
            return self._exchange(method, params, timeout, self.sessions.get(target_id))

    def reconnect(self, timeout=15):
        """One explicit recovery attempt; never replay an uncertain input."""
        with self.lock:
            if not self.failed and self.connection is not None:
                return
            if not self.ever_connected or self.reconnect_attempts >= 1:
                raise RuntimeError("Edge reconnect unavailable: initial approval or recovery budget exhausted")
            self.reconnect_attempts += 1
            self.close()
            self.failed = False
            try:
                self.command("Browser.getVersion", {}, timeout)
            except Exception:
                self.failed = True
                self.close()
                raise


def _browser_connection(endpoint: str) -> _BrowserCdp:
    return _BROWSER_CONNECTIONS.setdefault(endpoint, _BrowserCdp(endpoint))


def _browser_endpoint(profile_dir: Path, port: int | None = None) -> str:
    lines = (profile_dir / "DevToolsActivePort").read_text(encoding="utf-8").splitlines()
    recorded = int(lines[0])
    if not 0 < recorded < 65536 or (port is not None and recorded != port) or \
            len(lines) < 2 or not lines[1].startswith("/devtools/browser/"):
        raise RuntimeError("Invalid Edge browser endpoint")
    return f"ws://127.0.0.1:{recorded}{lines[1]}"


def close_edge_connection(profile_dir: Path) -> None:
    """Release the debugger connection without closing the operator browser."""
    try:
        endpoint = _browser_endpoint(profile_dir)
        if _RETAINED_CONNECTIONS.get(endpoint, 0):
            return
        channel = _BROWSER_CONNECTIONS.pop(endpoint, None)
    except (OSError, ValueError, IndexError, RuntimeError):
        return
    if channel is not None:
        channel.close()


def reconnect_edge_connection(profile_dir: Path, timeout_seconds: float = 15) -> None:
    """Reconnect only the pinned browser instance, on an explicit session command."""
    endpoint = _browser_endpoint(profile_dir)
    if _SESSION_ENDPOINTS.get(profile_dir.resolve()) != endpoint:
        raise RuntimeError("Browser instance changed; a new authorized session is required")
    channel = _BROWSER_CONNECTIONS.get(endpoint)
    if channel is None:
        raise RuntimeError("No previously authorized connection to recover")
    channel.reconnect(timeout_seconds)


@contextmanager
def retained_edge_connection(profile_dir: Path):
    """Let one explicit test session own cleanup across sequential captures."""
    endpoint = _browser_endpoint(profile_dir)
    profile_key = profile_dir.resolve()
    pinned = _SESSION_ENDPOINTS.get(profile_key)
    if pinned is not None and pinned != endpoint:
        raise RuntimeError("Edge endpoint changed; end this test session before approving a new one")
    _SESSION_ENDPOINTS[profile_key] = endpoint
    _RETAINED_CONNECTIONS[endpoint] = _RETAINED_CONNECTIONS.get(endpoint, 0) + 1
    try:
        yield
    finally:
        remaining = _RETAINED_CONNECTIONS[endpoint] - 1
        if remaining:
            _RETAINED_CONNECTIONS[endpoint] = remaining
        else:
            del _RETAINED_CONNECTIONS[endpoint]
            del _SESSION_ENDPOINTS[profile_key]
            # Use the original endpoint even if Edge replaced its port file.
            channel = _BROWSER_CONNECTIONS.pop(endpoint, None)
            if channel is not None:
                channel.close()


def wait_for_devtools_port(profile_dir: Path, timeout_seconds: float = 10.0) -> int:
    path = profile_dir / "DevToolsActivePort"
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            pinned = _SESSION_ENDPOINTS.get(profile_dir.resolve())
            if pinned is not None and _browser_endpoint(profile_dir) != pinned:
                raise RuntimeError("Edge endpoint changed; this session will not reconnect automatically")
            first_line = path.read_text(encoding="utf-8").splitlines()[0]
            port = int(first_line)
            if port > 0:
                version = _read_json_url(f"http://127.0.0.1:{port}/json/version", 0.25)
                if isinstance(version, dict) and version.get("webSocketDebuggerUrl"):
                    return port
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # Edge's operator-enabled debugger has a browser socket but no
                # HTTP discovery. Attempt it once; do not repeatedly prompt
                # the operator or silently start another browser on failure.
                try:
                    _page_targets(port, max(0.1, deadline - time.monotonic()), profile_dir)
                    return port
                except Exception as socket_error:
                    raise RuntimeError(
                        "Existing Edge debugger did not accept the connection; "
                        "check its remote-debugging status and any connection approval. "
                        "No replacement browser was started."
                    ) from socket_error
        except (OSError, ValueError, IndexError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise TimeoutError(f"Edge DevToolsActivePort was not ready under {profile_dir}")


def _page_targets(port: int, timeout_seconds: float, profile_dir: Path | None = None) -> list[dict[str, Any]]:
    endpoint = None
    if profile_dir is not None:
        pinned = _SESSION_ENDPOINTS.get(profile_dir.resolve())
        if pinned is not None:
            endpoint = _browser_endpoint(profile_dir, port)
            if endpoint != pinned:
                raise RuntimeError("Edge endpoint changed; this session will not reconnect automatically")
    try:
        return _read_json_url(f"http://127.0.0.1:{port}/json/list", timeout_seconds)
    except urllib.error.HTTPError as exc:
        if exc.code != 404 or profile_dir is None:
            raise
    # Operator-enabled Edge exposes the browser socket without HTTP discovery.
    endpoint = endpoint or _browser_endpoint(profile_dir, port)
    result = _browser_connection(endpoint).command("Target.getTargets", {}, timeout_seconds)
    return [{**row, "id": row["targetId"], "webSocketDebuggerUrl": endpoint + "#" + row["targetId"]}
            for row in result.get("targetInfos", [])]


def _active_page_websocket(port: int, timeout_seconds: float, profile_dir: Path | None = None,
                           *, target_id: str | None = None) -> str:
    return str(_active_page_target(port, timeout_seconds, profile_dir, target_id=target_id)["webSocketDebuggerUrl"])


def verify_existing_edge_target(profile_dir: Path, target_url: str, *,
                                target_id: str | None = None,
                                timeout_seconds: float = 3,
                                require_single_page: bool = False,
                                expected_hosts: list[str] | None = None) -> dict[str, Any]:
    """Select a same-host tab in the existing browser, without changing its state."""
    expected = urlsplit(target_url)
    if expected.scheme not in {"http", "https"} or not expected.hostname:
        raise ValueError("Existing Edge requires one HTTP(S) target URL")
    hosts = set(expected_hosts or [expected.hostname])
    if expected.hostname not in hosts or any(
            not isinstance(host, str) or urlsplit("https://" + host).hostname != host
            or "/" in host or "*" in host for host in hosts):
        raise ValueError("Expected hosts must be explicit hostnames including the entry host")
    if expected_hosts and not target_id:
        raise ValueError("Content-host navigation requires a pinned target ID")
    port = wait_for_devtools_port(profile_dir, timeout_seconds)
    # Target.getTargets can briefly omit a pinned page during a renderer swap.
    # Recheck that *same ID* on the retained connection; never pick another tab
    # or reconnect the browser to make an uncertain observation look successful.
    deadline = time.monotonic() + min(2.0, max(0.0, timeout_seconds))
    while True:
        rows = _page_targets(port, timeout_seconds, profile_dir)
        if require_single_page:
            web_pages = [row for row in rows if row.get("type") == "page"
                         and urlsplit(str(row.get("url", ""))).scheme in {"http", "https"}]
            if len(web_pages) != 1:
                raise RuntimeError("Single-app capture requires exactly one web page in the collection browser")
        pages = [row for row in rows if row.get("type") == "page"
                 and urlsplit(str(row.get("url", ""))).scheme in {"http", "https"}
                 and urlsplit(str(row.get("url", ""))).hostname in hosts
                 and (not target_id or row.get("id") == target_id)]
        if len(pages) == 1:
            if not pages[0].get("id") or not pages[0].get("webSocketDebuggerUrl"):
                raise RuntimeError("Existing Edge target has no debuggable identity")
            return pages[0]
        pinned_row = next((row for row in rows if target_id and row.get("id") == target_id), None)
        if pinned_row is not None and urlsplit(str(pinned_row.get("url", ""))).hostname not in hosts | {None}:
            raise RuntimeError("Pinned Edge tab left the expected host")
        if not target_id or len(pages) > 1 or time.monotonic() >= deadline:
            raise RuntimeError("Existing Edge target tab is missing or ambiguous; select its CDP tab ID explicitly")
        time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))


def _active_page_target(port: int, timeout_seconds: float, profile_dir: Path | None = None,
                        *, target_id: str | None = None) -> dict[str, Any]:
    targets = _page_targets(port, timeout_seconds, profile_dir)
    if target_id:
        targets = [target for target in targets if target.get("id") == target_id]
        if len(targets) != 1:
            raise RuntimeError("Pinned Edge tab is no longer available")
    pages = [
        target
        for target in targets
        if target.get("type") == "page"
        and urlsplit(str(target.get("url", ""))).scheme in {"http", "https"}
        and target.get("webSocketDebuggerUrl")
    ]
    if not pages:
        pages = [target for target in targets if target.get("type") == "page" and target.get("webSocketDebuggerUrl")]
    if not pages:
        raise RuntimeError("No debuggable Edge page target is available")
    return pages[-1]


def probe_edge_page_identity(
    profile_dir: Path, expected_hosts: list[str], *, timeout_seconds: float = 10.0,
    target_id: str | None = None,
) -> dict[str, Any]:
    """Verify a controlled target host without exporting its URL or page text."""

    base = {"schema_version": "windows-page-identity-v1", "content_redacted": True}
    try:
        port = wait_for_devtools_port(profile_dir, timeout_seconds)
        target = _active_page_target(port, timeout_seconds, profile_dir, target_id=target_id)
        observed_host = (urlsplit(str(target.get("url") or "")).hostname or "").lower()
        hosts = {host.lower() for host in expected_hosts}
        return {**base, "ok": bool(observed_host) and observed_host in hosts,
                "evidence": "expected_host_match" if observed_host in hosts else "host_mismatch"}
    except Exception as exc:
        return {**base, "ok": False, "evidence": "page_identity_unavailable", "error_type": type(exc).__name__}


def _evaluate(websocket_url: str, expression: str, timeout_seconds: float, *, before_send=None) -> list[dict[str, Any]]:
    try:
        import websocket
    except ImportError as exc:  # pragma: no cover - depends on operator environment
        raise RuntimeError("websocket-client is required for the Windows media probe") from exc
    endpoint, separator, target_id = websocket_url.partition("#")
    if separator:
        result = _browser_connection(endpoint).command("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": True,
        }, timeout_seconds, target_id=target_id, before_send=before_send).get("result", {})
        if result.get("subtype") == "error":
            raise RuntimeError(str(result.get("description", "media expression failed")))
        value = result.get("value", [])
        return value if isinstance(value, list) else []
    connection = websocket.create_connection(
        endpoint,
        timeout=timeout_seconds,
        origin="http://127.0.0.1",
    )
    try:
        if before_send is not None:
            before_send()
        connection.send(
            json.dumps(
                {
                    "id": 1,
                    "method": "Runtime.evaluate",
                    "params": {"expression": expression, "returnByValue": True, "awaitPromise": True},
                }
            )
        )
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            response = json.loads(connection.recv())
            if response.get("id") != 1:
                continue
            if response.get("error"):
                raise RuntimeError(str(response["error"].get("message", "CDP Runtime.evaluate failed")))
            result = response.get("result", {}).get("result", {})
            if result.get("subtype") == "error":
                raise RuntimeError(str(result.get("description", "media expression failed")))
            value = result.get("value", [])
            return value if isinstance(value, list) else []
        raise TimeoutError("Timed out waiting for Edge Runtime.evaluate")
    finally:
        connection.close()


# Only DOM facts needed for postconditions leave the page. No URL, title,
# message, cookie or page text is written to the behavior log.
def interruption_rules(spec):
    """One bounded rule vocabulary for notices and skippable advertisements."""
    rules = [*spec.get("benign_popups", []), *spec.get("advertisements", [])]
    # Exact accessible labels only. Arbitrary close/X buttons are never candidates.
    rules.append({"id": "standard-labelled-advertisement", "kind": "advertisement",
                  "marker_selector": '[role="dialog"][aria-label="广告"], [role="dialog"][aria-label="Advertisement"]',
                  "dismiss_selector": '[role="dialog"][aria-label="广告"] button[aria-label="关闭"], '
                                      '[role="dialog"][aria-label="Advertisement"] button[aria-label="Close"]',
                  "max_occurrences": 2, "timeout_seconds": 4})
    seen = set()
    for rule in rules:
        key = rule.get("id")
        if not key or key in seen or not rule.get("marker_selector") or not rule.get("dismiss_selector"):
            raise ValueError("interruption rules require unique IDs and explicit marker/dismiss selectors")
        if rule.get("kind", "benign") not in {"benign", "advertisement"}:
            raise ValueError("only benign notices and advertisements may be dismissed automatically")
        if not 1 <= int(rule.get("max_occurrences", 1)) <= 3:
            raise ValueError("interruption occurrence budget must be between one and three")
        if not 0 < float(rule.get("timeout_seconds", 4)) <= 10:
            raise ValueError("interruption verification timeout must be at most ten seconds")
        seen.add(key)
    return rules


BEHAVIOR_STATE_EXPRESSION = r"""
(() => {
  const spec = __WINDOWS_BINDING__;
  const visible = e => {
    if (!e.getClientRects().length || getComputedStyle(e).visibility === 'hidden') return false;
    const r = e.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && r.bottom > 0 && r.top < innerHeight &&
      r.right > 0 && r.left < innerWidth;
  };
  const compact = value => String(value || '').replace(/\s+/g, '').trim();
  const nonblocking = spec.nonblocking_dialog_selectors || [];
  const presentPopups = (spec.benign_popups || []).filter(p => {
    return Array.from(document.querySelectorAll(p.marker_selector)).some(visible);
  }).map(p => p.id);
  const benignPopups = (spec.benign_popups || []).filter(p => {
    const markers = Array.from(document.querySelectorAll(p.marker_selector)).filter(visible);
    const dismiss = Array.from(document.querySelectorAll(p.dismiss_selector)).filter(visible);
    return markers.length === 1 && dismiss.length === 1 && !dismiss[0].disabled &&
      dismiss[0].getAttribute('aria-disabled') !== 'true' &&
      (!p.marker_text_contains || compact(markers[0].innerText).includes(compact(p.marker_text_contains))) &&
      (!p.dismiss_text || compact(dismiss[0].innerText) === compact(p.dismiss_text));
  }).map(p => p.id);
  const benignDialogs = (spec.benign_popups || []).filter(p => benignPopups.includes(p.id))
    .map(p => p.marker_selector);
  const sensitive = Array.from(document.querySelectorAll(
    'input[type="password"], iframe[src*="captcha"], iframe[src*="recaptcha"], [id*="captcha"], [class*="captcha"]'
  )).some(visible) || Array.from(document.querySelectorAll('[role="dialog"], [aria-modal="true"]'))
    .some(e => visible(e) && /验证码|密码|支付|隐私协议|用户协议|登录|sign\s*in|log\s*in|captcha|password|payment|permission|terms of service/i.test(e.innerText || ''));
  const explicitBlockers = (spec.blocker_selectors || []).filter(selector =>
    Array.from(document.querySelectorAll(selector)).some(visible));
  const blocked = sensitive || explicitBlockers.length > 0 || Array.from(document.querySelectorAll(
    '[role="dialog"], [aria-modal="true"], input[type="password"]'
  )).some(e => visible(e) && (e.matches('input[type="password"]') ||
    ![...nonblocking, ...benignDialogs].some(selector => e.matches(selector))));
  const pausedMarkers = spec.paused_marker_selector ?
    Array.from(document.querySelectorAll(spec.paused_marker_selector)).filter(visible) : [];
  const verifiedPausedUi = pausedMarkers.length === 1;
  const candidates = Array.from(document.querySelectorAll(spec.media_selector || 'video,audio'))
    .filter(e => (e.readyState >= 2 ||
      (verifiedPausedUi && e.paused && e.readyState >= 1)) &&
      (e.tagName === 'AUDIO' || visible(e)));
  const playingMedia = candidates.filter(e => !e.paused && !e.ended);
  const media = playingMedia.length ? playingMedia : candidates;
  const area = e => { const r = e.getBoundingClientRect(); return r.width * r.height; };
  media.sort((a, b) => area(b) - area(a));
  const largest = media[0] ? area(media[0]) : 0;
  const second = media[1] ? area(media[1]) : 0;
  const m = media.length === 1 || (largest > 0 && largest >= second * 1.5) ? media[0] : null;
  const ui = spec.media_ui || {};
  const one = selector => selector ? Array.from(document.querySelectorAll(selector)).filter(visible) : [];
  const clocks = one(ui.clock_selector), positions = one(ui.position_selector);
  const durations = one(ui.duration_selector), controls = one(ui.control_selector);
  const identities = one(ui.identity_selector), playingControls = one(ui.playing_selector);
  const parseTime = (value, allowSecondsCarry = false) => {
    if (!/^\d+(?::\d{2}){1,2}$/.test(value)) return NaN;
    const parts = value.split(':').map(Number);
    return parts.length >= 2 && parts.length <= 3 && parts.every(Number.isFinite) &&
      parts.slice(1).every((part, index) => part >= 0 &&
        (part < 60 || (allowSecondsCarry && index === parts.length - 2 && part === 60))) ?
      parts.reduce((total, part) => total * 60 + part, 0) : NaN;
  };
  const clockParts = clocks.length === 1 ? compact(clocks[0].innerText).split('/') :
    positions.length === 1 && durations.length === 1 ?
      [compact(positions[0].innerText), compact(durations[0].innerText)] : [];
  // Some registered UI clocks briefly render 01:60 before 02:00. Carry the
  // observed seconds only; never synthesize elapsed time or relax duration.
  const elapsed = clockParts.length === 2 ?
    parseTime(clockParts[0], ui.elapsed_seconds_carry === true) : NaN;
  const duration = clockParts.length === 2 ? parseTime(clockParts[1]) : NaN;
  const uiIdentity = identities.length === 1 ?
    identities[0].getAttribute(ui.identity_attribute || 'href') || '' : '';
  const uiMedia = !m && clockParts.length === 2 && controls.length === 1 &&
    !!uiIdentity && playingControls.length <= 1 &&
    Number.isFinite(elapsed) && Number.isFinite(duration) &&
    duration > 0 && elapsed >= 0 && elapsed <= duration + 2;
  let hash = 2166136261;
  const identity = m ? (spec.media_identity_source === 'page_path' ?
    location.origin + location.pathname : m.currentSrc + ':' + m.duration) :
    uiMedia ? uiIdentity : '';
  if (identity) for (const c of identity)
    hash = Math.imul(hash ^ c.charCodeAt(0), 16777619) >>> 0;
  const decodedFrames = m && spec.media_progress_metric === 'decoded_frames' ?
    m.getVideoPlaybackQuality?.().totalVideoFrames ?? m.webkitDecodedFrameCount : null;
  const progress = spec.media_progress_metric === 'decoded_frames' ?
    Number.isFinite(decodedFrames) ? decodedFrames : null :
    m ? m.currentTime : uiMedia ? elapsed : null;
  const detail = !!(spec.detail_selector &&
    (!spec.detail_path_pattern || new RegExp(spec.detail_path_pattern).test(location.pathname)) &&
    Array.from(document.querySelectorAll(spec.detail_selector)).filter(visible).length === 1);
  const feedSelector = spec.feed_selector || spec.controls?.open_feed_content?.selector;
  const feedPresent = !feedSelector || Array.from(document.querySelectorAll(feedSelector)).some(visible);
  const scrollSelector = detail ? spec.detail_scroll_selector : spec.feed_scroll_selector;
  const scrollRoots = scrollSelector ?
    Array.from(document.querySelectorAll(scrollSelector)).filter(visible) : [];
  const scrollRootRequired = !!scrollSelector;
  const scrollRoot = scrollRoots.length === 1 ? scrollRoots[0] : null;
  const scrollRootValid = !scrollRootRequired || !!scrollRoot;
  const detailScrollRange = detail && scrollRootValid ? [
    scrollRoot ? scrollRoot.scrollTop : window.scrollY,
    Math.max(0, scrollRoot ? scrollRoot.scrollHeight - scrollRoot.clientHeight :
      document.scrollingElement.scrollHeight - innerHeight)] : null;
  const contentPage = !!(spec.content_path_pattern && new RegExp(spec.content_path_pattern).test(location.pathname));
  return [{allowed: !blocked && scrollRootValid && document.readyState !== 'loading', blocked,
    tab_active: document.visibilityState === 'visible' && document.hasFocus(),
    scroll_position: scrollRoot ? [scrollRoot.scrollLeft, scrollRoot.scrollTop] :
      scrollRootValid ? [window.scrollX, window.scrollY] : null,
    feed_ready: !detail && feedPresent, detail_open: detail, content_page: contentPage,
    content_url: detail ? location.href : null, content_title: detail ? document.title : null,
    detail_scroll_range: detailScrollRange,
    detail_scroll_finished: detailScrollRange ? detailScrollRange[1] - detailScrollRange[0] <= 2 : null,
    benign_popups: benignPopups, present_popups: presentPopups,
    blocker_kind: sensitive ? 'authentication_or_captcha' : blocked ? 'unknown' : null,
    media_present: !!m || uiMedia, paused: m ? m.paused : uiMedia && !playingControls.length,
    playing: m ? !m.paused && !m.ended : uiMedia && playingControls.length === 1,
    media_current_time: m ? m.currentTime : uiMedia ? elapsed : null,
    media_progress: progress,
    media_identity: identity ? String(hash) : null}];
})()
"""


def _behavior_socket(profile_dir: Path, target: dict[str, Any]) -> str:
    port = wait_for_devtools_port(profile_dir, 3)
    hosts = set(target.get("expected_hosts", ()))
    pages = _page_targets(port, 3, profile_dir)
    matching = [p for p in pages if p.get("type") == "page"
                and (urlsplit(p.get("url", "")).hostname or "").lower() in hosts
                and p.get("webSocketDebuggerUrl")]
    active_id = target.get("_active_page_id")
    if active_id:
        matching = [page for page in matching if page.get("id") == active_id]
    if len(matching) != 1:
        raise RuntimeError("behavior requires one unambiguous target page")
    return str(matching[0]["webSocketDebuggerUrl"])


def _activate_target(profile_dir: Path, port: int, target_id: str) -> None:
    """Select the verified new browser tab for subsequent page observations."""
    _browser_connection(_browser_endpoint(profile_dir, port)).command(
        "Target.activateTarget", {"targetId": target_id}, 3)


def _dispatch_mouse(websocket_url: str, events: list[dict[str, Any]], *, before_send=None) -> None:
    """Deliver browser input events to the selected page, without DOM mutation."""
    import websocket

    endpoint, separator, target_id = websocket_url.partition("#")
    if separator:
        channel = _browser_connection(endpoint)
        pressed = False
        try:
            for event in events:
                pressed = event["type"] == "mousePressed" or (pressed and event["type"] != "mouseReleased")
                channel.command("Input.dispatchMouseEvent", event, 5, target_id=target_id,
                                before_send=None if event["type"] == "mouseReleased" else before_send)
        finally:
            if pressed:
                release = next((e for e in reversed(events) if e["type"] == "mouseReleased"), None)
                if release is not None:
                    try:
                        channel.command("Input.dispatchMouseEvent", release, 5, target_id=target_id)
                    except Exception:
                        pass
        return
    connection = websocket.create_connection(
        endpoint, timeout=5, origin="http://127.0.0.1",
    )
    try:
        if before_send is not None:
            before_send()
        pressed = False
        try:
            for index, event in enumerate(events, start=1):
                if before_send is not None and event["type"] != "mouseReleased":
                    before_send()
                connection.send(json.dumps({"id": index,
                                            "method": "Input.dispatchMouseEvent", "params": event}))
                pressed = event["type"] == "mousePressed" or (pressed and event["type"] != "mouseReleased")
                while True:
                    response = json.loads(connection.recv())
                    if response.get("id") != index:
                        continue
                    if response.get("error"):
                        raise RuntimeError(str(response["error"].get("message", "Edge input failed")))
                    break
        finally:
            if pressed:
                release = next((event for event in reversed(events) if event["type"] == "mouseReleased"), None)
                if release is not None:
                    try:
                        connection.send(json.dumps({"id": len(events) + 1,
                                                    "method": "Input.dispatchMouseEvent", "params": release}))
                    except Exception:
                        pass
    finally:
        connection.close()


def _reveal_bound_control(socket, profile_dir, target, steps, guard):
    """Reveal a control using at most two explicitly bound UI operations."""
    if not isinstance(steps, list) or not 1 <= len(steps) <= 2:
        raise ValueError("control reveal requires one or two bounded steps")
    for step in steps:
        if (not isinstance(step, dict) or step.get("action") not in {"click", "hover"}
                or not isinstance(step.get("selector"), str) or not step["selector"]):
            raise ValueError("control reveal requires a selector and click or hover")
    def points(selector, button_only=False):
        return _evaluate(socket, """(() => {
          return Array.from(document.querySelectorAll(%s)).flatMap(e => {
            const r=e.getBoundingClientRect(), x=r.x+r.width/2, y=r.y+r.height/2;
            const hit=document.elementFromPoint(x,y);
            return r.width>=8 && r.height>=8 && r.left>=0 && r.top>=0 &&
              r.right<=innerWidth && r.bottom<=innerHeight &&
              !e.disabled && e.getAttribute('aria-disabled')!=='true' &&
              getComputedStyle(e).visibility!=='hidden' &&
              (hit===e || e.contains(hit)) && (!%s || e.tagName==='BUTTON') ? [{x,y}] : [];
          });
        })()""" % (json.dumps(selector), json.dumps(button_only)), 3)
    for step in steps:
        if guard is not None:
            guard()
        if not observe_edge_behavior(profile_dir, target).get("allowed"):
            raise RuntimeError("page became blocked while revealing the control")
        if step.get("skip_if_visible") and points(step["skip_if_visible"]):
            continue
        candidates = points(step["selector"], step["action"] == "click")
        if len(candidates) != 1:
            raise RuntimeError("reveal control missing or ambiguous")
        point = candidates[0]
        events = [{"type": "mouseMoved", **point}]
        if step["action"] == "click":
            events.extend([
                {"type": "mousePressed", **point, "button": "left", "buttons": 1, "clickCount": 1},
                {"type": "mouseReleased", **point, "button": "left", "buttons": 0, "clickCount": 1}])
        _dispatch_mouse(socket, events, before_send=guard)
        time.sleep(0.35)
    if not observe_edge_behavior(profile_dir, target).get("allowed"):
        raise RuntimeError("page became blocked while revealing the control")


def observe_edge_behavior(profile_dir: Path, target: dict[str, Any]) -> dict[str, Any]:
    try:
        spec = dict(target.get("semantic_binding", {}))
        spec["benign_popups"] = interruption_rules(spec)
        expression = BEHAVIOR_STATE_EXPRESSION.replace("__WINDOWS_BINDING__", json.dumps(spec))
        rows = _evaluate(_behavior_socket(profile_dir, target), expression, 3)
        return rows[0] if len(rows) == 1 else {"allowed": False}
    except Exception as exc:
        return {"allowed": False, "error_type": type(exc).__name__}


def _reveal_media_viewport(socket, profile_dir, target, guard):
    """Scroll an explicitly bound player into view without changing playback."""
    selector = target.get("semantic_binding", {}).get("media_selector", "video")
    for attempt in range(4):
        if guard is not None:
            guard()
        if not observe_edge_behavior(profile_dir, target).get("allowed"):
            raise RuntimeError("page became blocked while revealing media")
        rows = _evaluate(socket, """(() => Array.from(document.querySelectorAll(%s))
          .filter(e => e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden')
          .map(e => {const r=e.getBoundingClientRect(); return {
            x:r.x,y:r.y,width:r.width,height:r.height,bottom:r.bottom,
            viewportWidth:innerWidth,viewportHeight:innerHeight};})
          .filter(r => r.width>0 && r.height>0))()""" % json.dumps(selector), 3)
        if not rows:
            return
        if len(rows) != 1:
            raise RuntimeError("media reveal requires one unambiguous player")
        row = rows[0]
        width, height = row["viewportWidth"], row["viewportHeight"]
        # Leave room for the site's fixed header; oversized players align at top.
        if row["y"] >= 80 and (row["bottom"] <= height - 20 or
                                (row["height"] > height - 100 and row["y"] <= 100)):
            return
        if attempt == 3:
            raise RuntimeError("player remains outside viewport after bounded scroll")
        delta = max(-height * 0.8, min(height * 0.8, row["y"] - 100))
        if abs(delta) < 1:
            raise RuntimeError("player cannot fit the available viewport")
        _dispatch_mouse(socket, [{"type": "mouseWheel", "x": width * 0.8,
                                  "y": height * 0.6, "deltaX": 0, "deltaY": delta}],
                        before_send=guard)
        time.sleep(0.35)


def _detail_scroll_direction(spec, direction, position, maximum):
    """Choose one wheel direction before input; never retry an uncertain gesture."""
    policy = spec.get("detail_scroll_boundary")
    if policy is None:
        return direction
    if policy not in {"reverse", "finish"}:
        raise ValueError("unsupported detail scroll boundary policy")
    position, maximum = float(position), float(maximum)
    if not math.isfinite(position) or not math.isfinite(maximum) or maximum < 0:
        raise RuntimeError("invalid detail scroll geometry")
    if maximum <= 2:
        raise RuntimeError("detail surface has no verified scroll range")
    if (direction > 0 and maximum - position <= 2) or (direction < 0 and position <= 2):
        if policy == "finish":
            raise RuntimeError("detail scroll boundary reached before input")
        return -direction
    return direction


def perform_edge_behavior(profile_dir: Path, target: dict[str, Any], action: str, parameters) -> None:
    socket = _behavior_socket(profile_dir, target)
    spec = target.get("semantic_binding", {})
    guard = parameters.get("check_active")
    state = observe_edge_behavior(profile_dir, target)
    if not state.get("allowed"):
        raise RuntimeError("page is blocked or target identity is unavailable")
    if spec.get("reveal_media_viewport") and action in {
            "enter_live_room", "ensure_live_active", "ensure_paused", "ensure_playing"}:
        _reveal_media_viewport(socket, profile_dir, target, guard)
        state = observe_edge_behavior(profile_dir, target)
        if not state.get("allowed"):
            raise RuntimeError("page became blocked after revealing media")
        if action == "enter_live_room" and state.get("content_page") and state.get("media_present"):
            return
    if action == "start_music_playback" and state.get("media_present") and state.get("playing"):
        return
    if action == "ensure_video_active" and action not in spec.get("controls", {}) \
            and "advance_short_video" in spec.get("controls", {}) \
            and state.get("media_present") and not state.get("playing"):
        # A short-video surface without a bound resume control can still hold a
        # paused item in view, because a hidden or unfocused page stops its own
        # playback. Use the binding's own verified feed action once and let the
        # independent postcondition re-verify playback instead of failing the
        # whole task from the adapter.
        perform_edge_behavior(profile_dir, target, "advance_short_video", parameters)
        return
    if action in {"start_music_playback", "ensure_video_active", "ensure_live_active"} \
            and action not in spec.get("controls", {}):
        if not state.get("media_present") or not state.get("playing"):
            raise RuntimeError("active media has no verified control to start playback")
        if action != "start_music_playback" and spec.get("content_path_pattern") and not state.get("content_page"):
            raise RuntimeError("active media is outside a verified content page")
        return
    if action == "open_music_player" and spec.get("player_embedded") and \
            state.get("media_present") and state.get("playing"):
        return
    if action == "ensure_video_active" and \
            spec.get("controls", {}).get(action, {}).get("input") == "seek_feed_video":
        if state.get("playing"):
            return
        limit = int(spec["controls"][action].get("max_wheels", 4))
        if not 1 <= limit <= 5:
            raise ValueError("feed video seek requires one to five bounded wheel events")
        viewport = _evaluate(socket, "[{width:innerWidth,height:innerHeight}]", 3)[0]
        for _ in range(limit):
            _dispatch_mouse(socket, [{"type": "mouseWheel", "x": viewport["width"] * 0.65,
                                      "y": viewport["height"] * 0.6, "deltaX": 0,
                                      "deltaY": viewport["height"] * 0.8}], before_send=guard)
            deadline = time.monotonic() + 2.5
            while time.monotonic() < deadline:
                if guard is not None:
                    guard()
                state = observe_edge_behavior(profile_dir, target)
                if not state.get("allowed"):
                    raise RuntimeError("feed became blocked while seeking a video")
                if state.get("media_present") and state.get("playing"):
                    return
                time.sleep(0.2)
        if state.get("media_present"):
            raise RuntimeError("visible feed video is not playing")
        raise RuntimeError("no playable feed video after bounded scroll")
    if action == "advance_short_video" and spec.get("controls", {}).get(action, {}).get("input") == "wheel":
        viewport = _evaluate(socket, "[{width:innerWidth,height:innerHeight}]", 3)[0]
        _dispatch_mouse(socket, [{"type": "mouseWheel", "x": viewport["width"] * 0.65,
                                  "y": viewport["height"] * 0.6, "deltaX": 0,
                                  "deltaY": viewport["height"] * 0.8}], before_send=guard)
        return
    if action in {"advance_feed", "scroll_content"}:
        if action == "scroll_content" and state.get("detail_open") and spec.get("detail_scroll_selector"):
            selector = json.dumps(spec["detail_scroll_selector"])
            surfaces = _evaluate(socket, f"""(() => {{
              return Array.from(document.querySelectorAll({selector})).filter(e => {{
                const r = e.getBoundingClientRect();
                return e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden' &&
                  r.width > 0 && r.height > 0 && r.bottom > 0 && r.top < innerHeight &&
                  r.right > 0 && r.left < innerWidth;
              }}).map(e => {{
                const r = e.getBoundingClientRect();
                const left = Math.max(0, r.left), top = Math.max(0, r.top);
                const right = Math.min(innerWidth, r.right), bottom = Math.min(innerHeight, r.bottom);
                const x = (left + right) / 2, y = (top + bottom) / 2;
                const hit = document.elementFromPoint(x, y);
                return {{x, y, height: bottom - top, hit: hit === e || e.contains(hit),
                  scrollY: e.scrollTop, maxScrollY: Math.max(0, e.scrollHeight - e.clientHeight)}};
              }});
            }})()""", 3)
            if len(surfaces) != 1 or not surfaces[0].get("hit"):
                raise RuntimeError("detail scroll surface is absent, ambiguous or obstructed")
            surface = surfaces[0]
            direction = -1 if parameters.get("direction") == "down" else 1
            direction = _detail_scroll_direction(spec, direction,
                surface.get("scrollY", 0), surface.get("maxScrollY", 0))
            _dispatch_mouse(socket, [{"type": "mouseWheel", "x": surface["x"],
                                      "y": surface["y"], "deltaX": 0,
                                      "deltaY": direction * surface["height"] * 0.7}], before_send=guard)
            return
        paginate = action == "advance_feed" and "paginate_feed" in spec.get("controls", {})
        detail_scroll = action == "scroll_content" and state.get("detail_open")
        expression = ("[{width:innerWidth,height:innerHeight,scrollY:scrollY,"
                      "maxScrollY:Math.max(0,document.scrollingElement.scrollHeight-innerHeight)}]"
                      if paginate or detail_scroll else "[{width:innerWidth,height:innerHeight}]")
        viewport = _evaluate(socket, expression, 3)[0]
        direction = -1 if parameters.get("direction") == "down" else 1
        if detail_scroll:
            direction = _detail_scroll_direction(spec, direction,
                viewport.get("scrollY", 0), viewport.get("maxScrollY", 0))
        if (paginate and direction > 0 and viewport["maxScrollY"] > 0
                and viewport["scrollY"] >= viewport["maxScrollY"] - 16):
            # A bound next-page control keeps finite result feeds moving.
            action = "paginate_feed"
        else:
            _dispatch_mouse(socket, [{"type": "mouseWheel", "x": viewport["width"] * 0.65,
                                      "y": viewport["height"] * 0.6, "deltaX": 0,
                                      "deltaY": direction * viewport["height"] * 0.7}], before_send=guard)
            return
    control = spec.get("controls", {}).get(action, {})
    if control.get("input") == "close_detail_tab":
        # Only a detail tab created by this run's verified click may be closed.
        ownership = target.get("_detail_tab_owner", {})
        active_id = target.get("_active_page_id")
        if action != "return_to_feed" or not state.get("detail_open") or \
                active_id != ownership.get("detail") or not ownership.get("feed"):
            raise RuntimeError("detail-tab return requires owned detail and feed targets")
        selector = control.get("selector")
        if not selector or _evaluate(socket, f"[{{count:document.querySelectorAll({json.dumps(selector)}).length}}]", 3) != [{"count": 1}]:
            raise RuntimeError("detail marker absent or ambiguous")
        port = wait_for_devtools_port(profile_dir, 3)
        pages = _page_targets(port, 3, profile_dir)
        feed = [p for p in pages if p.get("id") == ownership["feed"] and p.get("webSocketDebuggerUrl")]
        urls = [u for u in target.get("args", []) if urlsplit(u).scheme in {"http", "https"}]
        if len(feed) != 1 or len(urls) != 1 or feed[0].get("url", "").rstrip("/") != urls[0].rstrip("/"):
            raise RuntimeError("owned feed is missing or has changed destination")
        expression = BEHAVIOR_STATE_EXPRESSION.replace("__WINDOWS_BINDING__", json.dumps(spec))
        feed_state = _evaluate(feed[0]["webSocketDebuggerUrl"], expression, 3)
        if len(feed_state) != 1 or not feed_state[0].get("allowed") or not feed_state[0].get("feed_ready"):
            raise RuntimeError("owned feed postcondition is unavailable")
        if guard is not None:
            guard()
        channel = _browser_connection(_browser_endpoint(profile_dir, port))
        receipt = channel.command("Target.closeTarget", {"targetId": active_id}, 3)
        if not receipt.get("success"):
            raise RuntimeError("owned detail tab did not close")
        target["_active_page_id"] = ownership["feed"]
        target.pop("_detail_tab_owner", None)
        _activate_target(profile_dir, port, target["_active_page_id"])
        return
    if control.get("input") == "registered_entry":
        # External detail pages need not expose a link back to the search/feed.
        # Bind the current detail marker, then navigate to the sole registered
        # entry; the shared playbook still verifies the resulting feed state.
        if action != "return_to_feed" or not state.get("detail_open"):
            raise RuntimeError("registered-entry return requires a verified detail page")
        selector = control.get("selector")
        urls = [value for value in target.get("args", []) if urlsplit(value).scheme in {"http", "https"}]
        if not selector or len(urls) != 1:
            raise ValueError("registered-entry return requires a detail marker and one feed URL")
        operation = f"""
          const markers = Array.from(document.querySelectorAll({json.dumps(selector)})).filter(e => {{
            const r = e.getBoundingClientRect();
            return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden';
          }});
          if (!state.detail_open || markers.length !== 1) throw Error('detail marker absent or ambiguous');
          location.assign({json.dumps(urls[0])});
        """
    elif action in {"launch_app", "ensure_content_feed", "recover_content_feed", "return_to_feed"} and action not in spec.get("controls", {}):
        urls = [value for value in target.get("args", []) if urlsplit(value).scheme in {"http", "https"}]
        if len(urls) != 1:
            raise ValueError("binding requires one known feed URL")
        operation = f"location.assign({json.dumps(urls[0])});"
    elif action == "dismiss_popup" or action in spec.get("controls", {}):
        if action == "dismiss_popup":
            popup_id = parameters.get("popup_id")
            matches = [popup for popup in interruption_rules(spec) if popup["id"] == popup_id]
            if len(matches) != 1 or popup_id not in state.get("benign_popups", []):
                raise RuntimeError("known benign popup is absent or ambiguous")
            control = {"selector": matches[0]["dismiss_selector"], "selection": "unique"}
        else:
            control = spec["controls"][action]
        selector = json.dumps(control["selector"])
        selection = control.get("selection", "unique")
        if selection not in {"unique", "random"}:
            raise ValueError("binding selection must be unique or random")
        fraction = float(parameters.get("choice_fraction", 0))
        if not 0 <= fraction < 1:
            raise ValueError("invalid seeded candidate choice")
        path_pattern = json.dumps(control.get("href_path_pattern", ""))
        allow_placeholder_href = json.dumps(bool(control.get("allow_placeholder_href", False)))
        hosts = json.dumps(list(target.get("expected_hosts", ())))
        identity_ancestor = json.dumps(control.get("identity_ancestor", ""))
        identity_attribute = json.dumps(control.get("identity_attribute", ""))
        previous_identity = json.dumps(target.get("_last_content_identity") if control.get("avoid_repeat") else None)
        expression = f"""(() => {{
          const pattern = {path_pattern};
          const allowPlaceholder = {allow_placeholder_href};
          return Array.from(document.querySelectorAll({selector})).map(e => {{
            const r = e.getBoundingClientRect(), x = r.x + r.width / 2, y = r.y + r.height / 2;
            const hit = document.elementFromPoint(x, y);
            const link = e.closest('a[href]');
            const url = link ? new URL(link.href, location.href) : null;
            const placeholder = !!(link && allowPlaceholder &&
              link.getAttribute('href').trim().toLowerCase() === 'javascript:;');
            const identityNode = {identity_ancestor} ? e.closest({identity_ancestor}) : link;
            const identity = identityNode ? ({identity_attribute} ? identityNode.getAttribute({identity_attribute}) : link?.href) : null;
            if ({json.dumps(bool(control.get('avoid_repeat')))} && (!identity || identity === {previous_identity})) return null;
            if (r.width < 8 || r.height < 8 || r.left < 0 || r.top < 0 ||
                e.disabled || e.getAttribute('aria-disabled') === 'true' ||
                r.right > innerWidth || r.bottom > innerHeight ||
                !(hit === e || e.contains(hit)) ||
                getComputedStyle(e).visibility === 'hidden' ||
                (url && !placeholder && (!['http:', 'https:'].includes(url.protocol) ||
                  !{hosts}.includes(url.hostname) ||
                  (pattern && !new RegExp(pattern).test(url.pathname))))) return null;
            return {{x, y, identity, opens_new_tab: {json.dumps(bool(control.get('opens_new_tab')))} || !!(link && link.target === '_blank')}};
          }}).filter(Boolean);
        }})()"""
        if action in {"enter_live_room", "enter_long_video", "open_music_player"}:
            ready_deadline = time.monotonic() + 6
            while time.monotonic() < ready_deadline:
                if guard is not None:
                    guard()
                if _evaluate(socket, f"[{{count:document.querySelectorAll({selector}).length}}]", 3)[0]["count"]:
                    break
                time.sleep(0.25)
        candidates = _evaluate(socket, expression, 3)
        if not candidates and control.get("reveal_steps"):
            _reveal_bound_control(socket, profile_dir, target, control["reveal_steps"], guard)
            candidates = _evaluate(socket, expression, 3)
        if not candidates and control.get("reveal") == "bottom_hover":
            viewport = _evaluate(socket, "[{width:innerWidth,height:innerHeight}]", 3)[0]
            _dispatch_mouse(socket, [{"type": "mouseMoved", "x": viewport["width"] * 0.5,
                                      "y": viewport["height"] * 0.98}], before_send=guard)
            time.sleep(0.25)
            candidates = _evaluate(socket, expression, 3)
        if not candidates and (control.get("reveal") in {"scroll_down", "scroll_up"} or
                action in {"enter_live_room", "enter_long_video", "open_music_player"}):
            scroll_direction = -1 if control.get("reveal") == "scroll_up" else 1
            for attempt in range(3):
                if attempt and not observe_edge_behavior(profile_dir, target).get("allowed"):
                    raise RuntimeError("page became blocked while revealing the control")
                viewport = _evaluate(socket, "[{width:innerWidth,height:innerHeight}]", 3)[0]
                _dispatch_mouse(socket, [{"type": "mouseWheel", "x": viewport["width"] * 0.65,
                                          "y": viewport["height"] * 0.6, "deltaX": 0,
                                          "deltaY": scroll_direction * viewport["height"] * 0.7}], before_send=guard)
                settle_deadline = time.monotonic() + 3
                while time.monotonic() < settle_deadline:
                    if guard is not None:
                        guard()
                    if observe_edge_behavior(profile_dir, target).get("allowed"):
                        break
                    time.sleep(0.2)
                else:
                    raise RuntimeError("page became blocked while revealing the control")
                visible_deadline = time.monotonic() + 3
                while time.monotonic() < visible_deadline:
                    if guard is not None:
                        guard()
                    candidates = _evaluate(socket, expression, 3)
                    if candidates:
                        break
                    time.sleep(0.2)
                if candidates:
                    break
        if not candidates and control.get("reveal") in {"scroll_up", "scroll_into_view"}:
            # Some embedded players consume wheel events. Reposition the bound
            # link once, then require the same hit-tested visible control.
            if guard is not None:
                guard()
            _evaluate(socket, f"""(() => {{
              const link = document.querySelector({selector});
              if (link) link.scrollIntoView({{block:'center', inline:'nearest'}});
              return [];
            }})()""", 3)
            time.sleep(0.35)
            candidates = _evaluate(socket, expression, 3)
        if not candidates or (selection == "unique" and len(candidates) != 1):
            raise RuntimeError("visible control missing or ambiguous")
        selected = candidates[int(fraction * len(candidates))]
        feed_id = target.get("_active_page_id")
        if control.get("opens_new_tab") and not feed_id:
            raise RuntimeError("new-tab content click requires a pinned feed target")
        before_page_rows = _page_targets(wait_for_devtools_port(profile_dir, 3), 3, profile_dir)
        before_pages = {page.get("id") for page in before_page_rows}
        x, y = selected["x"], selected["y"]
        if control.get("same_tab") and selected["opens_new_tab"]:
            # Preserve one collection tab while delivering a real mouse click.
            # Only the exact hit-tested, already allowlisted content link changes
            # its browsing context; its destination and page content stay intact.
            if guard is not None:
                guard()
            changed = _evaluate(socket, f"""(() => {{
              const e = document.elementFromPoint({x}, {y});
              const link = e && e.closest('a[href]');
              if (!link || link.target !== '_blank' ||
                  !{hosts}.includes(new URL(link.href, location.href).hostname) ||
                  ({path_pattern} && !new RegExp({path_pattern}).test(new URL(link.href, location.href).pathname)) ||
                  (link !== e && !link.contains(e))) return [];
              link.setAttribute('target', '_self');
              return [{{changed: true}}];
            }})()""", 3)
            if changed != [{"changed": True}]:
                raise RuntimeError("content link changed before same-tab click")
            selected["opens_new_tab"] = False
        _dispatch_mouse(socket, [
            {"type": "mouseMoved", "x": x, "y": y},
            {"type": "mousePressed", "x": x, "y": y, "button": "left", "buttons": 1, "clickCount": 1},
            {"type": "mouseReleased", "x": x, "y": y, "button": "left", "buttons": 0, "clickCount": 1},
        ], before_send=guard)
        deadline = time.monotonic() + (5 if selected["opens_new_tab"] else 1.5)
        while time.monotonic() < deadline:
            port = wait_for_devtools_port(profile_dir, 3)
            new_pages = [page for page in _page_targets(port, 3, profile_dir)
                         if page.get("type") == "page" and page.get("id") not in before_pages
                         and urlsplit(page.get("url", "")).scheme in {"http", "https"}]
            if new_pages:
                same_host = [(urlsplit(page.get("url", "")).hostname or "").lower()
                             in target.get("expected_hosts", ()) for page in new_pages]
                if len(new_pages) != 1 or same_host != [True]:
                    diagnostic = [{"target_id": page.get("id"),
                        "host": urlsplit(page.get("url", "")).hostname,
                        "opener_id": page.get("openerId"),
                        "same_url_before": any(old.get("url") == page.get("url")
                                               for old in before_page_rows)} for page in new_pages]
                    raise RuntimeError("click opened unexpected or ambiguous tabs: "
                                       + json.dumps(diagnostic, separators=(',', ':')))
                target["_active_page_id"] = new_pages[0]["id"]
                if control.get("opens_new_tab"):
                    target["_detail_tab_owner"] = {"feed": feed_id, "detail": new_pages[0]["id"]}
                if selected.get("identity"):
                    target["_last_content_identity"] = selected["identity"]
                if not target.get("_background_control_only"):
                    _activate_target(profile_dir, port, target["_active_page_id"])
                return
            time.sleep(0.1)
        if selected["opens_new_tab"]:
            raise RuntimeError("click did not open one verified target tab")
        return
    else:
        raise ValueError("Windows semantic action has no verified page binding")
    # Recheck within the same page context to avoid acting across a redirect.
    hosts = json.dumps(list(target.get("expected_hosts", ())))
    state_expression = BEHAVIOR_STATE_EXPRESSION.replace("__WINDOWS_BINDING__", json.dumps(spec))
    expression = "(async () => { const state = (" + state_expression + ")[0]; " + (
        f"if (!{hosts}.includes(location.hostname) || !state.allowed) "
        "throw Error('page no longer allowed'); "
    ) + operation + " return []; })()"
    if guard is not None:
        guard()
    _evaluate(socket, expression, 3, before_send=guard)


def probe_edge_media(
    profile_dir: Path,
    *,
    observe_seconds: float = 2.6,
    min_advance_seconds: float = 0.75,
    timeout_seconds: float = 10.0,
    target_id: str | None = None,
) -> dict[str, Any]:
    """Observe media timing without returning URLs, titles, text, or payload."""

    base = {
        "schema_version": "windows-media-playback-evidence-v1",
        "content_redacted": True,
        "method": "edge_cdp_html_media_current_time",
    }
    try:
        port = wait_for_devtools_port(profile_dir, timeout_seconds)
        websocket_url = _active_page_websocket(port, timeout_seconds, profile_dir, target_id=target_id)
        before = _evaluate(websocket_url, MEDIA_STATE_EXPRESSION, timeout_seconds)
        time.sleep(max(0.0, observe_seconds))
        after = _evaluate(websocket_url, MEDIA_STATE_EXPRESSION, timeout_seconds)
        after_by_key = {str(item.get("key")): item for item in after}
        best_advance = 0.0
        for item in before:
            later = after_by_key.get(str(item.get("key")))
            if not later:
                continue
            advance = float(later.get("current_time", 0)) - float(item.get("current_time", 0))
            usable = not bool(later.get("paused")) and not bool(later.get("ended")) and int(later.get("ready_state", 0)) >= 2
            if usable:
                best_advance = max(best_advance, advance)
        ready = [item for item in after if int(item.get("ready_state", 0)) >= 2 and not bool(item.get("ended"))]
        playing = [item for item in ready if not bool(item.get("paused"))]
        verified = best_advance >= min_advance_seconds
        return {
            **base,
            "ok": verified,
            "evidence": "html_media_current_time_advanced" if verified else "html_media_not_advancing",
            "observed_advance_seconds": round(best_advance, 3),
            "media_count": len(after),
            "ready_count": len(ready),
            "playing_count": len(playing),
            "observe_seconds": observe_seconds,
            "minimum_advance_seconds": min_advance_seconds,
        }
    except Exception as exc:
        return {
            **base,
            "ok": False,
            "evidence": "media_probe_unavailable",
            "error_type": type(exc).__name__,
        }
