"""Transport for an already authorized browser-use tab.

The shared PlaybookRunner still owns every action and postcondition. This
adapter does not attach a debugger, launch a browser, or request permissions.
The browser-side consumer must use the documented browser-use API.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit
import uuid
import re

from .automation import WindowsDesktopDriver


class BrowserControlTransport:
    PROTOCOL = "windows-browser-use-v1"
    IDENTITY_KEY = "tab_id"
    # Browser commands run only inside an active CUA tool call. Allow the next
    # bounded tool call to resume the consumer without resending uncertain input.
    MAX_REQUEST_SECONDS = 90
    SESSION_LEASE_SECONDS = 90

    def __init__(self, directory: Path, *, timeout_seconds: float = MAX_REQUEST_SECONDS):
        self.directory = directory.resolve()
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= self.MAX_REQUEST_SECONDS:
            raise ValueError("Browser-use request deadline must be within 90 seconds")
        self.timeout_seconds = timeout_seconds
        self._lock = threading.Lock()
        self.session = self._session()

    def _session(self):
        row = json.loads(self._file_access(
            lambda: (self.directory / "session.json").read_text(encoding="utf-8")))
        now = (self._workspace_epoch() if row.get("clock_source") == "windows_workspace_file_mtime"
               else time.time())
        age = now - float(row.get("heartbeat_epoch", 0))
        if (row.get("protocol") != self.PROTOCOL
                or row.get("status") != "ready"
                or not row.get("session_id") or not row.get(self.IDENTITY_KEY)
                or not math.isfinite(age) or not -.01 <= age <= self.SESSION_LEASE_SECONDS):
            raise RuntimeError("Authorized browser-use consumer is not live")
        return row

    def _workspace_epoch(self):
        # GetSystemTimePreciseAsFileTime (Python) can differ from the control
        # worker clock. File modification times give both peers one Windows
        # reference without changing the system clock or granting access.
        probe = self.directory / "producer-clock.json"
        raw = time.time()
        self._file_access(lambda: probe.write_text(json.dumps({"producer_epoch": raw}), encoding="utf-8"))
        return self._file_access(lambda: probe.stat().st_mtime_ns) / 1_000_000_000

    @staticmethod
    def _file_access(operation):
        # Windows readers may briefly share-lock an atomic publication. Retry
        # file access only; never reissue a browser operation or request ID.
        for attempt in range(10):
            try:
                return operation()
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(.02)

    def request(self, operation: str, **payload):
        with self._lock:
            live = self._session()
            if live["session_id"] != self.session["session_id"]:
                raise RuntimeError("Browser-use consumer changed; refusing stale commands")
            request_id = str(uuid.uuid4())
            started = (self._workspace_epoch() if live.get("clock_source") == "windows_workspace_file_mtime"
                       else time.time())
            request = {"protocol": self.PROTOCOL, "session_id": live["session_id"],
                       "request_id": request_id, "operation": operation,
                       "created_epoch": started, "expires_epoch": started + self.timeout_seconds,
                       "clock_source": live.get("clock_source", "producer_wall_clock"),
                       "producer_raw_epoch": time.time(),
                       **payload}
            path = self.directory / "request.json"
            temporary = self.directory / f"{request_id}.tmp"
            temporary.write_text(json.dumps(request), encoding="utf-8")
            self._file_access(lambda: temporary.replace(path))
            response_path = self.directory / "response.json"
            deadline = time.monotonic() + self.timeout_seconds
            while time.monotonic() < deadline:
                try:
                    response = json.loads(response_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    response = {}
                if response.get("request_id") == request_id:
                    if (response.get("session_id") != live["session_id"]
                            or not started <= float(response.get("completed_epoch", 0)) <= request["expires_epoch"]):
                        raise RuntimeError("Stale or mismatched browser-use response")
                    if not response.get("ok"):
                        raise RuntimeError(response.get("error", "Browser-use operation failed"))
                    return response.get("result", {})
                time.sleep(0.05)
            # An uncertain action is never resent by this transport.
            raise TimeoutError(f"Browser-use {operation} did not return evidence before its deadline")


def verified_article_redirect(state, target, url=None):
    """Accept only a recorded feed link plus independently observed article DOM."""
    try:
        spec = target.get('semantic_binding', {})
        item = state['article_redirect']
        source, link, final = (urlsplit(item[key]) for key in ('source_url','link_url','final_url'))
        return (spec.get('allow_external_article_redirects') is True
                and source.scheme in {'http','https'} and source.hostname in target['expected_hosts']
                and link.scheme in {'http','https'} and link.hostname in spec['content_hosts']
                and re.search(spec['detail_path_pattern'], link.path) is not None
                and final.scheme in {'http','https'} and bool(final.hostname)
                and state.get('content_url') == item['final_url']
                and (url is None or item['final_url'] == url)
                and bool(item['link_text']) and bool(item['link_identity'])
                and item['article_count'] == 1 and item['title_count'] == 1
                and bool(item['title']) and item['article_chars'] >= 200
                and state.get('allowed') is True and state.get('detail_open') is True
                and not state.get('blocked') and not state.get('blocker_kind'))
    except (KeyError, TypeError, ValueError, re.error):
        return False


class BrowserUseDesktopDriver(WindowsDesktopDriver):
    """Existing Windows shared-task driver with browser-use control transport."""
    def __init__(self, directory: Path, *, edge_profile_dir: Path, tab_id: str,
                 tolerate_foreground_interruptions: bool = False,
                 background_control_only: bool = False):
        super().__init__(edge_profile_dir=edge_profile_dir, attach_existing_edge=True,
                         existing_edge_tab_id=tab_id,
                         background_control_only=background_control_only,
                         tolerate_foreground_interruptions=tolerate_foreground_interruptions)
        self.transport = BrowserControlTransport(directory)
        self._article_redirects = {}
        if self.transport.session["tab_id"] != tab_id:
            raise ValueError("Browser-use transport must pin the explicitly selected tab")

    def launch_target(self, target):
        self.launch(target["command"], target.get("args", []), enable_media_probe=True, target=target)

    def launch(self, command, args, *, enable_media_probe=False, target=None):
        if Path(command).name.lower() not in {"msedge", "msedge.exe"}:
            raise ValueError("Browser-use transport currently supports Edge browser targets")
        urls = [value for value in args if urlsplit(value).scheme in {"http", "https"}]
        if len(urls) != 1:
            raise ValueError("Browser-use launch requires one registered entry URL")
        result = self.transport.request("launch", entry_url=urls[0], target=target,
                                        focus_required=self._tab_focus_required())
        from urllib.parse import parse_qsl, urlencode
        ignored = (target or {}).get("semantic_binding", {}).get("entry_tracking_query_keys", [])
        def canonical(url):
            parts = urlsplit(url)
            query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in ignored])
            return parts._replace(path=parts.path or "/", query=query)
        if result.get("tab_id") != self._existing_target_id or canonical(result.get("url", "")) != canonical(urls[0]):
            raise RuntimeError("Existing browser-use target does not match the fresh registered entry")
        self._media_probe_active = True

    def observe_behavior(self, target):
        try:
            result = self.transport.request("observe", target=target)
            state = result["state"]
            host = (urlsplit(result.get("url", "")).hostname or "").lower()
            redirect_ok = verified_article_redirect(state, target, result.get('url'))
            if ((host not in target.get("expected_hosts", []) and not redirect_ok) or not result.get("tab_id")
                    or not isinstance(state.get("allowed"), bool)):
                raise RuntimeError("Browser-use observation has no verified target identity")
            self._existing_target_id = result["tab_id"]
            if redirect_ok:
                self._article_redirects[result['url']] = dict(state)
            state["browser_control_transport"] = "authorized_browser_use"
            state["resolved_target_id"] = self._existing_target_id
            return state
        except Exception as exc:
            return {"allowed": False, "error_type": type(exc).__name__,
                    "error_detail": str(exc)[:1000],
                    "observation_failure_source": "authorized_browser_use"}

    def perform_behavior(self, action, target, parameters):
        parameters.get("check_active", lambda: None)()
        self.transport.request("perform", action=action, target=target,
                               focus_required=self._tab_focus_required(),
                               parameters={key: value for key, value in parameters.items()
                                           if not callable(value)})

    def _tab_focus_required(self):
        return not (getattr(self, "background_control_only", False)
                    or getattr(self, "tolerate_foreground_interruptions", False))

    def close(self):
        # The transport and browser belong to the user and survive this child run.
        pass

    def export_focus_evidence(self, run_dir: Path, target: dict):
        session = self.transport.session
        if session.get('focus_protocol') != 'windows-tab-focus-v2':
            return None
        source = Path(session['focus_events_path']).resolve()
        if source.parent != self.transport.directory or source.name != f"focus-{session['session_id']}.jsonl":
            raise ValueError('Focus evidence must belong to the authorized consumer directory')
        hosts = target['expected_hosts']
        rows = []
        for raw in self.transport._file_access(lambda: source.read_text(encoding='utf-8')).splitlines():
            row = json.loads(raw)
            sample = row['focus_source']['sample']
            redirect_state = self._article_redirects.get(sample.get('url'), {})
            redirect_ok = verified_article_redirect(redirect_state, target, sample.get('url'))
            if redirect_ok:
                row['payload']['state'].update({key:redirect_state[key] for key in
                    ('article_redirect','allowed','detail_open','blocked','blocker_kind')})
            row['payload']['state']['tab_active'] = bool(row['payload']['state']['tab_active']
                                                       and (row['payload']['state']['host'] in hosts or redirect_ok))
            rows.append(row)
        destination = run_dir / 'platform_evidence' / 'browser_tab_focus.jsonl'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(''.join(json.dumps(r)+'\n' for r in rows), encoding='utf-8')
        return {'protocol':'windows-tab-focus-v2','session_id':session['session_id'],
                'tab_id':session['tab_id'],'events':'platform_evidence/browser_tab_focus.jsonl'}


def verify_continuous_focus(path: Path, metadata: dict, *, session_id: str, tab_id: str,
                            expected_hosts: list[str], target: dict | None = None) -> bool:
    """Verify document-buffer ownership and independently recompute tab state."""
    try:
        if (metadata['protocol'] != 'windows-tab-focus-v2' or metadata['session_id'] != session_id
                or str(metadata['tab_id']) != str(tab_id) or not expected_hosts):
            return False
        rows = [json.loads(r) for r in path.read_text(encoding='utf-8').splitlines() if r.strip()]
        if len(rows) < 2:
            return False
        sequences = {}
        for row in rows:
            source = row['focus_source']; raw = source['sample']
            state = row['payload']['state']
            document = source['document_id']
            redirect_ok = bool(target and raw.get('url') and verified_article_redirect(
                dict(state, content_url=raw['url']), target, raw['url']))
            if (row['event_type'] != 'windows_observation' or source['method'] != 'Runtime.evaluate'
                    or str(source['tab_id']) != str(tab_id) or not document
                    or source['protocol'] != 'windows-tab-focus-v2' or source['session_id'] != session_id
                    or type(raw['sequence']) is not int or raw['sequence'] != sequences.get(document,0)+1
                    or type(raw['tab_active']) is not bool
                    or not math.isfinite(raw['observed_epoch'])
                    or row['payload']['observed_epoch'] != raw['observed_epoch']
                    or state['host'] != raw['host']
                    or state['tab_active'] is not (raw['tab_active'] and (raw['host'] in expected_hosts or redirect_ok))):
                return False
            sequences[document] = raw['sequence']
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False
