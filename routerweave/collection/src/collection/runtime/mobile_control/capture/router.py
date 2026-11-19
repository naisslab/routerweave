"""Shared router transport for collection."""
import os
from collection_core.router import RouterStreamCapture, RouterCaptureError, _router_ssh, parse_tcpdump_trailer


def default_router_identity():
    return os.environ.get("ROUTERWEAVE_SSH_KEY") or None
