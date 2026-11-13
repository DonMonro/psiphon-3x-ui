"""Serving-process TLS state, initialized by the panel's Uvicorn config."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .tls_reload import TLSController

_tls_controller: TLSController | None = None


def set_tls_controller(controller: TLSController) -> None:
    """Register the controller in the actual serving process, not a supervisor."""
    global _tls_controller
    _tls_controller = controller


def get_tls_controller() -> TLSController | None:
    return _tls_controller


def reset_runtime_state() -> None:
    """Clear serving state on a new server start or in isolated tests."""
    global _tls_controller
    _tls_controller = None
