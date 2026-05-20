"""WSGI-style emergency-stop middleware. Returns HTTP 423 Locked when pressed.

SPEC §5.4. The Python equivalent of the TS Express/Connect middleware uses
the WSGI environ/start_response signature so it composes with any standard
Python web framework (Flask, Django via wsgi_app, Bottle, etc.).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .hub import EStopHub

WSGIEnviron = dict[str, Any]
WSGIStartResponse = Callable[[str, list[tuple[str, str]]], Any]
WSGIApp = Callable[[WSGIEnviron, WSGIStartResponse], list[bytes]]


@dataclass
class EStopMiddlewareOptions:
    resolve_user_id: Callable[[WSGIEnviron], Optional[str]]
    """Extract the user id from the request environ. Return None to skip."""
    exclude: Optional[Callable[[WSGIEnviron], bool]] = None
    """Predicate to bypass the gate (e.g., for the clear endpoint)."""
    locked_response_body: Optional[Callable[[dict[str, Any], str], dict[str, Any]]] = None
    """Override the JSON body returned on 423."""


def create_estop_middleware(
    hub: EStopHub,
    options: EStopMiddlewareOptions,
) -> Callable[[WSGIApp], WSGIApp]:
    """Decorate a WSGI app with the e-stop gate."""
    body_factory = options.locked_response_body or _default_locked_body
    exclude = options.exclude

    def middleware(app: WSGIApp) -> WSGIApp:
        def wrapped(environ: WSGIEnviron, start_response: WSGIStartResponse) -> list[bytes]:
            if exclude is not None and exclude(environ):
                return app(environ, start_response)
            user_id = options.resolve_user_id(environ)
            if user_id is None:
                return app(environ, start_response)
            if not hub.is_pressed(user_id):
                return app(environ, start_response)
            state = hub.status(user_id)
            payload = body_factory({"pressed_at": state.pressed_at}, user_id)
            body = json.dumps(payload).encode("utf-8")
            start_response(
                "423 Locked",
                [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                ],
            )
            return [body]
        return wrapped

    return middleware


def _default_locked_body(state: dict[str, Any], user_id: str) -> dict[str, Any]:  # noqa: ARG001
    return {
        "error": "estop_active",
        "message": (
            "An emergency stop is active for your account. "
            "Outbound actions are blocked until cleared."
        ),
        "pressed_at": state.get("pressed_at"),
    }
