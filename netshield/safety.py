"""Shared safety gate — the single enforcement point for every control-plane action.

Every function in this project that can scan ports, ARP-spoof, cut or throttle a
target MUST validate the target through :func:`assert_safe_target` (imported
from THIS module) before doing anything. The checks are deliberately strict:

  (a) the target IP must be inside the detected local /24
  (b) it must not be the gateway IP
  (c) it must not be the host machine's own IP

plus network/broadcast/loopback/multicast exclusions. Violations raise
:class:`SafetyViolation` (surfaced to the user as an error) and are recorded
in both the application log and the activity log.

There is intentionally NO other copy of this logic anywhere in the codebase —
services import this module, never re-implement the checks.
"""
from __future__ import annotations

import ipaddress
import logging
from functools import wraps

import config

logger = logging.getLogger("netshield.safety")


class SafetyViolation(Exception):
    """Raised when a control-plane action targets an unsafe IP."""


def validate_target_ip(ip: str) -> str | None:
    """Return None if the target is safe, otherwise a human-readable reason."""
    if not ip:
        return "no target IP supplied"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return f"{ip!r} is not a valid IP address"
    if addr.is_loopback or addr.is_multicast or not addr.is_private:
        return f"{ip} is not a private LAN address"
    net = config.current_network()
    if addr not in net:
        return f"{ip} is not inside the local network {net}"
    if addr == net.network_address:
        return f"{ip} is the network address of {net}"
    if addr == net.broadcast_address:
        return f"{ip} is the broadcast address of {net}"
    if str(addr) == config.detect_host_ip():
        return f"{ip} is this host's own IP — refusing to target ourselves"
    if str(addr) == config.gateway_ip():
        return f"{ip} is the gateway IP — refusing to target the router"
    return None


def assert_safe_target(ip: str) -> None:
    """Raise :class:`SafetyViolation` unless the target passes every check."""
    reason = validate_target_ip(ip)
    if reason:
        _log_rejection(ip, reason)
        raise SafetyViolation(f"Safety gate: {reason}")


def _log_rejection(ip: str, reason: str) -> None:
    logger.warning("SAFETY BLOCKED target %s: %s", ip, reason)
    try:
        from flask import has_app_context
        if has_app_context():
            from netshield.audit import log_activity
            log_activity("system", f"SAFETY BLOCKED target {ip}: {reason}")
    except Exception:
        pass


def safety_gate(fn):
    """Decorator: validate any IP-looking argument before calling fn.

    Looks for an 'ip' kwarg or a positional argument that parses as an IPv4
    address. All control-plane service functions also call
    ``assert_safe_target()`` internally — this decorator is defence-in-depth
    at the function boundary, not a replacement for the internal check.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        for value in list(kwargs.values()) + list(args):
            if isinstance(value, str):
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                assert_safe_target(value)
                break
        return fn(*args, **kwargs)
    return wrapper
