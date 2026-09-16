"""services/ — framework-agnostic business logic (no Flask route code).

Every service is importable and testable without a running web server; the
blueprints and background threads are thin callers. Packet-level and
spoofing logic lives in network_scanner.py / traffic_control.py and is
heavily commented for auditability.
"""
