"""TLS SNI extraction — read the plaintext server name out of a TLS
ClientHello (the one piece of every HTTPS connection that is NOT encrypted).

This is what makes category blocking actually work even when a device
bypasses DNS filtering (encrypted DNS, cached IPs, custom resolvers):
every HTTPS connection starts with a ClientHello carrying the destination
hostname in the SNI extension. We are in the L2 path, so we can block by
name and reset the connection. ECH (encrypted SNI) would hide it, but it
is still rare — and the DNS + IP layers keep working underneath.

Parser is hand-rolled with strict bounds checks (no third-party deps).
"""
from __future__ import annotations

import struct

TLS_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000
SNI_HOST_NAME = 0x00


def extract_sni(tcp_payload: bytes) -> str | None:
    """Return the SNI hostname from a TLS ClientHello, or None."""
    try:
        data = bytes(tcp_payload)
        if len(data) < 5:
            return None
        if data[0] != TLS_HANDSHAKE:
            return None
        # TLS record: type(1) version(2) length(2)
        rec_len = struct.unpack(">H", data[3:5])[0]
        if rec_len == 0 or 5 + rec_len > len(data):
            return None
        body = data[5:5 + rec_len]
        if len(body) < 4 or body[0] != HANDSHAKE_CLIENT_HELLO:
            return None
        # handshake: type(1) length(3)
        hs_len = (body[1] << 16) | (body[2] << 8) | body[3]
        if hs_len == 0 or 4 + hs_len > len(body):
            return None
        ch = body[4:4 + hs_len]
        pos = 0
        # client_version(2) + random(32)
        if len(ch) < 34:
            return None
        pos = 34
        # session id
        if pos >= len(ch):
            return None
        sid_len = ch[pos]
        pos += 1 + sid_len
        # cipher suites
        if pos + 2 > len(ch):
            return None
        cs_len = struct.unpack(">H", ch[pos:pos + 2])[0]
        pos += 2 + cs_len
        # compression methods
        if pos >= len(ch):
            return None
        comp_len = ch[pos]
        pos += 1 + comp_len
        # extensions
        if pos + 2 > len(ch):
            return None
        ext_len = struct.unpack(">H", ch[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_len, len(ch))
        while pos + 4 <= end:
            etype, elen = struct.unpack(">HH", ch[pos:pos + 4])
            pos += 4
            if etype == EXT_SERVER_NAME and pos + elen <= end:
                return _parse_server_name(ch[pos:pos + elen])
            pos += elen
        return None
    except Exception:
        return None


def _parse_server_name(ext: bytes) -> str | None:
    if len(ext) < 2:
        return None
    list_len = struct.unpack(">H", ext[0:2])[0]
    p = 2
    end = min(2 + list_len, len(ext))
    while p + 3 <= end:
        ntype = ext[p]
        nlen = struct.unpack(">H", ext[p + 1:p + 3])[0]
        p += 3
        if ntype == SNI_HOST_NAME and p + nlen <= end:
            name = ext[p:p + nlen].decode("ascii", errors="ignore")
            return name.strip().lower() or None
        p += nlen
    return None
