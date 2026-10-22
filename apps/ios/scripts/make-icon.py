#!/usr/bin/env python3
"""Draws the placeholder app icon (1024x1024 RGB, no alpha, as the App Store requires) with
only the standard library. Replace with real artwork before release."""
import struct, zlib, sys, math

N = 1024
def pixel(x, y):
    # vertical gradient background
    t = y / (N - 1)
    r, g, b = int(20 + 20 * t), int(80 + 50 * t), int(170 - 40 * t)
    cx = cy = (N - 1) / 2
    d = math.hypot(x - cx, y - cy)
    # white ring
    if 250 <= d <= 300:
        return 255, 255, 255
    return r, g, b

def png(path):
    raw = bytearray()
    for y in range(N):
        raw.append(0)
        for x in range(N):
            d = math.hypot(x - (N - 1) / 2, y - (N - 1) / 2)
            ang = math.degrees(math.atan2(y - (N - 1) / 2, x - (N - 1) / 2))
            r, g, b = pixel(x, y)
            # open the top of the ring (like a power symbol)
            if 250 <= d <= 300 and -125 <= ang <= -55:
                t = y / (N - 1)
                r, g, b = int(20 + 20 * t), int(80 + 50 * t), int(170 - 40 * t)
            # power-symbol stem, drawn last so the gap in the ring does not cut it
            if abs(x - (N - 1) / 2) <= 28 and (N - 1) / 2 - 330 <= y <= (N - 1) / 2 - 40:
                r, g, b = 255, 255, 255
            raw += bytes((r, g, b))
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    out = b"\x89PNG\r\n\x1a\n"
    out += chunk(b"IHDR", struct.pack(">IIBBBBB", N, N, 8, 2, 0, 0, 0))
    out += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    out += chunk(b"IEND", b"")
    open(path, "wb").write(out)

png(sys.argv[1] if len(sys.argv) > 1 else "icon-1024.png")
