"""Generate Vaultly icons (PNG + ICO) with no third-party dependencies.

The mark is a rounded dark tile with a teal padlock. Rendered with 4x
supersampling so small sizes stay legible. Run from the project root:

    python scripts/make_icons.py
"""

import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "src-tauri" / "icons"
SIZES = [32, 128, 256, 512, 1024]
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]

BG = (11, 18, 32, 255)
BG_EDGE = (17, 28, 48, 255)
TEAL = (45, 212, 191, 255)
TEAL_DARK = (13, 148, 136, 255)
WHITE = (236, 254, 255, 255)


def rounded_rect(x, y, left, top, right, bottom, radius):
    if not (left <= x <= right and top <= y <= bottom):
        return False
    cx = min(max(x, left + radius), right - radius)
    cy = min(max(y, top + radius), bottom - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius**2


def shield(x, y):
    # Simple shield outline in normalized coordinates.
    nx = (x - 0.5) / 0.28
    ny = (y - 0.46) / 0.34
    if abs(nx) > 1.0 or ny < -1.0 or ny > 1.1:
        return False
    width = 1.0 - max(0.0, ny) * 0.55
    inside = abs(nx) <= width and (ny <= 0.35 or abs(nx) <= width * (1.1 - ny) / 0.75)
    return inside


def sample(x, y):
    """Return RGBA at normalized coordinates (0..1)."""
    if not rounded_rect(x, y, 0.04, 0.04, 0.96, 0.96, 0.18):
        return (0, 0, 0, 0)
    # Subtle vertical gradient background.
    mix = min(1.0, max(0.0, (y - 0.04) / 0.92))
    r = round(BG[0] * (1 - mix) + BG_EDGE[0] * mix)
    g = round(BG[1] * (1 - mix) + BG_EDGE[1] * mix)
    b = round(BG[2] * (1 - mix) + BG_EDGE[2] * mix)
    color = (r, g, b, 255)

    if shield(x, y):
        color = TEAL_DARK
        # Lock body.
        if rounded_rect(x, y, 0.36, 0.50, 0.64, 0.74, 0.05):
            color = TEAL
        # Shackle.
        cx, cy, radius = 0.5, 0.47, 0.11
        if 0.38 <= y <= 0.53:
            dist = math.hypot(x - cx, y - cy)
            if radius - 0.028 <= dist <= radius and y <= 0.50:
                color = TEAL
        # Keyhole.
        if math.hypot(x - 0.5, y - 0.585) <= 0.030:
            color = WHITE
        if 0.585 <= y <= 0.665 and abs(x - 0.5) <= (0.665 - y) * 0.20 + 0.008:
            color = WHITE
    return color


def render(size, supersample=4):
    rows = []
    inv = 1.0 / (size * supersample)
    for py in range(size):
        row = bytearray()
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(supersample):
                for sx in range(supersample):
                    x = (px * supersample + sx + 0.5) * inv
                    y = (py * supersample + sy + 0.5) * inv
                    r, g, b, a = sample(x, y)
                    acc[0] += r * a
                    acc[1] += g * a
                    acc[2] += b * a
                    acc[3] += a
            samples = supersample * supersample
            alpha = acc[3] / samples
            if alpha == 0:
                row += bytes((0, 0, 0, 0))
            else:
                row += bytes(
                    (
                        round(acc[0] / acc[3]),
                        round(acc[1] / acc[3]),
                        round(acc[2] / acc[3]),
                        round(alpha),
                    )
                )
        rows.append(bytes(row))
    return rows


def png_bytes(size, rows):
    def chunk(tag, data):
        payload = tag + data
        return (
            struct.pack(">I", len(data))
            + payload
            + struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)
        )
    raw = b"".join(b"\x00" + row for row in rows)
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def ico_bytes(images):
    count = len(images)
    header = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    entries = b""
    payload = b""
    for size, data in images:
        entries += struct.pack(
            "<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset
        )
        offset += len(data)
        payload += data
    return header + entries + payload


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        rows = render(size)
        (OUT / f"{size}x{size}.png").write_bytes(png_bytes(size, rows))
    # Tauri looks for a 2x asset as well.
    (OUT / "128x128@2x.png").write_bytes((OUT / "256x256.png").read_bytes())
    ico = [(size, png_bytes(size, render(size))) for size in ICO_SIZES]
    (OUT / "icon.ico").write_bytes(ico_bytes(ico))
    print(f"wrote {len(SIZES) + 2} icon files to {OUT}")


if __name__ == "__main__":
    main()
